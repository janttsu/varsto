// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Device removal, vault key epochs and remote wipe on storage format 3
//! (`docs/spec/format-3-design.md` section 6, "Removal"; `alpha-0-format.md`
//! section 77.6, "Vault epochs"). The records are those of `membership3`:
//!
//! 1. the removing device writes the signed vault epoch record of the next
//!    number (put-if-absent: two devices removing at once collide there),
//!    with the previous vault key, the devices that stay and the removed
//!    ones; a revocation per removed device (ledger cut-off, optional wipe
//!    order) under the epoch-0 registry key, so the removed device reads it
//!    too; vault grants of the new K3 to every device that stays;
//! 2. a folder epoch for every folder the removed device took part in: a
//!    random K9ₑ₊₁ granted to the participants that stay (folder keys are
//!    never derived from the vault key, so nothing else is re-keyed).
//!
//! Other devices pick the grants up on their next read of the membership
//! (`Membership::refresh`: the chain of epoch records must lead back to the
//! keys they hold and keep them). Every later write (ledger batches, folder
//! records, manifests, blocks of the folders) uses keys the removed device
//! never had. What it already held stays readable to it: nothing can recall
//! a key. The removed device reads its revocation and stops; with a wipe
//! order it empties its folders and its device directory.

use super::*;
use crate::crypto::VerifyingKey;
use crate::kem::DecapsKey;
use crate::ledger::EventScope;
use zeroize::Zeroizing;

const VAULT_KEYS_FILE: &str = "vault-keys.enc";
/// Vault epochs written twice under one number by different devices, and
/// which one the user kept (`varsto device resolve-epoch`).
const EPOCH_FORK_FILE: &str = "epoch-fork.json";
const REMOVED_FILE: &str = "removed.json";
const WIPED_FILE: &str = "wiped.json";

// ----- local key epochs ----------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
struct EpochFile {
    keys: BTreeMap<u32, String>,
    #[serde(default)]
    kem_hex: String,
}

impl Drop for EpochFile {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for v in self.keys.values_mut() {
            v.zeroize();
        }
        self.kem_hex.zeroize();
    }
}

/// The vault keys K3ₑ of every epoch this device holds and its KEM key
/// pair K8. Stored in `vault-keys.enc` under a key derived from the
/// device's own root key (like the local keyring).
pub(crate) struct VaultEpochs {
    pub(crate) keys: BTreeMap<u32, SecretKey>,
    pub(crate) kem: Option<DecapsKey>,
    /// Vault epoch numbers held by two different signed records
    /// (`epoch-fork.json`).
    pub(crate) forks: EpochForks,
}

/// Two signed vault epoch records under one number, by different issuers
/// or with different contents: both are recorded, and the device signs
/// nothing until the user keeps one (`varsto device resolve-epoch <n>
/// --keep <issuer>`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochForks {
    /// Epoch number -> the issuers of the records found under it.
    #[serde(default)]
    pub found: BTreeMap<u32, BTreeSet<DeviceId>>,
    /// Epoch number -> the issuer whose record the user kept.
    #[serde(default)]
    pub kept: BTreeMap<u32, DeviceId>,
}

impl EpochForks {
    /// Epoch numbers with two records and no choice made yet.
    pub fn unresolved(&self) -> Vec<u32> {
        self.found
            .keys()
            .filter(|e| !self.kept.contains_key(e))
            .copied()
            .collect()
    }
}

impl VaultEpochs {
    /// A vault that was never re-keyed: epoch 0 is the vault key itself.
    pub(crate) fn genesis(vault_key: &SecretKey) -> Self {
        VaultEpochs {
            keys: BTreeMap::from([(0, vault_key.clone())]),
            kem: Some(DecapsKey::generate()),
            forks: EpochForks::default(),
        }
    }

    pub(crate) fn current(&self) -> u32 {
        self.keys.keys().next_back().copied().unwrap_or(0)
    }

    fn file_key(keys: &Keys) -> SecretKey {
        keys.master.derive("local-vault-keys", &[])
    }

    fn aad(vault: &VaultId, device: &DeviceId) -> Vec<u8> {
        crypto::aad(
            "local-vault-keys",
            &[vault.as_str().as_bytes(), device.as_str().as_bytes()],
        )
    }

    /// A device without the file holds epoch 0 only (its vault key), and
    /// gets a KEM key on first use.
    pub(crate) fn load(
        home: &Path,
        keys: &Keys,
        vault: &VaultId,
        device: &DeviceId,
    ) -> Result<Self> {
        let p = home.join(VAULT_KEYS_FILE);
        let forks: EpochForks = util::read_json(&home.join(EPOCH_FORK_FILE)).unwrap_or_default();
        if !p.exists() {
            let mut e = Self::genesis(&keys.master);
            e.kem = None;
            e.forks = forks;
            return Ok(e);
        }
        let plain = Zeroizing::new(
            crypto::decrypt(
                &Self::file_key(keys),
                &Self::aad(vault, device),
                &fs::read(&p)?,
            )
            .context("open vault-keys.enc")?,
        );
        let f: EpochFile = serde_json::from_slice(&plain)?;
        let mut keys_out = BTreeMap::new();
        for (e, hex) in &f.keys {
            let k = SecretKey::from_hex(hex)?;
            // Every epoch key is cut from log lines, like the master key.
            crate::logging::register_key(k.as_bytes());
            keys_out.insert(*e, k);
        }
        if keys_out.is_empty() {
            keys_out.insert(0, keys.master.clone());
        }
        Ok(VaultEpochs {
            keys: keys_out,
            kem: if f.kem_hex.is_empty() {
                None
            } else {
                Some(DecapsKey::from_bytes(&hex::decode(&f.kem_hex)?)?)
            },
            forks,
        })
    }

    pub(crate) fn save(
        &self,
        home: &Path,
        keys: &Keys,
        vault: &VaultId,
        device: &DeviceId,
    ) -> Result<()> {
        let f = EpochFile {
            keys: self.keys.iter().map(|(e, k)| (*e, k.to_hex())).collect(),
            kem_hex: self
                .kem
                .as_ref()
                .map(|k| hex::encode(k.to_bytes()))
                .unwrap_or_default(),
        };
        let plain = Zeroizing::new(serde_json::to_vec(&f)?);
        let blob = crypto::encrypt(&Self::file_key(keys), &Self::aad(vault, device), &plain)?;
        util::write_atomic(&home.join(VAULT_KEYS_FILE), &blob)
    }
}

// ----- results and local markers ---------------------------------------------

/// A revocation this device accepted (kept in `devices.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Revoked {
    pub by: DeviceId,
    pub issued_utc: i64,
    pub cutoff_seq: u64,
    pub wipe: bool,
}

/// This device was removed from the vault (`removed.json`, or `wiped.json`
/// after a wipe; neither holds anything secret).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Removal {
    pub by: DeviceId,
    pub by_name: String,
    pub issued_utc: i64,
    pub wipe: bool,
    pub noticed_utc: i64,
}

/// Why this device no longer syncs. Returned (inside `anyhow::Error`) by
/// sync, pull and push once the device has seen its own revocation; the
/// service drops its engine when `wiped` is set.
#[derive(Clone, Debug)]
pub struct DeviceRemoved {
    pub by_name: String,
    pub issued_utc: i64,
    pub wiped: bool,
}

impl std::fmt::Display for DeviceRemoved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "this device was removed from the vault by {} on {}",
            self.by_name,
            util::format_date(self.issued_utc)
        )?;
        if self.wiped {
            write!(f, "; its keys, sync state and folder contents were wiped")?;
        } else {
            write!(f, "; it no longer syncs (reset it to start over)")?;
        }
        Ok(())
    }
}

impl std::error::Error for DeviceRemoved {}

/// The removal of this device, if one was recorded in `home` (also after a
/// wipe, when nothing else of the vault is left).
pub fn removal_notice(home: &Path) -> Option<Removal> {
    [WIPED_FILE, REMOVED_FILE]
        .iter()
        .find_map(|f| util::read_json(&home.join(f)).ok())
}

/// One device of the vault as the device list shows it.
#[derive(Clone, Debug, Serialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub name: String,
    pub enrolled_utc: i64,
    pub this_device: bool,
    pub revoked: bool,
    pub revoked_utc: Option<i64>,
    pub revoked_by: Option<String>,
    pub wipe_ordered: bool,
    /// System, model and Varsto version the device last published.
    #[serde(default)]
    pub details: Option<super::devinfo::DeviceDetails>,
    /// In an organization: the person the device belongs to, and whether
    /// it is an administrator. Absent without an organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// What `revoke_device` did.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeReport {
    pub device_id: String,
    pub name: String,
    /// Every device removed in this epoch (one, or a user's devices).
    #[serde(default)]
    pub devices: Vec<String>,
    pub key_epoch: u32,
    pub cutoff_seq: u64,
    pub wipe: bool,
    /// Devices the new vault key was granted to.
    pub keys_sent_to: Vec<String>,
    /// Devices that stay but whose device record has no KEM key: none in
    /// format 3 (every device record carries one); kept for the interface.
    pub keys_pending_for: Vec<String>,
    /// Folders that got a new folder epoch (new content uses new keys).
    pub folders_rekeyed: Vec<String>,
    /// Folders the removed device took part in that this device cannot
    /// rotate (it is not an owner there, or holds no key of them).
    pub folders_not_rekeyed: Vec<String>,
}

/// Remove what a wipe removes inside one folder root. A root that is the
/// file system root, the user's home directory or a directory that contains
/// the device directory is too wide to empty blindly: there only the files
/// the folder state names are removed. Links are removed, never followed.
fn wipe_root(root: &Path, home: &Path, tracked: &[String]) -> u64 {
    let mut removed = 0u64;
    let user_home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    let wide = root.parent().is_none()
        || user_home.as_deref() == Some(root)
        || home.starts_with(root)
        || !root.is_absolute();
    if !wide {
        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .contents_first(true)
            .min_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            if entry.file_type().is_dir() {
                let _ = fs::remove_dir(p);
            } else if fs::remove_file(p).is_ok() {
                removed += 1;
            }
        }
        return removed;
    }
    for rel in tracked {
        if crate::util::check_rel_path(rel).is_err() {
            continue;
        }
        let disk = crate::names::join(root, rel);
        for p in [placeholder_path(&disk), disk] {
            if fs::symlink_metadata(&p).is_ok() && fs::remove_file(&p).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

impl Engine {
    // ----- keys per epoch ---------------------------------------------------------

    /// The newest vault key epoch this device holds (0 until a device is removed).
    pub fn key_epoch(&self) -> u32 {
        self.epochs.current()
    }

    /// Epoch-0 vault key: the root of everything that must stay the same
    /// across epochs (disk pool ids, replica key, LAN beacon tag).
    pub(super) fn root_key(&self) -> &SecretKey {
        self.epochs.keys.get(&0).unwrap_or(&self.keys.master)
    }

    pub(super) fn current_vault_key(&self) -> &SecretKey {
        self.epochs
            .keys
            .values()
            .next_back()
            .unwrap_or(&self.keys.master)
    }

    /// The key of the in-memory location view's batches (`ledger` or
    /// `ledger@<epoch>`, `Engine::view`). Format 3 stores no such batch, so
    /// the view holds only this device's events not sealed yet.
    pub(super) fn ledger_key_for(&self, id: &str) -> Option<SecretKey> {
        let epoch = if id == KEY_LEDGER {
            0
        } else {
            id.strip_prefix(ledger::KEY_LEDGER_EPOCH_PREFIX)?
                .parse()
                .ok()?
        };
        Some(self.epochs.keys.get(&epoch)?.derive("ledger", &[]))
    }

    /// The keys of a folder this device holds: only what grants (or
    /// escrow) gave it, never a key derived from the vault key.
    pub(super) fn folder_keys(&self, rec: &FolderRecord) -> Result<FolderKeys> {
        self.folder_keys3(rec)
    }

    // ----- who belongs ------------------------------------------------------------

    pub fn is_revoked(&self, device: &DeviceId) -> bool {
        self.devices.revoked.contains_key(device)
    }

    /// Whether a policy or placement record written by `device` is adopted.
    pub(super) fn org_accepts_policy_from(&self, device: &DeviceId) -> bool {
        match &self.org {
            Some(o) => o.is_admin(device) || o.policy().members_may_set_policies,
            None => true,
        }
    }

    fn org_role(&self, device: &DeviceId) -> Option<String> {
        let o = self.org.as_ref()?;
        if o.is_admin(device) {
            Some("admin".into())
        } else if o.lists(device) {
            Some("member".into())
        } else {
            None
        }
    }

    /// Devices whose records and grants this device acts on: current
    /// devices of the vault, which in an organization also run a platform
    /// (and version) its policy allows: a device locked out that way gets
    /// no new keys and what it writes is not taken, until it is allowed
    /// again.
    pub(super) fn trusted(&self, device: &DeviceId) -> bool {
        self.belongs(device)
            && (device == &self.vault.device_id || self.org_refuses_device(device).is_none())
    }

    /// `trusted` without the organization's platform policy: the device has
    /// an accepted device record and no accepted revocation (and, in an
    /// organization, the roster lists it).
    pub(super) fn belongs(&self, device: &DeviceId) -> bool {
        if device == &self.vault.device_id {
            return self.removal.is_none();
        }
        if self.is_revoked(device) || !self.devices.devices.contains_key(device) {
            return false;
        }
        if let Some(o) = &self.org {
            if o.roster.is_some() && !o.lists(device) {
                return false;
            }
        }
        true
    }

    /// Format 2: whether a ledger batch counts (the format-2 ledger of
    /// other areas still asks; f3-switch: part B).
    pub(super) fn batch_accepted(&self, device: &DeviceId, seq: u64) -> bool {
        self.devices
            .revoked
            .get(device)
            .is_none_or(|r| seq <= r.cutoff_seq)
    }

    /// Format 2: the scope of a format-2 batch (the format-2 ledger of
    /// other areas still asks; f3-switch: part B).
    pub(super) fn event_scope(&self, device: &DeviceId, key_id: &str) -> Option<EventScope> {
        let scope = EventScope::of_key_id(key_id)?;
        let me = device == &self.vault.device_id;
        let ok = match &scope {
            EventScope::Full => {
                (me && !self.vault.member)
                    || (self.devices.devices.contains_key(device)
                        && (self.trusted(device) || self.is_revoked(device)))
            }
            EventScope::Replica => self.devices.replicas.contains_key(device),
            EventScope::Member(_) => me || self.devices.members.contains_key(device),
        };
        ok.then_some(scope)
    }

    /// Format 2: what decides `event_scope`, for the format-2 cached view.
    pub(super) fn scope_context(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for d in self.ledger.devices() {
            let class = [
                self.event_scope(&d, KEY_LEDGER).is_some(),
                self.event_scope(&d, KEY_REPLICA).is_some(),
                d == self.vault.device_id || self.devices.members.contains_key(&d),
            ];
            out.extend_from_slice(d.as_str().as_bytes());
            out.extend(class.iter().map(|c| *c as u8));
        }
        out
    }

    pub(super) fn device_name(&self, device: &DeviceId) -> String {
        if device == &self.vault.device_id {
            return self.vault.device_name.clone();
        }
        self.devices
            .devices
            .get(device)
            .or_else(|| self.devices.members.get(device))
            .map(|r| r.name.clone())
            .unwrap_or_else(|| device.short().to_string())
    }

    pub(super) fn device_key(&self, device: &DeviceId) -> Option<VerifyingKey> {
        if device == &self.vault.device_id {
            return Some(self.keys.signer.public());
        }
        self.devices.devices.get(device)?.pubkey().ok()
    }

    /// The removal of this device, once it has seen it.
    pub fn removal(&self) -> Option<&Removal> {
        self.removal.as_ref()
    }

    /// Refuse to act on a device that was removed from the vault, or that
    /// runs a platform its organization does not allow.
    pub(super) fn ensure_active(&self) -> Result<()> {
        self.ensure_not_removed()?;
        if let Some(why) = self.org_platform_block() {
            bail!("{why}: this device does not sync or open the vault until an administrator allows it");
        }
        Ok(())
    }

    /// Refuse to act on a device that was removed from the vault.
    pub(super) fn ensure_not_removed(&self) -> Result<()> {
        match &self.removal {
            Some(r) => Err(anyhow::Error::new(DeviceRemoved {
                by_name: r.by_name.clone(),
                issued_utc: r.issued_utc,
                wiped: r.wipe,
            })),
            None => Ok(()),
        }
    }

    pub(super) fn save_epochs(&self) -> Result<()> {
        self.epochs.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )
    }

    /// Every device this one knows a name for (itself, the enrolled devices,
    /// and devices only the ledger names): one name per id, used wherever a
    /// device is shown, so the same id never appears under two names.
    pub fn known_device_names(&self) -> Vec<(DeviceId, String)> {
        let mut out: BTreeMap<DeviceId, String> = BTreeMap::new();
        if let Ok(view) = self.view3() {
            for (id, name) in &view.devices {
                if !name.is_empty() {
                    out.insert(DeviceId::from_bytes(id), name.clone());
                }
            }
        }
        for (id, rec) in &self.devices.devices {
            if !rec.name.is_empty() {
                out.insert(id.clone(), rec.name.clone());
            }
        }
        out.insert(self.vault.device_id.clone(), self.vault.device_name.clone());
        out.into_iter().collect()
    }

    pub fn devices_list(&self) -> Vec<DeviceInfo> {
        let me = &self.vault.device_id;
        let mut out = vec![DeviceInfo {
            device_id: me.to_string(),
            name: self.vault.device_name.clone(),
            enrolled_utc: self
                .devices
                .devices
                .get(me)
                .map(|r| r.enrolled_utc)
                .unwrap_or(self.vault.created_utc),
            this_device: true,
            revoked: false,
            revoked_utc: None,
            revoked_by: None,
            wipe_ordered: false,
            details: self.devices.details.get(me).cloned(),
            user: self.org.as_ref().and_then(|o| o.user_of(me)),
            role: self.org_role(me),
        }];
        for (id, rec) in &self.devices.devices {
            if id == me || !(self.trusted(id) || self.is_revoked(id)) {
                continue;
            }
            let r = self.devices.revoked.get(id);
            out.push(DeviceInfo {
                device_id: id.to_string(),
                name: rec.name.clone(),
                enrolled_utc: rec.enrolled_utc,
                this_device: false,
                revoked: r.is_some(),
                revoked_utc: r.map(|r| r.issued_utc),
                revoked_by: r.map(|r| self.device_name(&r.by)),
                wipe_ordered: r.is_some_and(|r| r.wipe),
                details: self.devices.details.get(id).cloned(),
                user: self.org.as_ref().and_then(|o| o.user_of(id)),
                role: self.org_role(id),
            });
        }
        out
    }

    // ----- removing ---------------------------------------------------------------

    /// Remove another full device from the vault: a vault epoch with its
    /// revocation (optionally with a wipe order), the new vault key granted
    /// to every device that stays, and a folder epoch for every folder the
    /// device took part in. See the module documentation for what the
    /// removed device can and cannot read afterwards.
    pub fn revoke_device(&mut self, name_or_id: &str, wipe: bool) -> Result<RevokeReport> {
        crate::logged_op!("revoke device", name_or_id, {
            self.revoke_device_inner(name_or_id, wipe)
        })
    }

    fn revoke_device_inner(&mut self, name_or_id: &str, wipe: bool) -> Result<RevokeReport> {
        if self.vault.member {
            bail!("a member device cannot remove devices from the owner's vault");
        }
        self.ensure_active()?;
        self.pull_ledger()?;
        let me = self.vault.device_id.clone();
        let wanted = name_or_id.trim();
        if let Some(o) = &self.org {
            if !o.is_admin(&me) {
                bail!(
                    "in the organization {}, only an administrator can remove devices",
                    o.name
                );
            }
        }
        let own = self.own_record();
        let matches: Vec<DeviceId> = self
            .devices
            .devices
            .iter()
            .chain(std::iter::once((&me, &own)))
            .filter(|(id, rec)| {
                rec.name == wanted
                    || id.as_str() == wanted
                    || (wanted.len() >= 8 && id.as_str().starts_with(wanted))
            })
            .map(|(id, _)| id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let target = match matches.as_slice() {
            [] => bail!("no device named {wanted} in this vault (see `varsto device list`)"),
            [one] => one.clone(),
            _ => bail!("several devices are named {wanted}: use the device id instead"),
        };
        if target == me {
            bail!("a device cannot remove itself: remove it from another device, or reset this one (Settings, or `varsto reset --yes`) to start over");
        }
        if self.is_revoked(&target) {
            bail!("{wanted} was already removed");
        }
        if !self.belongs(&target) {
            bail!("{wanted} is not a current device of this vault");
        }
        let report = self.revoke_many(std::slice::from_ref(&target), wipe)?;
        self.org_after_revoke(&target, wipe, report.key_epoch)?;
        Ok(report)
    }

    /// Remove several current devices in one vault epoch (a user's devices).
    /// The caller has checked that they are current and not this device.
    pub(super) fn revoke_many(&mut self, targets: &[DeviceId], wipe: bool) -> Result<RevokeReport> {
        self.revoke_many_as(targets, wipe, false)
    }

    /// Tests: what a modified client could do, remove a device without
    /// pulling first and ignoring newer vault epochs on the storages (its
    /// record chains to the newest key it holds, under the number after
    /// the highest one listed). Every other device must still apply
    /// removals in the order of the vault epochs, and refuses a record that
    /// skips a signed epoch.
    #[doc(hidden)]
    pub fn revoke_unchecked(&mut self, name_or_id: &str, _issued_utc: i64) -> Result<RevokeReport> {
        let target = self
            .devices
            .devices
            .iter()
            .find(|(id, rec)| rec.name == name_or_id || id.as_str() == name_or_id)
            .map(|(id, _)| id.clone())
            .ok_or_else(|| anyhow!("no device {name_or_id}"))?;
        self.revoke_many_as(&[target], false, true)
    }

    fn revoke_many_as(
        &mut self,
        targets: &[DeviceId],
        wipe: bool,
        unchecked: bool,
    ) -> Result<RevokeReport> {
        let me = self.vault.device_id.clone();
        if targets.is_empty() {
            bail!("no current device to remove");
        }
        if targets.contains(&me) {
            bail!("a device cannot remove itself");
        }
        let targets: BTreeSet<DeviceId> = targets.iter().cloned().collect();
        let mut list = Vec::new();
        for t in &targets {
            list.push((
                members3::bin(t)?,
                self.f3.ledger.head(&members3::bin(t)?).seq,
            ));
        }
        let names: Vec<String> = targets.iter().map(|t| self.device_name(t)).collect();
        let k1 = self.f3.recovery.clone();
        // A device the organization's policy locks out stays a member of the
        // new epoch; it gets the key once it is allowed again.
        let held = self.org_held3();
        let report = self
            .with_members3_as(!unchecked, |m| {
                m.hold_grants = held;
                m.remove_devices(&list, wipe, k1.as_ref(), unchecked)
            })?
            .ok_or_else(|| anyhow!("this device has no storage to publish the removal to"))?;
        // Everything this device writes from now on uses the new keys; its
        // peer record goes out again under them, so the removed device stops
        // learning its addresses at once.
        self.reset_view3();
        self.republish_own_peer_record();
        let folder_name = |f: &crate::record::Id16| {
            self.f3
                .members
                .registry
                .get(f)
                .map(|s| s.name.clone())
                .unwrap_or_else(|| hex::encode(f))
        };
        let target = targets.iter().next().cloned().expect("checked non-empty");
        Ok(RevokeReport {
            device_id: target.to_string(),
            name: names[0].clone(),
            devices: names,
            key_epoch: report.vault_epoch,
            cutoff_seq: list[0].1,
            wipe,
            keys_sent_to: report
                .vault_keys_sent_to
                .iter()
                .filter(|d| **d != self.me3())
                .map(|d| self.device_name(&DeviceId::from_bytes(d)))
                .collect(),
            keys_pending_for: Vec::new(),
            folders_rekeyed: report
                .folder_epochs
                .iter()
                .map(|(f, _)| folder_name(f))
                .collect(),
            folders_not_rekeyed: report.folders_not_rotated.iter().map(folder_name).collect(),
        })
    }

    // ----- picking up changes on sync -------------------------------------------

    /// Format-2 name of reading the membership (the format-2 ledger of
    /// other areas still calls it): format 3 reads it with every pull.
    pub(super) fn sync_membership(&mut self) -> Result<()> {
        self.refresh_members3()
    }

    /// After every read of the membership: act on a revocation of this
    /// device (with a wipe order, wipe it), record vault epochs two devices
    /// wrote under one number, and refuse to go on while one waits for the
    /// user's choice.
    pub(super) fn after_members3(
        &mut self,
        own: Option<crate::membership3::RevocationRecord>,
        forks: BTreeMap<u32, BTreeSet<crate::record::Id16>>,
    ) -> Result<()> {
        if let Some(rev) = own {
            if self.removal.is_none() {
                let by = DeviceId::from_bytes(&rev.issuer);
                let removal = Removal {
                    by_name: self.device_name(&by),
                    by,
                    issued_utc: util::now_utc(),
                    wipe: rev.wipe,
                    noticed_utc: util::now_utc(),
                };
                util::write_json(&self.home.join(REMOVED_FILE), &removal)?;
                self.removal = Some(removal.clone());
                if rev.wipe {
                    self.wipe_this_device(&removal)?;
                }
            }
            return self.ensure_not_removed();
        }
        let found: BTreeMap<u32, BTreeSet<DeviceId>> = forks
            .into_iter()
            .map(|(e, s)| (e, s.iter().map(|d| DeviceId::from_bytes(d)).collect()))
            .collect();
        if found != self.epochs.forks.found {
            self.epochs.forks.found = found;
            util::write_json(&self.home.join(EPOCH_FORK_FILE), &self.epochs.forks)?;
        }
        if let Some(e) = self.epochs.forks.unresolved().first() {
            bail!(
                "two devices wrote key epoch {e} at once; keep one first (`varsto device resolve-epoch {e} --keep <device>`)"
            );
        }
        Ok(())
    }

    /// The issuers the user kept for vault epochs two devices wrote.
    pub(super) fn vault_kept3(&self) -> BTreeMap<u32, crate::record::Id16> {
        self.epochs
            .forks
            .kept
            .iter()
            .filter_map(|(e, d)| Some((*e, members3::bin(d).ok()?)))
            .collect()
    }

    /// Vault epoch numbers held by two different signed records, and the
    /// user's choice; while there is one without a choice, this device
    /// signs nothing.
    pub fn epoch_forks(&self) -> &EpochForks {
        &self.epochs.forks
    }

    /// Keep the record of `issuer` (device name or id) for vault epoch
    /// `epoch`, which two devices wrote: revocations and keys of the other
    /// record are ignored, and this device signs again. The kept issuer
    /// must be a trusted device. A device that already adopted the other
    /// record's key cannot switch: pair it again.
    pub fn resolve_epoch_fork(&mut self, epoch: u32, keep: &str) -> Result<()> {
        let Some(issuers) = self.epochs.forks.found.get(&epoch).cloned() else {
            bail!("key epoch {epoch} was not written twice");
        };
        let keep = keep.trim();
        let chosen: Vec<DeviceId> = issuers
            .iter()
            .filter(|d| {
                d.as_str() == keep
                    || self.device_name(d) == keep
                    || (keep.len() >= 8 && d.as_str().starts_with(keep))
            })
            .cloned()
            .collect();
        let [issuer] = chosen.as_slice() else {
            bail!(
                "name one of the devices that wrote key epoch {epoch}: {}",
                issuers
                    .iter()
                    .map(|d| format!("{} ({})", self.device_name(d), d.short()))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        };
        if !self.trusted(issuer) {
            bail!(
                "{} is not a trusted device of this vault; keep the other one",
                self.device_name(issuer)
            );
        }
        self.epochs.forks.kept.insert(epoch, issuer.clone());
        util::write_json(&self.home.join(EPOCH_FORK_FILE), &self.epochs.forks)?;
        self.reset_view3();
        Ok(())
    }

    // ----- remote wipe ------------------------------------------------------------

    /// Carry out a wipe order addressed to this device: empty every attached
    /// folder (see `wipe_root`), then remove the keys, keyring, secrets,
    /// ledger, sync state, trash, configuration and peer identity from the
    /// device directory. Nothing outside the folder roots and the device
    /// directory is touched, and storages are left alone. Unsynced changes
    /// on this device are lost: that is the point of wiping a lost device.
    fn wipe_this_device(&mut self, removal: &Removal) -> Result<()> {
        for m in self.config.folders.clone() {
            // The local names of the files (`crate::names`).
            let rules = self.local_rules(&m.path);
            let tracked: Vec<String> = self
                .load_state(&m.folder_id)
                .map(|s| {
                    s.files
                        .keys()
                        .chain(s.pending_remote.keys())
                        .map(|p| s.local_names.local_rel(rules, p).into_owned())
                        .collect()
                })
                .unwrap_or_default();
            wipe_root(&m.path, &self.home, &tracked);
        }
        reset_device(&self.home)?;
        let mut extra: Vec<PathBuf> = [
            crate::p2p::quic::CERT_FILE,
            crate::p2p::quic::KEY_FILE,
            "replica.json",
        ]
        .iter()
        .map(|f| self.home.join(f))
        .collect();
        if let Ok(rd) = fs::read_dir(&self.home) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if n.starts_with("pool-") && n.ends_with(".json") {
                    extra.push(e.path());
                }
            }
        }
        for p in extra {
            let _ = fs::remove_file(p);
        }
        util::write_json(&self.home.join(WIPED_FILE), removal)?;
        self.keyring = Keyring::default();
        self.config = Config::default();
        self.unlocked.clear();
        Ok(())
    }
}

/// Files `reset_device` removes in addition to the alpha-0 set.
pub(super) const RESET_EXTRA: [&str; 4] =
    [VAULT_KEYS_FILE, REMOVED_FILE, WIPED_FILE, EPOCH_FORK_FILE];
