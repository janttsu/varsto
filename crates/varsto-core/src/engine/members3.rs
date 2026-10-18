// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The membership of a format-3 vault as the engine keeps it
//! (`docs/spec/format-3-design.md` sections 5, 6 and 9): device records,
//! folder records, the folder keys granted to this device, member devices
//! of shared folders and revocations, read with `membership3::Membership`
//! and kept between operations ([`Members3`]), so that every record the
//! engine accepts is judged by the same trust ([`EngineTrust`]) and opened
//! with the same keys (`membership3::KeyRing`).
//!
//! What this device holds of a folder comes only from grants to it (and,
//! after `join --recovery-words`, from escrow): the local keyring keeps a
//! copy of those keys (`FolderRecord::key_hex`, `epoch_keys`, `k11_hex`),
//! never a key derived from the vault key.

use super::*;
use crate::membership3::{
    DeviceRegistry, FolderRegistry, GrantedKeys, KeyRing, MemberRegistry, Membership,
    RevocationRecord, Role, Trust, VaultKeys,
};
use crate::record::{Announced, Id16, KeyId, Kind, RecordTrust, RecordsRefused};

/// What the engine knows of the vault's membership (a copy of what
/// `Membership` read last).
#[derive(Clone, Default)]
pub(crate) struct Members3 {
    pub devices: DeviceRegistry,
    pub registry: FolderRegistry,
    pub granted: GrantedKeys,
    pub members: MemberRegistry,
    pub revoked: BTreeSet<Id16>,
    pub revocations: BTreeMap<Id16, RevocationRecord>,
    pub refused: RecordsRefused,
    /// A revocation of this device (`Membership::own_revocation`).
    pub own_revocation: Option<RevocationRecord>,
    /// Vault epoch numbers two devices wrote.
    pub vault_forks: BTreeMap<u32, BTreeSet<Id16>>,
    /// Devices whose ledger batches count only up to a cut-off: removed
    /// from the vault (revocations), or member devices of other vaults
    /// removed from a folder (folder epoch records).
    pub cutoffs: BTreeMap<Id16, u64>,
    /// On a member device of another vault: what its grants say.
    pub member: Option<MemberInfo>,
    /// The newest key wraps of every Strongroom folder.
    pub strongrooms: BTreeMap<Id16, crate::membership3::strongrooms::StrongroomRecord>,
    /// Read at least once in this process.
    pub read: bool,
}

/// A member device's own standing in its shared folder.
#[derive(Clone, Debug, Default)]
pub(crate) struct MemberInfo {
    pub folder: Id16,
    pub role: Option<Role>,
    pub access_lost: bool,
    /// The owner devices whose grants counted.
    pub owners: BTreeSet<Id16>,
}

impl Members3 {
    fn of(m: &Membership<'_>) -> Members3 {
        let mut cutoffs: BTreeMap<Id16, u64> = BTreeMap::new();
        for (f, ep) in &m.registry.epochs {
            for r in ep.applied.values() {
                for x in &r.removed {
                    // Own devices removed from one folder still write for
                    // the others: only another person's device is cut off.
                    if m.devices.get(&x.device).is_none()
                        && m.members.folders_of(&x.device).iter().all(|g| g == f)
                    {
                        cutoffs.insert(x.device, x.cutoff);
                    }
                }
            }
        }
        for (d, r) in &m.revocations {
            cutoffs.insert(*d, r.cutoff_seq);
        }
        Members3 {
            devices: m.devices.clone(),
            registry: m.registry.clone(),
            granted: m.granted.clone(),
            members: m.members.clone(),
            revoked: m.revoked_set().clone(),
            revocations: m.revocations.clone(),
            refused: m.refused.clone(),
            own_revocation: m.own_revocation.clone(),
            vault_forks: m.vault_forks.clone(),
            cutoffs,
            member: None,
            strongrooms: m.strongrooms.clone(),
            read: true,
        }
    }

    /// What a member device knows, as the same registries.
    fn of_member(v: crate::membership3::MemberView) -> Members3 {
        Members3 {
            member: Some(MemberInfo {
                folder: v.folder,
                role: v.role,
                access_lost: v.access_lost,
                owners: v.owners.clone(),
            }),
            devices: v.devices,
            registry: v.registry,
            granted: v.granted,
            members: v.members,
            revoked: BTreeSet::new(),
            revocations: BTreeMap::new(),
            refused: v.refused,
            own_revocation: None,
            vault_forks: BTreeMap::new(),
            cutoffs: v.cutoffs,
            strongrooms: BTreeMap::new(),
            read: true,
        }
    }

    /// Whether `folder` is shared with other people's devices (once it is,
    /// it stays so: the owners' folder events go into folder-scoped
    /// batches the members can read).
    pub fn shared(&self, folder: &Id16) -> bool {
        self.registry
            .get(folder)
            .is_some_and(|st| !st.members.is_empty())
    }

    /// The trust of section 9 over these registries.
    pub fn trust(&self) -> Trust<'_> {
        Trust {
            devices: &self.devices,
            revoked: &self.revoked,
            folders: Some(&self.registry),
            members: Some(&self.members),
        }
    }

    /// The role of `device` in `folder` at the folder's current epoch.
    pub fn role(&self, device: &Id16, folder: &Id16) -> Option<Role> {
        let epoch = self
            .registry
            .epochs
            .get(folder)
            .map(|e| e.current())
            .unwrap_or(0);
        self.registry.role(device, folder, epoch)
    }
}

/// `record::RecordTrust` of the engine: section 9 over the membership, and
/// the announcements of the ledger view (step 5 of the acceptance rule).
pub(crate) struct EngineTrust<'a> {
    pub inner: Trust<'a>,
    pub view: &'a crate::ledger3::LedgerView,
}

impl RecordTrust for EngineTrust<'_> {
    fn signer_key(
        &self,
        device: &Id16,
        kind: Kind,
        scope: &Id16,
    ) -> Option<crate::crypto::VerifyingKey> {
        self.inner.signer_key(device, kind, scope)
    }
    fn may_write(&self, device: &Id16, kind: Kind, scope: &Id16, key_id: &KeyId) -> bool {
        self.inner.may_write(device, kind, scope, key_id)
    }
    fn announcement(&self, device: &Id16, kind: Kind, scope: &Id16, seq: u64) -> Option<Announced> {
        crate::manifest3::announcement(self.view, device, kind, scope, seq)
    }
}

/// A storage whose reads of membership records (`vault/`) are kept in a
/// local mirror as well.
struct Tee<'a> {
    inner: &'a dyn Storage,
    mirror: &'a crate::storage::LocalDirStorage,
}

impl Tee<'_> {
    fn keep(&self, key: &str, got: &Option<Vec<u8>>) {
        if let Some(b) = got {
            if key.starts_with("vault/") && key.ends_with(".rec") {
                if let Err(e) = self.mirror.put_if_absent(key, b) {
                    log::debug!("membership record {key} not kept locally: {e:#}");
                }
            }
        }
    }
}

impl Storage for Tee<'_> {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        self.inner.put_if_absent(key, data)
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let got = self.inner.get(key)?;
        self.keep(key, &got);
        Ok(got)
    }
    fn get_bounded(&self, key: &str, max: u64) -> Result<Option<Vec<u8>>> {
        let got = self.inner.get_bounded(key, max)?;
        self.keep(key, &got);
        Ok(got)
    }
    fn exists(&self, key: &str) -> Result<bool> {
        self.inner.exists(key)
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.inner.list(prefix)
    }
    fn list_after(&self, prefix: &str, start_after: &str) -> Result<Vec<String>> {
        self.inner.list_after(prefix, start_after)
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key)
    }
}

/// `member3.json` of a member device.
const MEMBER_FILE: &str = "member3.json";

#[derive(Serialize, Deserialize)]
struct MemberState3 {
    folder: String,
    anchor: String,
}

/// The binary form of an id (16 bytes) of this vault.
pub(crate) fn bin(id: &crate::ids::Id) -> Result<Id16> {
    crate::record::id16(id).ok_or_else(|| anyhow!("id {id} is not 16 bytes of hex"))
}

impl Engine {
    /// This device's id on the wire.
    pub(crate) fn me3(&self) -> Id16 {
        bin(&self.vault.device_id).expect("a device id is 16 bytes")
    }

    /// The vault keys this device holds, by epoch.
    pub(crate) fn vault_keys3(&self) -> VaultKeys {
        VaultKeys {
            keys: self.epochs.keys.clone(),
        }
    }

    /// The keys that open and seal records here: registry, ledger and
    /// epoch keys of every vault epoch held, the folder keys granted to
    /// this device, its K8.
    pub(crate) fn keys3<'a>(&'a self, vault_keys: &'a VaultKeys) -> KeyRing<'a> {
        let m = &self.f3.members;
        // A Strongroom's key is held only while it is unlocked here.
        let now = util::now_utc();
        let mut extra = Vec::new();
        for (fid, (k13, until)) in &self.unlocked {
            let Ok(f) = bin(fid) else { continue };
            if *until <= now {
                continue;
            }
            let keys = crate::membership3::FolderKeys {
                folder: f,
                epochs: BTreeMap::from([(0, k13.clone())]),
                k11: crate::membership3::grants::k11_of(&f, k13),
            };
            if let Some(k) = keys.k10(0) {
                extra.push((KeyId::Meta { folder: f, epoch: 0 }, k));
            }
            if let Some(k) = keys.share_ledger(0) {
                extra.push((KeyId::ShareLedger { folder: f, epoch: 0 }, k));
            }
        }
        KeyRing {
            me: self.me3(),
            vault: vault_keys,
            kem: self.epochs.kem.as_ref(),
            devices: Some(&m.devices),
            folders: Some(&m.granted),
            recovery: None,
            extra,
            members: Some(&m.members),
        }
    }

    /// The hot metadata storages membership records are read from and
    /// written to.
    fn member_storages(&self) -> Result<OpenStorages> {
        Ok(self
            .metadata_storages(false)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect())
    }

    /// Run `f` over a `Membership` of this device opened on the hot
    /// metadata storages (it reads every membership record first); the
    /// engine keeps what it read afterwards. Stamps follow the engine's
    /// clock, so roles given now hold for the batches this device seals
    /// next. `None` without a storage.
    pub(crate) fn with_members3<R>(
        &mut self,
        f: impl FnOnce(&mut Membership<'_>) -> Result<R>,
    ) -> Result<Option<R>> {
        self.with_members3_as(true, f)
    }

    /// `with_members3`; without `guard` (tests: a modified client) a
    /// revocation of this device and an unresolved vault epoch stop
    /// nothing.
    pub(crate) fn with_members3_as<R>(
        &mut self,
        guard: bool,
        f: impl FnOnce(&mut Membership<'_>) -> Result<R>,
    ) -> Result<Option<R>> {
        let open = self.member_storages()?;
        if open.is_empty() {
            return Ok(None);
        }
        let vault = bin(&self.vault.vault_id)?;
        // Every membership record read is kept in a local mirror, so that
        // a later process knows the membership without reading a storage.
        let mirror = self.records_mirror3()?;
        let teed: Vec<Tee> = open
            .iter()
            .map(|(_, b)| Tee {
                inner: &**b,
                mirror: &mirror,
            })
            .collect();
        let refs: Vec<&dyn Storage> = teed.iter().map(|t| t as &dyn Storage).collect();
        let lamport = self.clock.lamport;
        let kept = self.vault_kept3();
        let (out, snapshot, keys, stamped) = {
            let Some(kem) = self.epochs.kem.as_ref() else {
                bail!("this device has no KEM key (K8); it cannot take part in format-3 folders");
            };
            let mut m = Membership::open_with(
                vault,
                &refs,
                &self.keys.signer,
                kem,
                self.vault_keys3(),
                kept,
            )?;
            m.observe_lamport(lamport);
            // A removed device, or one that waits for the user's choice
            // between two vault epochs, writes nothing.
            let out = if !guard {
                f(&mut m)
            } else if m.own_revocation.is_some() {
                Err(anyhow!("this device was removed from the vault"))
            } else if let Some(e) = m.unresolved_vault_forks().first() {
                Err(anyhow!(
                    "two devices wrote key epoch {e} at once; keep one first (`varsto device resolve-epoch {e} --keep <device>`)"
                ))
            } else {
                f(&mut m)
            };
            (out, Members3::of(&m), m.vault_keys.clone(), m.lamport())
        };
        let own = snapshot.own_revocation.clone();
        let forks = snapshot.vault_forks.clone();
        self.adopt_members3(snapshot, keys)?;
        self.observe_clock(stamped)?;
        if guard {
            self.after_members3(own, forks)?;
        }
        out.map(Some)
    }

    /// The local mirror of the membership records (`state/records3/`).
    fn records_mirror3(&self) -> Result<crate::storage::LocalDirStorage> {
        crate::storage::LocalDirStorage::new(
            "records3".into(),
            self.home.join("state").join("records3"),
        )
    }

    /// Copy every membership record of the local mirror to `to` (a storage
    /// just added), put-if-absent.
    pub(crate) fn copy_records3(&self, to: &dyn Storage) -> Result<()> {
        let dir = self.home.join("state").join("records3");
        if !dir.is_dir() {
            return Ok(());
        }
        let mirror = self.records_mirror3()?;
        for key in mirror.list("vault/")? {
            if let Some(b) = mirror.get(&key)? {
                to.put_if_absent(&key, &b)?;
            }
        }
        Ok(())
    }

    /// The membership as the local mirror of its records gives it (an
    /// engine just opened knows its devices and folders without a storage).
    pub(crate) fn load_members3_local(&mut self) -> Result<()> {
        let dir = self.home.join("state").join("records3");
        if !dir.is_dir() {
            return Ok(());
        }
        if self.vault.member {
            let mirror = self.records_mirror3()?;
            return self.read_member3(&[&mirror]);
        }
        let vault = bin(&self.vault.vault_id)?;
        let mirror = self.records_mirror3()?;
        let refs: Vec<&dyn Storage> = vec![&mirror];
        let (snapshot, keys) = {
            let Some(kem) = self.epochs.kem.as_ref() else {
                return Ok(());
            };
            let m = Membership::open_with(
                vault,
                &refs,
                &self.keys.signer,
                kem,
                self.vault_keys3(),
                self.vault_kept3(),
            )?;
            (Members3::of(&m), m.vault_keys.clone())
        };
        self.adopt_members3(snapshot, keys)
    }

    /// Read every membership record again (and publish this device's own
    /// device record when the registry lacks it).
    pub(crate) fn refresh_members3(&mut self) -> Result<()> {
        if self.vault.member {
            let open = self.member_storages()?;
            if open.is_empty() {
                return Ok(());
            }
            let mirror = self.records_mirror3()?;
            let teed: Vec<Tee> = open
                .iter()
                .map(|(_, b)| Tee {
                    inner: &**b,
                    mirror: &mirror,
                })
                .collect();
            let refs: Vec<&dyn Storage> = teed.iter().map(|t| t as &dyn Storage).collect();
            return self.read_member3(&refs);
        }
        self.with_enrolled3(|_| Ok(()))?;
        Ok(())
    }

    /// The shared folder of a member device (`member3.json`: the folder
    /// and the owner device its trust starts from).
    pub(crate) fn member_state3(&self) -> Option<(Id16, Id16)> {
        let st: MemberState3 = util::read_json(&self.home.join(MEMBER_FILE)).ok()?;
        let f = hex::decode(&st.folder).ok()?.try_into().ok()?;
        let a = hex::decode(&st.anchor).ok()?.try_into().ok()?;
        Some((f, a))
    }

    pub(crate) fn save_member_state3(&self, folder: &Id16, anchor: &Id16) -> Result<()> {
        util::write_json(
            &self.home.join(MEMBER_FILE),
            &MemberState3 {
                folder: hex::encode(folder),
                anchor: hex::encode(anchor),
            },
        )
    }

    /// A member device: read its grants and the folder epochs, and keep
    /// what they give as the engine's membership.
    fn read_member3(&mut self, storages: &[&dyn Storage]) -> Result<()> {
        let Some((folder, anchor)) = self.member_state3() else {
            return Ok(());
        };
        let vault = bin(&self.vault.vault_id)?;
        let view = {
            let Some(kem) = self.epochs.kem.as_ref() else {
                bail!("this member device has no KEM key (K8)");
            };
            crate::membership3::MemberView::read(storages, vault, self.me3(), kem, folder, anchor)?
        };
        self.adopt_members3(Members3::of_member(view), VaultKeys::default())
    }

    /// `with_members3` after publishing this device's device record when
    /// the registry lacks it.
    pub(crate) fn with_enrolled3<R>(
        &mut self,
        f: impl FnOnce(&mut Membership<'_>) -> Result<R>,
    ) -> Result<Option<R>> {
        let name = self.vault.device_name.clone();
        self.with_members3(|m| {
            if m.devices.get(&m.me).is_none() {
                m.enrol(&name)?;
            }
            f(m)
        })
    }

    /// Keep what a `Membership` read: the registries, newer vault keys,
    /// the folders of the vault in the local keyring (with the keys granted
    /// to this device), the device list.
    fn adopt_members3(&mut self, mut snapshot: Members3, keys: VaultKeys) -> Result<()> {
        // Keys this device took from escrow (`recover_folders3`) are kept
        // in the local keyring only: they count as held.
        for rec in self.keyring.folders.values() {
            let Ok(id) = bin(&rec.folder_id) else {
                continue;
            };
            if snapshot.granted.get(&id).is_some() || rec.k11_hex.is_empty() {
                continue;
            }
            let mut epochs = BTreeMap::new();
            if !rec.key_hex.is_empty() {
                epochs.insert(0, SecretKey::from_hex(&rec.key_hex)?);
            }
            for (e, k) in &rec.epoch_keys {
                epochs.insert(*e, SecretKey::from_hex(k)?);
            }
            if epochs.is_empty() {
                continue;
            }
            snapshot.granted.add(crate::membership3::FolderKeys {
                folder: id,
                epochs,
                k11: SecretKey::from_hex(&rec.k11_hex)?,
            });
        }
        let mut epochs_changed = false;
        for (e, k) in keys.keys {
            if let std::collections::btree_map::Entry::Vacant(v) = self.epochs.keys.entry(e) {
                v.insert(k);
                epochs_changed = true;
            }
        }
        if epochs_changed {
            self.save_epochs()?;
        }
        let mut lamport = 0;
        for st in snapshot.registry.folders.values() {
            lamport = lamport.max(st.max_lamport);
        }
        for (d, _) in snapshot.devices.devices.values() {
            lamport = lamport.max(d.stamp.lamport);
        }
        self.f3.members = snapshot;
        self.observe_clock(lamport)?;
        // A folder another device converted into a Strongroom (or gave a
        // new Strongroom key) takes the old one's place here before the
        // old one, now removed, is forgotten.
        self.adopt_conversions3()?;
        self.sync_keyring3()?;
        self.sync_devices3()
    }

    /// The local keyring follows the folder records: every folder of the
    /// vault is listed (with its keys when a grant gave them here), removed
    /// folders are forgotten.
    fn sync_keyring3(&mut self) -> Result<()> {
        let mut changed = false;
        let folders: Vec<(Id16, String, Id16, bool, bool)> = self
            .f3
            .members
            .registry
            .folders
            .values()
            .map(|st| {
                (
                    st.id,
                    st.name.clone(),
                    st.creator,
                    st.is_removed(),
                    !st.members.is_empty(),
                )
            })
            .collect();
        let mut removed = Vec::new();
        for (id, name, creator, is_removed, shared) in folders {
            let fid = FolderId::from_bytes(&id);
            if is_removed {
                if self
                    .keyring
                    .folders
                    .get(&fid)
                    .is_some_and(|r| !r.is_removed())
                {
                    removed.push(fid);
                }
                continue;
            }
            let keys = self.f3.members.granted.get(&id).cloned();
            changed |= !self.keyring.folders.contains_key(&fid);
            let rec = self
                .keyring
                .folders
                .entry(fid.clone())
                .or_insert_with(|| FolderRecord {
                    folder_id: fid.clone(),
                    name: name.clone(),
                    key_hex: String::new(),
                    k11_hex: String::new(),
                    created_by: DeviceId::from_bytes(&creator),
                    created_utc: util::now_utc(),
                    shared: false,
                    policy: None,
                    policy_updated_utc: 0,
                    placement: None,
                    placement_updated_utc: 0,
                    strongroom: None,
                    removed_utc: 0,
                    epoch_keys: BTreeMap::new(),
                    backup: None,
                });
            if rec.name != name {
                rec.name = name;
                changed = true;
            }
            if rec.shared != shared {
                rec.shared = shared;
                changed = true;
            }
            if let Some(info) = self
                .f3
                .members
                .strongrooms
                .get(&id)
                .and_then(|r| r.info().ok())
            {
                if rec.strongroom.as_ref() != Some(&info) {
                    rec.strongroom = Some(info);
                    changed = true;
                }
            }
            if let Some(k) = keys {
                for (e, k9) in &k.epochs {
                    let hex = k9.to_hex();
                    if *e == 0 {
                        if rec.key_hex != hex {
                            rec.key_hex = hex;
                            changed = true;
                        }
                    } else if rec.epoch_keys.get(e) != Some(&hex) {
                        rec.epoch_keys.insert(*e, hex);
                        changed = true;
                    }
                }
                let k11 = k.k11.to_hex();
                if rec.k11_hex != k11 {
                    rec.k11_hex = k11;
                    changed = true;
                }
            }
        }
        for fid in removed {
            self.forget_folder(&fid, util::now_utc())?;
            changed = true;
        }
        if changed {
            self.keyring.save(
                &self.home,
                &self.keys,
                &self.vault.vault_id,
                &self.vault.device_id,
            )?;
        }
        Ok(())
    }

    /// The device list (`devices.json`) follows the device records.
    fn sync_devices3(&mut self) -> Result<()> {
        let m = &self.f3.members;
        let mut devices = BTreeMap::new();
        let mut epochs = BTreeMap::new();
        let mut details = BTreeMap::new();
        for (id, (rec, epoch)) in &m.devices.devices {
            let did = DeviceId::from_bytes(id);
            if let Some(d) = &rec.details {
                details.insert(
                    did.clone(),
                    super::devinfo::DeviceDetails::of_record(&did, d),
                );
            }
            devices.insert(
                did.clone(),
                DeviceRecord {
                    device_id: did.clone(),
                    name: rec.name.clone(),
                    pubkey_hex: hex::encode(&rec.sign_pub),
                    enrolled_utc: self
                        .devices
                        .devices
                        .get(&did)
                        .map(|r| r.enrolled_utc)
                        .unwrap_or_else(util::now_utc),
                },
            );
            if *epoch > 0 {
                epochs.insert(did, *epoch);
            }
        }
        let mut members = BTreeMap::new();
        for md in m.members.members.values() {
            let did = DeviceId::from_bytes(&md.device);
            members.insert(
                did.clone(),
                DeviceRecord {
                    device_id: did,
                    name: md.name.clone(),
                    pubkey_hex: hex::encode(&md.k6),
                    enrolled_utc: 0,
                },
            );
        }
        let mut revoked = BTreeMap::new();
        for (id, r) in &m.revocations {
            revoked.insert(
                DeviceId::from_bytes(id),
                membership::Revoked {
                    by: DeviceId::from_bytes(&r.issuer),
                    issued_utc: 0,
                    cutoff_seq: r.cutoff_seq,
                    wipe: r.wipe,
                },
            );
        }
        let changed = self.devices.devices.keys().ne(devices.keys())
            || self.devices.members.keys().ne(members.keys())
            || self.devices.revoked.keys().ne(revoked.keys())
            || self.devices.record_epochs != epochs
            || self.devices.details != details;
        self.devices.details = details;
        self.devices.devices = devices;
        self.devices.members = members;
        self.devices.revoked = revoked;
        self.devices.record_epochs = epochs;
        if changed {
            self.save_devices()?;
        }
        Ok(())
    }

    /// Read the membership once in this process if nothing did yet.
    pub(crate) fn members3_ready(&mut self) -> Result<()> {
        if !self.f3.members.read {
            self.refresh_members3()?;
        }
        Ok(())
    }

    /// The keys of `folder` held here: from grants to this device (the
    /// local keyring keeps a copy), never derived from the vault key.
    pub(crate) fn folder_keys3(&self, rec: &FolderRecord) -> Result<FolderKeys> {
        if rec.key_hex.is_empty() && rec.epoch_keys.is_empty() {
            bail!(
                "this device holds no key of folder {}: ask for it with `varsto folder request {}` and approve it on a device that has the folder",
                rec.name,
                rec.name
            );
        }
        rec.keys()
    }

    /// The recovery key of this session (made by `init`, or given with
    /// `unlock --with-recovery-key`): folder epochs made now are escrowed
    /// under it at once.
    pub fn set_recovery_key(&mut self, k1: Option<crate::membership3::RecoveryKey>) {
        self.f3.recovery = k1;
    }

    /// `join --recovery-words`: every folder key the escrow holds, opened
    /// with the recovery key and this device's K3₀, is kept here (the
    /// vault words alone give no folder). Returns the names of the folders
    /// recovered.
    pub fn recover_folders(&mut self, k1: &crate::membership3::RecoveryKey) -> Result<Vec<String>> {
        let got = self
            .with_enrolled3(|m| {
                let keys = m.recover_all_folders(k1)?;
                Ok(keys
                    .folders
                    .keys()
                    .filter_map(|f| m.registry.get(f).map(|s| s.name.clone()))
                    .collect::<Vec<_>>())
            })?
            .ok_or_else(|| anyhow!("no storage to read the recovery copies from"))?;
        self.f3.recovery = Some(k1.clone());
        Ok(got)
    }

    /// `add_folder` with the recovery key given for this folder's escrow
    /// (when the session holds none).
    pub fn add_folder_with_recovery(
        &mut self,
        name: &str,
        path: &Path,
        k1: Option<crate::membership3::RecoveryKey>,
    ) -> Result<FolderId> {
        if self.f3.recovery.is_some() || k1.is_none() {
            return self.add_folder(name, path);
        }
        self.f3.recovery = k1;
        let out = self.add_folder(name, path);
        self.f3.recovery = None;
        out
    }

    /// Whether this session holds the recovery key.
    pub fn has_recovery_key(&self) -> bool {
        self.f3.recovery.is_some()
    }

    /// The recovery kit with both word sets (the newest vault key and the
    /// recovery key of this session), as `init` prints it.
    pub fn recovery_kit_text(&self) -> Result<String> {
        let k1 = self.f3.recovery.as_ref().ok_or_else(|| {
            anyhow!("the recovery words are not at hand in this session (give them with --with-recovery-key)")
        })?;
        self.f3_kit_text(k1)
    }
}
