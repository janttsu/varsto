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
    /// Read at least once in this process.
    pub read: bool,
}

impl Members3 {
    fn of(m: &Membership<'_>) -> Members3 {
        Members3 {
            devices: m.devices.clone(),
            registry: m.registry.clone(),
            granted: m.granted.clone(),
            members: m.members.clone(),
            revoked: m.revoked_set().clone(),
            revocations: m.revocations.clone(),
            refused: m.refused.clone(),
            read: true,
        }
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
        KeyRing {
            me: self.me3(),
            vault: vault_keys,
            kem: self.epochs.kem.as_ref(),
            devices: Some(&m.devices),
            folders: Some(&m.granted),
            recovery: None,
            extra: Vec::new(),
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
        let open = self.member_storages()?;
        if open.is_empty() {
            return Ok(None);
        }
        let vault = bin(&self.vault.vault_id)?;
        let refs: Vec<&dyn Storage> = open.iter().map(|(_, b)| &**b).collect();
        let lamport = self.clock.lamport;
        let (out, snapshot, keys, stamped) = {
            let Some(kem) = self.epochs.kem.as_ref() else {
                bail!("this device has no KEM key (K8); it cannot take part in format-3 folders");
            };
            let mut m = Membership::open(vault, &refs, &self.keys.signer, kem, self.vault_keys3())?;
            m.observe_lamport(lamport);
            let out = f(&mut m);
            (out, Members3::of(&m), m.vault_keys.clone(), m.lamport())
        };
        self.adopt_members3(snapshot, keys)?;
        self.observe_clock(stamped)?;
        out.map(Some)
    }

    /// Read every membership record again (and publish this device's own
    /// device record when the registry lacks it).
    pub(crate) fn refresh_members3(&mut self) -> Result<()> {
        if self.vault.member {
            return Ok(());
        }
        self.with_enrolled3(|_| Ok(()))?;
        Ok(())
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
        self.sync_keyring3()?;
        self.sync_devices3()
    }

    /// The local keyring follows the folder records: every folder of the
    /// vault is listed (with its keys when a grant gave them here), removed
    /// folders are forgotten.
    fn sync_keyring3(&mut self) -> Result<()> {
        let mut changed = false;
        let folders: Vec<(Id16, String, Id16, bool)> = self
            .f3
            .members
            .registry
            .folders
            .values()
            .map(|st| (st.id, st.name.clone(), st.creator, st.is_removed()))
            .collect();
        let mut removed = Vec::new();
        for (id, name, creator, is_removed) in folders {
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
                    share_join: None,
                });
            if rec.name != name {
                rec.name = name;
                changed = true;
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
        for (id, (rec, epoch)) in &m.devices.devices {
            let did = DeviceId::from_bytes(id);
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
            || self.devices.record_epochs != epochs;
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
