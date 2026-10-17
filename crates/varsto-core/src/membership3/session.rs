// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `Membership`: the membership records of one vault as one device sees
//! them, and the operations that write new ones.

use super::devices::{DeviceRecord, DeviceRegistry};
use super::epochs::{
    self, FolderEpochRecord, FolderEpochs, RemovalReport, Removed, RevocationRecord,
    VaultEpochRecord,
};
use super::escrow::{EscrowRecord, MissingEscrow, RecoveryKey};
use super::folders::{folder_id, Denied, FolderRecord, FolderRegistry, FolderState, Participant};
use super::grants::{self, k10_of, k11_of, FolderKeys, GrantRecord, GrantedKeys, VaultGrantRecord};
use super::keys::{KeyRing, VaultKeys};
use super::requests::{fingerprint, PendingRequest, RequestRecord};
use super::store::{self, Writer};
use super::trust::Trust;
use super::{derive3, Role, Stamp, VAULT_SCOPE};
use crate::crypto::{SecretKey, SigningKey, VerifyingKey};
use crate::kem::DecapsKey;
use crate::record::{
    Id16, KeyId, Kind, Record, RecordName, RecordsRefused, SignedRecord, StreamRef,
};
use crate::storage::Storage;
use anyhow::{anyhow, bail, Result};
use rand::RngCore;
use std::collections::{BTreeMap, BTreeSet};

/// What `start_folder_epoch` did.
#[derive(Clone, Debug)]
pub struct EpochStart {
    pub folder: Id16,
    pub epoch: u32,
    pub keys: FolderKeys,
    /// Participants that stay and were granted the new key.
    pub granted_to: Vec<Id16>,
    /// Participants that stay but have no device record with a KEM key
    /// here (members of other vaults: WP8b).
    pub pending: Vec<Id16>,
    /// Whether the new epoch was escrowed (K1 was given).
    pub escrowed: bool,
}

/// The membership state of one device of one vault.
pub struct Membership<'a> {
    pub vault: Id16,
    /// Metadata storages; the first decides put-if-absent races.
    pub storages: &'a [&'a dyn Storage],
    pub me: Id16,
    sign: &'a SigningKey,
    kem: &'a DecapsKey,
    pub vault_keys: VaultKeys,
    pub devices: DeviceRegistry,
    /// Accepted revocations by removed device.
    pub revocations: BTreeMap<Id16, RevocationRecord>,
    revoked: BTreeSet<Id16>,
    /// Vault epoch numbers with two signed records.
    pub vault_forks: BTreeMap<u32, BTreeSet<Id16>>,
    /// Folder records and the folder epochs this device could read.
    pub registry: FolderRegistry,
    /// Folder keys from grants to this device (and recovery).
    pub granted: GrantedKeys,
    /// Keys from escrow (`recover_all_folders`), kept across refreshes.
    recovered: GrantedKeys,
    /// The issuer the user kept for a folder epoch number with two records.
    pub kept: BTreeMap<(Id16, u32), Id16>,
    pub refused: RecordsRefused,
    lamport: u64,
}

impl<'a> Membership<'a> {
    /// Open with the vault keys this device holds (K3₀ up to its newest
    /// epoch) and read everything.
    pub fn open(
        vault: Id16,
        storages: &'a [&'a dyn Storage],
        sign: &'a SigningKey,
        kem: &'a DecapsKey,
        vault_keys: VaultKeys,
    ) -> Result<Membership<'a>> {
        let mut m = Membership {
            vault,
            storages,
            me: super::devices::device_id(&sign.public()),
            sign,
            kem,
            vault_keys,
            devices: DeviceRegistry::default(),
            revocations: BTreeMap::new(),
            revoked: BTreeSet::new(),
            vault_forks: BTreeMap::new(),
            registry: FolderRegistry::default(),
            granted: GrantedKeys::default(),
            recovered: GrantedKeys::default(),
            kept: BTreeMap::new(),
            refused: RecordsRefused::default(),
            lamport: 0,
        };
        m.refresh()?;
        Ok(m)
    }

    /// Open with one vault key (the vault words): its epoch is found on
    /// the storages and the chain of vault epoch records gives every older
    /// key down to K3₀. A key from before a removal does not open the
    /// newest records: such a device sees an old vault and gets no grant.
    pub fn join(
        vault: Id16,
        storages: &'a [&'a dyn Storage],
        sign: &'a SigningKey,
        kem: &'a DecapsKey,
        k3: SecretKey,
    ) -> Result<Membership<'a>> {
        let top = epochs::epoch_of_key(storages, vault, &k3)?;
        if epochs::highest_number(storages)? > top {
            bail!("this vault key is out of date: a device was removed since (the keys changed then). Use the current vault key: pair from one of your devices, or print a new recovery kit there");
        }
        let (keys, _) = epochs::walk_vault_chain(storages, vault, top, k3)?;
        Membership::open(vault, storages, sign, kem, keys)
    }

    fn writer(&self) -> Writer<'_> {
        Writer {
            vault: self.vault,
            storages: self.storages,
            device: self.me,
            key: self.sign,
        }
    }

    fn ring(&self) -> KeyRing<'_> {
        KeyRing {
            me: self.me,
            vault: &self.vault_keys,
            kem: Some(self.kem),
            devices: Some(&self.devices),
            folders: Some(&self.granted),
            recovery: None,
            extra: Vec::new(),
        }
    }

    fn trust(&self) -> Trust<'_> {
        Trust {
            devices: &self.devices,
            revoked: &self.revoked,
            folders: Some(&self.registry),
        }
    }

    fn next_stamp(&mut self) -> Stamp {
        self.lamport += 1;
        Stamp {
            lamport: self.lamport,
            device: self.me,
        }
    }

    fn newest_registry(&self) -> KeyId {
        KeyId::Registry(self.vault_keys.newest_epoch())
    }

    /// Whether `device` was removed from the vault.
    pub fn is_revoked(&self, device: &Id16) -> bool {
        self.revoked.contains(device)
    }

    // ----- reading ---------------------------------------------------------

    /// Read every membership record again.
    pub fn refresh(&mut self) -> Result<()> {
        self.refused = RecordsRefused::default();
        self.read_devices()?;
        if self.adopt_vault_grants()? {
            self.read_devices()?;
        }
        self.read_vault_epochs()?;
        let devices = &self.devices;
        let trust = Trust {
            devices,
            revoked: &self.revoked,
            folders: None,
        };
        let ring = KeyRing::vault_only(self.me, &self.vault_keys);
        self.registry =
            FolderRegistry::read(self.storages, self.vault, &ring, &trust, &mut self.refused)?;
        self.read_folder_keys()?;
        let mut lamport = self.lamport;
        for st in self.registry.folders.values() {
            lamport = lamport.max(st.max_lamport);
        }
        for (d, _) in self.devices.devices.values() {
            lamport = lamport.max(d.stamp.lamport);
        }
        self.lamport = lamport;
        Ok(())
    }

    fn read_devices(&mut self) -> Result<()> {
        let ring = KeyRing::vault_only(self.me, &self.vault_keys);
        self.devices = DeviceRegistry::read(self.storages, self.vault, &ring, &mut self.refused)?;
        Ok(())
    }

    /// Adopt newer vault keys granted to this device. A grant counts when
    /// a trusted device signed it, its key opens a chain of epoch records
    /// that leads to the keys this device holds, and the newest record
    /// keeps this device.
    fn adopt_vault_grants(&mut self) -> Result<bool> {
        let mut counter = std::mem::take(&mut self.refused);
        let grants = {
            let ring = self.ring();
            let trust = Trust {
                devices: &self.devices,
                revoked: &self.revoked,
                folders: None,
            };
            grants::read_vault_grants(
                self.storages,
                self.vault,
                &self.me,
                &ring,
                &trust,
                &mut counter,
            )
        };
        self.refused = counter;
        let grants = grants?;
        let mut changed = false;
        let mut sorted: Vec<&Record<VaultGrantRecord>> = grants.iter().collect();
        sorted.sort_by_key(|g| g.body.epoch);
        for g in sorted {
            if g.body.epoch <= self.vault_keys.newest_epoch() {
                continue;
            }
            let Ok((keys, opened)) = epochs::walk_vault_chain(
                self.storages,
                self.vault,
                g.body.epoch,
                SecretKey(g.body.k3),
            ) else {
                continue;
            };
            let agrees = self
                .vault_keys
                .keys
                .iter()
                .all(|(e, k)| keys.get(*e).is_none_or(|n| n.0 == k.0));
            let keeps_me = opened
                .first()
                .is_some_and(|o| o.record.members.contains(&self.me));
            if agrees && keeps_me {
                for (e, k) in keys.keys {
                    self.vault_keys.keys.entry(e).or_insert(k);
                }
                changed = true;
            }
        }
        Ok(changed)
    }

    /// Check the chain of vault epoch records this device holds (every
    /// record signed by a device of the vault), find numbers with two
    /// records, and accept the revocations the epochs back.
    fn read_vault_epochs(&mut self) -> Result<()> {
        self.revoked.clear();
        self.revocations.clear();
        let (top, k3) = match self.vault_keys.newest() {
            Some((e, k)) => (e, k.clone()),
            None => bail!("no vault key"),
        };
        let (_, opened) = epochs::walk_vault_chain(self.storages, self.vault, top, k3)?;
        let mut backing: BTreeMap<u32, (Id16, Vec<Id16>)> = BTreeMap::new();
        for o in &opened {
            let pk = self.devices.signing_key(&o.record.issuer).ok_or_else(|| {
                anyhow!(
                    "vault epoch {} is signed by an unknown device",
                    o.record.epoch
                )
            })?;
            if o.envelope.iter().any(|e| e.verify(&pk).is_err()) {
                bail!(
                    "the signature of vault epoch {} does not verify",
                    o.record.epoch
                );
            }
            backing.insert(o.record.epoch, (o.record.issuer, o.record.revoked.clone()));
        }
        let devices = &self.devices;
        let found = store::numbered(
            self.storages,
            self.vault,
            Kind::Epoch,
            "vault/epochs/",
            &|d| devices.signing_key(d),
        )?;
        self.vault_forks.clear();
        for (seq, list) in found {
            if list.len() > 1 {
                if let Ok(e) = u32::try_from(seq) {
                    self.vault_forks
                        .insert(e, list.iter().map(|n| n.device).collect());
                }
            }
        }
        let revs: Vec<Record<RevocationRecord>> = {
            let ring = KeyRing::vault_only(self.me, &self.vault_keys);
            let empty = BTreeSet::new();
            let trust = Trust {
                devices: &self.devices,
                revoked: &empty,
                folders: None,
            };
            store::read_all(
                self.storages,
                self.vault,
                Kind::Revocation,
                "vault/revocations/",
                &ring,
                &trust,
                &mut self.refused,
            )?
        };
        let mut revs: Vec<RevocationRecord> = revs.into_iter().map(|r| r.body).collect();
        revs.sort_by_key(|r| (r.new_epoch, r.issuer));
        for r in revs {
            let backed = backing.get(&r.new_epoch).is_some_and(|(issuer, revoked)| {
                *issuer == r.issuer && revoked.contains(&r.device)
            });
            if !backed || self.revoked.contains(&r.issuer) {
                continue;
            }
            self.revoked.insert(r.device);
            self.revocations.entry(r.device).or_insert(r);
        }
        Ok(())
    }

    /// Whether `d` may grant (and start epochs) in `folder` at `epoch`.
    fn owner_at(st: &FolderState, ep: &FolderEpochs, d: &Id16, epoch: u32) -> bool {
        !ep.removed_at(d, epoch)
            && (st.role(d) == Some(Role::Owner) || ep.role_kept(d, epoch) == Some(Role::Owner))
    }

    /// Read folder epochs and grants to this device, folder by folder.
    fn read_folder_keys(&mut self) -> Result<()> {
        let mut counter = std::mem::take(&mut self.refused);
        let grants = {
            let ring = self.ring();
            let trust = Trust {
                devices: &self.devices,
                revoked: &self.revoked,
                folders: None,
            };
            grants::read_folder_grants(
                self.storages,
                self.vault,
                &self.me,
                &ring,
                &trust,
                &mut counter,
            )
        };
        self.refused = counter;
        let grants = grants?;
        let mut by_folder: BTreeMap<Id16, Vec<Record<GrantRecord>>> = BTreeMap::new();
        for g in grants {
            by_folder.entry(g.body.folder).or_default().push(g);
        }
        self.granted = GrantedKeys::default();
        self.registry.epochs.clear();
        let folders: Vec<Id16> = self.registry.folders.keys().copied().collect();
        for folder in folders {
            let list = by_folder.remove(&folder).unwrap_or_default();
            let (ep, keys) = self.load_folder(&folder, list)?;
            self.registry.epochs.insert(folder, ep);
            if let Some(k) = keys {
                self.granted.add(k);
            }
        }
        for (_, k) in self.recovered.folders.clone() {
            self.granted.add(k);
        }
        Ok(())
    }

    /// One folder: apply its epoch records in order as far as this device
    /// holds their keys, and accept the grants whose issuer was an owner at
    /// their epoch, until nothing changes.
    fn load_folder(
        &mut self,
        folder: &Id16,
        mut list: Vec<Record<GrantRecord>>,
    ) -> Result<(FolderEpochs, Option<FolderKeys>)> {
        let Some(st) = self.registry.folders.get(folder).cloned() else {
            return Ok((FolderEpochs::default(), None));
        };
        let prefix = FolderEpochRecord::stream(*folder, [0u8; 16])
            .prefix()
            .unwrap_or_default();
        let devices = &self.devices;
        let envs = store::numbered(self.storages, self.vault, Kind::ShareEpoch, &prefix, &|d| {
            devices.signing_key(d)
        })?;
        // The creator's grants first: two different K9₀ cannot both be right.
        list.sort_by_key(|g| {
            (
                g.body.epoch,
                g.body.issuer != st.creator,
                g.body.issuer,
                g.meta.seq,
            )
        });
        let mut accepted = vec![false; list.len()];
        let mut keys: Option<FolderKeys> = self.recovered.get(folder).cloned();
        let kept: BTreeMap<u32, Id16> = self
            .kept
            .iter()
            .filter(|((f, _), _)| f == folder)
            .map(|((_, e), d)| (*e, *d))
            .collect();
        let mut counter = std::mem::take(&mut self.refused);
        let result = loop {
            // (a) epoch records with the keys held so far.
            let mut ep = FolderEpochs {
                kept: kept.clone(),
                ..FolderEpochs::default()
            };
            let mut stopped = false;
            for (seq, cands) in &envs {
                let Ok(e) = u32::try_from(*seq) else { continue };
                if e == 0 {
                    continue;
                }
                let owners: Vec<&store::Numbered> = cands
                    .iter()
                    .filter(|n| Self::owner_at(&st, &ep, &n.device, e - 1))
                    .collect();
                if owners.is_empty() {
                    continue;
                }
                ep.seen.insert(e, owners.iter().map(|n| n.device).collect());
                if stopped || e != ep.current() + 1 {
                    stopped = true;
                    continue;
                }
                let chosen: Vec<&&store::Numbered> = match kept.get(&e) {
                    Some(k) => owners.iter().filter(|n| n.device == *k).collect(),
                    None => owners.iter().collect(),
                };
                if chosen.len() != 1 {
                    ep.forks
                        .insert(e, owners.iter().map(|n| n.device).collect());
                    stopped = true;
                    continue;
                }
                let Some(k9) = keys.as_ref().and_then(|k| k.epochs.get(&e)) else {
                    stopped = true;
                    continue;
                };
                match self.open_epoch_record(folder, e, k9, chosen[0], &mut counter) {
                    Some(rec) => {
                        ep.applied.insert(e, rec);
                    }
                    None => stopped = true,
                }
            }
            // (b) grants.
            let mut changed = false;
            for (i, g) in list.iter().enumerate() {
                if accepted[i] {
                    continue;
                }
                let b = &g.body;
                let e = b.epoch;
                if ep.forks.keys().any(|f| *f <= e) {
                    continue;
                }
                let k9 = SecretKey(b.k9);
                let ok = if e == 0 {
                    Self::owner_at(&st, &ep, &b.issuer, 0)
                } else if ep.applied.contains_key(&e) {
                    Self::owner_at(&st, &ep, &b.issuer, e)
                        && keys
                            .as_ref()
                            .and_then(|k| k.epochs.get(&e))
                            .is_some_and(|held| held.0 == b.k9)
                } else if e == ep.current() + 1 {
                    // The epoch record is not applied yet: the grant's key
                    // must open the one record of an owner under e.
                    let issuer_ok = Self::owner_at(&st, &ep, &b.issuer, e - 1)
                        || ep.seen.get(&e).is_some_and(|s| s.contains(&b.issuer));
                    let one = envs.get(&u64::from(e)).and_then(|c| {
                        let owners: Vec<&store::Numbered> = c
                            .iter()
                            .filter(|n| Self::owner_at(&st, &ep, &n.device, e - 1))
                            .filter(|n| kept.get(&e).is_none_or(|k| *k == n.device))
                            .collect();
                        (owners.len() == 1).then(|| owners[0])
                    });
                    issuer_ok
                        && one.is_some_and(|n| {
                            self.open_epoch_record(folder, e, &k9, n, &mut counter)
                                .is_some()
                        })
                } else {
                    false
                };
                if !ok {
                    continue;
                }
                let mut gk = FolderKeys {
                    folder: *folder,
                    epochs: BTreeMap::from([(e, k9)]),
                    k11: SecretKey(b.k11),
                };
                for (oe, ok9) in &b.older {
                    gk.epochs.insert(*oe, SecretKey(*ok9));
                }
                // K11 must come from K9₀ when the grant carries K9₀.
                if let Some(k0) = gk.epochs.get(&0) {
                    if k11_of(folder, k0).0 != gk.k11.0 {
                        continue;
                    }
                }
                let fits = match &mut keys {
                    None => {
                        keys = Some(gk);
                        true
                    }
                    Some(have) => {
                        let agree = have.k11.0 == gk.k11.0
                            && gk
                                .epochs
                                .iter()
                                .all(|(e, k)| have.epochs.get(e).is_none_or(|h| h.0 == k.0));
                        agree && have.merge(&gk)
                    }
                };
                if fits {
                    accepted[i] = true;
                    changed = true;
                }
            }
            if !changed {
                break (ep, keys);
            }
        };
        self.refused = counter;
        Ok(result)
    }

    /// Accept a folder epoch record with the key K9ₑ.
    fn open_epoch_record(
        &self,
        folder: &Id16,
        epoch: u32,
        k9: &SecretKey,
        n: &store::Numbered,
        counter: &mut RecordsRefused,
    ) -> Option<FolderEpochRecord> {
        let mut ring = KeyRing::vault_only(self.me, &self.vault_keys);
        ring.extra.push((
            KeyId::Meta {
                folder: *folder,
                epoch,
            },
            k10_of(folder, k9),
        ));
        let trust = Trust {
            devices: &self.devices,
            revoked: &self.revoked,
            folders: None,
        };
        store::accept_numbered::<FolderEpochRecord>(self.vault, &ring, &trust, n, counter)
            .map(|r| r.body)
    }

    /// The role of `device` in `folder` at folder epoch `epoch`.
    pub fn role(&self, device: &Id16, folder: &Id16, epoch: u32) -> Option<Role> {
        self.registry.role(device, folder, epoch)
    }

    /// Folder keys this device holds (from grants and recovery).
    pub fn read_my_grants(&self) -> &GrantedKeys {
        &self.granted
    }

    /// `RecordKeys` of this device: registry, ledger and epoch keys of
    /// every vault epoch held, `meta:` and `share-ledger:` keys of the
    /// folder epochs held, its K8.
    pub fn record_keys(&self) -> KeyRing<'_> {
        self.ring()
    }

    /// `RecordTrust` of this device.
    pub fn record_trust(&self) -> Trust<'_> {
        self.trust()
    }

    /// The epochs of `folder` as this device sees them.
    pub fn folder_epochs(&self, folder: &Id16) -> FolderEpochs {
        self.registry
            .epochs
            .get(folder)
            .cloned()
            .unwrap_or_default()
    }

    // ----- writing ---------------------------------------------------------

    /// Publish this device's record (name, K6, K8) under the newest
    /// registry key.
    pub fn enrol(&mut self, name: &str) -> Result<()> {
        let stamp = self.next_stamp();
        let rec = DeviceRecord {
            device: self.me,
            name: name.to_string(),
            sign_pub: self.sign.public().to_bytes(),
            kem_pub: self.kem.public().to_bytes(),
            stamp,
        };
        let key = self.newest_registry();
        self.writer().write(
            &self.ring(),
            &DeviceRecord::stream(self.me),
            None,
            &key,
            &rec,
        )?;
        self.read_devices()
    }

    fn write_folder_record(
        &mut self,
        folder: &Id16,
        creation: Option<[u8; 16]>,
        name: Option<(String, BTreeMap<String, String>)>,
        participants: Vec<Participant>,
        denied: Vec<Denied>,
    ) -> Result<()> {
        let stamp = self.next_stamp();
        let (name, settings) = match name {
            Some(n) => n,
            None => {
                let st = self
                    .registry
                    .get(folder)
                    .ok_or_else(|| anyhow!("no folder {}", hex::encode(folder)))?;
                (st.name.clone(), st.settings.clone())
            }
        };
        let rec = FolderRecord {
            id: *folder,
            name,
            settings,
            stamp,
            creation,
            participants,
            denied,
        };
        let key = self.newest_registry();
        self.writer().write(
            &self.ring(),
            &FolderRegistry::stream(*folder, self.me),
            None,
            &key,
            &rec,
        )?;
        Ok(())
    }

    /// Create a folder: its first folder record (this device the owner),
    /// a random K9₀ granted to this device, and an escrow when K1 is given.
    pub fn create_folder(
        &mut self,
        name: &str,
        settings: BTreeMap<String, String>,
        k1: Option<&RecoveryKey>,
    ) -> Result<Id16> {
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let folder = folder_id(&self.me, &nonce);
        let stamp = Stamp {
            lamport: self.lamport + 1,
            device: self.me,
        };
        let me = Participant {
            device: self.me,
            role: Role::Owner,
            stamp,
        };
        self.write_folder_record(
            &folder,
            Some(nonce),
            Some((name.to_string(), settings)),
            vec![me],
            Vec::new(),
        )?;
        let keys = FolderKeys::new_folder(folder, SecretKey::random());
        self.write_grant(&keys, 0, self.me, Role::Owner)?;
        if let Some(k1) = k1 {
            self.write_escrow(&keys, 0, k1)?;
        }
        self.refresh()?;
        Ok(folder)
    }

    fn write_grant(
        &self,
        keys: &FolderKeys,
        epoch: u32,
        recipient: Id16,
        role: Role,
    ) -> Result<()> {
        let k9 = keys
            .epochs
            .get(&epoch)
            .ok_or_else(|| anyhow!("folder epoch {epoch} is not held here"))?;
        let older = keys.epochs.range(..epoch).map(|(e, k)| (*e, k.0)).collect();
        let body = GrantRecord {
            folder: keys.folder,
            epoch,
            recipient,
            issuer: self.me,
            role,
            k9: k9.0,
            k11: keys.k11.0,
            older,
        };
        if self.devices.kem_key(&recipient).is_none() {
            bail!(
                "device {} has no KEM key in its device record",
                hex::encode(recipient)
            );
        }
        self.writer().write(
            &self.ring(),
            &body.stream(),
            None,
            &KeyId::Kem(recipient),
            &body,
        )?;
        Ok(())
    }

    /// Grant `folder`'s key of `epoch` (and every older one held) to
    /// `recipient`. Only an owner of the folder at that epoch may; readers
    /// refuse a grant from anyone else.
    pub fn issue_grant(
        &mut self,
        folder: &Id16,
        epoch: u32,
        recipient: &Id16,
        role: Role,
    ) -> Result<()> {
        if !self.registry.is_owner(&self.me, folder, epoch) {
            bail!("this device is not an owner of the folder");
        }
        let keys = self
            .granted
            .get(folder)
            .cloned()
            .ok_or_else(|| anyhow!("this device holds no key of the folder"))?;
        self.write_grant(&keys, epoch, *recipient, role)
    }

    /// Ask for `folder` (a device that holds K3 but not the folder).
    pub fn request_folder(&mut self, folder: &Id16, role_wanted: Role) -> Result<()> {
        let name = self.devices.name(&self.me);
        let body = RequestRecord {
            device: self.me,
            name,
            kem_pub: self.kem.public().to_bytes(),
            role_wanted,
        };
        let key = self.newest_registry();
        self.writer().write(
            &self.ring(),
            &RequestRecord::stream(*folder, self.me),
            None,
            &key,
            &body,
        )?;
        Ok(())
    }

    /// Requests for `folder` that are not answered: the requester is a
    /// device of the vault whose device record carries the request's K8,
    /// neither a participant nor denied.
    pub fn list_requests(&mut self, folder: &Id16) -> Result<Vec<PendingRequest>> {
        let prefix = format!("vault/requests/{}/", hex::encode(folder));
        let recs: Vec<Record<RequestRecord>> = {
            let ring = self.ring();
            let trust = self.trust();
            let mut counter = RecordsRefused::default();
            let r = store::read_all(
                self.storages,
                self.vault,
                Kind::Request,
                &prefix,
                &ring,
                &trust,
                &mut counter,
            )?;
            for (k, v) in counter.by_kind {
                *self.refused.by_kind.entry(k).or_insert(0) += v;
            }
            r
        };
        let st = self.registry.get(folder);
        let mut newest: BTreeMap<Id16, Record<RequestRecord>> = BTreeMap::new();
        for r in recs {
            if r.meta.scope != *folder {
                continue;
            }
            match newest.get(&r.body.device) {
                Some(o) if o.meta.seq >= r.meta.seq => {}
                _ => {
                    newest.insert(r.body.device, r);
                }
            }
        }
        let mut out = Vec::new();
        for (device, r) in newest {
            let Some(dev) = self.devices.get(&device) else {
                continue;
            };
            if dev.kem_pub != r.body.kem_pub {
                continue;
            }
            if st.is_some_and(|s| s.entries.contains_key(&device)) {
                continue;
            }
            out.push(PendingRequest {
                folder: *folder,
                device,
                name: dev.name.clone(),
                role_wanted: r.body.role_wanted,
                fingerprint: fingerprint(&dev.sign_pub, &dev.kem_pub),
            });
        }
        Ok(out)
    }

    /// Approve `device` for `folder` with `role`: a folder record that
    /// lists it and a grant of the current epoch (and every older one).
    /// One owner's approval suffices.
    pub fn approve(&mut self, folder: &Id16, device: &Id16, role: Role) -> Result<()> {
        let epoch = self.folder_epochs(folder).current();
        if !self.registry.is_owner(&self.me, folder, epoch) {
            bail!("this device is not an owner of the folder");
        }
        let stamp = Stamp {
            lamport: self.lamport + 1,
            device: self.me,
        };
        self.write_folder_record(
            folder,
            None,
            None,
            vec![Participant {
                device: *device,
                role,
                stamp,
            }],
            Vec::new(),
        )?;
        self.issue_grant(folder, epoch, device, role)?;
        self.refresh()
    }

    /// Deny `device` (a `denied` entry; it is no longer listed as pending).
    pub fn deny(&mut self, folder: &Id16, device: &Id16) -> Result<()> {
        let epoch = self.folder_epochs(folder).current();
        if !self.registry.is_owner(&self.me, folder, epoch) {
            bail!("this device is not an owner of the folder");
        }
        let stamp = Stamp {
            lamport: self.lamport + 1,
            device: self.me,
        };
        self.write_folder_record(
            folder,
            None,
            None,
            Vec::new(),
            vec![Denied {
                device: *device,
                stamp,
            }],
        )?;
        self.refresh()
    }

    /// Start folder epoch e+1 of `folder`: a random K9, the epoch record
    /// (put-if-absent at the number), `denied` entries for the removed
    /// devices, grants to every participant that stays, and an escrow when
    /// K1 is given. Returns the new keys.
    pub fn start_folder_epoch(
        &mut self,
        folder: &Id16,
        remove: &[Removed],
        k1: Option<&RecoveryKey>,
    ) -> Result<EpochStart> {
        let ep = self.folder_epochs(folder);
        if let Some(e) = ep.unresolved().first() {
            bail!("two owners started folder epoch {e} at once; keep one first");
        }
        let current = ep.current();
        if ep.newest_seen() > current {
            bail!("another owner started a newer epoch of this folder; sync, then try again");
        }
        if !self.registry.is_owner(&self.me, folder, current) {
            bail!("this device is not an owner of the folder");
        }
        if remove.iter().any(|r| r.device == self.me) {
            bail!("a device cannot remove itself from a folder");
        }
        let mut keys = self
            .granted
            .get(folder)
            .cloned()
            .filter(|k| k.holds(current))
            .ok_or_else(|| anyhow!("this device does not hold the folder's current key"))?;
        let st = self
            .registry
            .get(folder)
            .cloned()
            .ok_or_else(|| anyhow!("no folder {}", hex::encode(folder)))?;
        let gone: BTreeSet<Id16> = remove.iter().map(|r| r.device).collect();
        let stay: Vec<Participant> = st
            .participants()
            .into_iter()
            .filter(|p| !gone.contains(&p.device) && !ep.removed_at(&p.device, current))
            .collect();
        let e = current + 1;
        let k9 = SecretKey::random();
        let body = FolderEpochRecord {
            folder: *folder,
            epoch: e,
            issuer: self.me,
            participants: stay.clone(),
            removed: remove.to_vec(),
        };
        {
            let mut ring = self.ring();
            ring.extra.push((
                KeyId::Meta {
                    folder: *folder,
                    epoch: e,
                },
                k10_of(folder, &k9),
            ));
            self.writer().write(
                &ring,
                &FolderEpochRecord::stream(*folder, self.me),
                Some(u64::from(e)),
                &KeyId::Meta {
                    folder: *folder,
                    epoch: e,
                },
                &body,
            )?;
        }
        let stamp = Stamp {
            lamport: self.lamport + 1,
            device: self.me,
        };
        let denied: Vec<Denied> = remove
            .iter()
            .map(|r| Denied {
                device: r.device,
                stamp,
            })
            .collect();
        if !denied.is_empty() {
            self.write_folder_record(folder, None, None, Vec::new(), denied)?;
        }
        keys.epochs.insert(e, k9);
        let (mut granted_to, mut pending) = (Vec::new(), Vec::new());
        for p in &stay {
            if self.devices.kem_key(&p.device).is_some() {
                self.write_grant(&keys, e, p.device, p.role)?;
                granted_to.push(p.device);
            } else {
                pending.push(p.device);
            }
        }
        let escrowed = match k1 {
            Some(k1) => {
                self.write_escrow(&keys, e, k1)?;
                true
            }
            None => false,
        };
        self.refresh()?;
        Ok(EpochStart {
            folder: *folder,
            epoch: e,
            keys,
            granted_to,
            pending,
            escrowed,
        })
    }

    /// Remove own full device `target` from the vault: a vault epoch (its
    /// signed record, the revocation, vault grants to every device that
    /// stays) and a folder epoch for every folder it held. `cutoff_seq` is
    /// its newest ledger batch that stays valid (the engine's ledger head).
    pub fn remove_device(
        &mut self,
        target: &Id16,
        cutoff_seq: u64,
        wipe: bool,
        k1: Option<&RecoveryKey>,
    ) -> Result<RemovalReport> {
        if *target == self.me {
            bail!("a device cannot remove itself");
        }
        if self.devices.get(target).is_none() || self.revoked.contains(target) {
            bail!(
                "{} is not a current device of the vault",
                hex::encode(target)
            );
        }
        if let Some(e) = self.vault_forks.keys().next() {
            bail!("two devices wrote vault epoch {e} at once; keep one first");
        }
        let (old, old_k3) = match self.vault_keys.newest() {
            Some((e, k)) => (e, k.clone()),
            None => bail!("no vault key"),
        };
        let devices = &self.devices;
        let found = store::numbered(
            self.storages,
            self.vault,
            Kind::Epoch,
            "vault/epochs/",
            &|d| devices.signing_key(d),
        )?;
        if found.keys().any(|s| *s > u64::from(old)) {
            bail!("another device changed the vault keys and this device has not received them yet; sync, then try again");
        }
        let members: Vec<Id16> = self
            .devices
            .devices
            .keys()
            .filter(|d| *d != target && !self.revoked.contains(*d))
            .copied()
            .collect();
        let new = old + 1;
        let k3 = SecretKey::random();
        let record = VaultEpochRecord {
            epoch: new,
            issuer: self.me,
            previous_epoch: old,
            previous_k3: old_k3.0,
            members: members.clone(),
            revoked: vec![*target],
        };
        {
            let mut ring = self.ring();
            ring.extra
                .push((KeyId::Epoch(new), derive3(&k3, "epoch-record", &[])));
            self.writer().write(
                &ring,
                &StreamRef::new(Kind::Epoch, VAULT_SCOPE, self.me),
                Some(u64::from(new)),
                &KeyId::Epoch(new),
                &record,
            )?;
        }
        let rev = RevocationRecord {
            device: *target,
            name: self.devices.name(target),
            issuer: self.me,
            cutoff_seq,
            wipe,
            new_epoch: new,
        };
        self.writer().write(
            &self.ring(),
            &RevocationRecord::stream(*target, self.me),
            None,
            &KeyId::Registry(0),
            &rev,
        )?;
        let mut sent = Vec::new();
        for m in &members {
            if self.devices.kem_key(m).is_none() {
                continue;
            }
            let body = VaultGrantRecord {
                epoch: new,
                recipient: *m,
                issuer: self.me,
                k3: k3.0,
            };
            self.writer().write(
                &self.ring(),
                &StreamRef::grant(VAULT_SCOPE, new, *m, self.me),
                None,
                &KeyId::Kem(*m),
                &body,
            )?;
            sent.push(*m);
        }
        self.vault_keys.keys.insert(new, k3);
        self.refresh()?;
        // A folder epoch for every folder the device took part in.
        let mut report = RemovalReport {
            vault_epoch: new,
            vault_keys_sent_to: sent,
            folder_epochs: Vec::new(),
            folders_not_rotated: Vec::new(),
        };
        let held: Vec<Id16> = self
            .registry
            .folders
            .iter()
            .filter(|(_, st)| st.role(target).is_some())
            .map(|(f, _)| *f)
            .collect();
        for folder in held {
            let current = self.folder_epochs(&folder).current();
            if !self.registry.is_owner(&self.me, &folder, current)
                || !self.granted.holds(&folder, current)
            {
                report.folders_not_rotated.push(folder);
                continue;
            }
            let start = self.start_folder_epoch(
                &folder,
                &[Removed {
                    device: *target,
                    cutoff: cutoff_seq,
                }],
                k1,
            )?;
            report.folder_epochs.push((folder, start.epoch));
        }
        Ok(report)
    }

    // ----- recovery escrow --------------------------------------------------

    fn write_escrow(&self, keys: &FolderKeys, epoch: u32, k1: &RecoveryKey) -> Result<()> {
        let k3_0 = self
            .vault_keys
            .k3_0()
            .ok_or_else(|| anyhow!("K3 of vault epoch 0 is not held here"))?;
        let k9 = keys
            .epochs
            .get(&epoch)
            .ok_or_else(|| anyhow!("folder epoch {epoch} is not held here"))?;
        let body = EscrowRecord {
            folder: keys.folder,
            epoch,
            k9: k9.0,
            k11: keys.k11.0,
        };
        let mut ring = self.ring();
        ring.recovery = Some(k1.escrow_key(&self.vault, k3_0));
        self.writer().write(
            &ring,
            &EscrowRecord::stream(keys.folder, epoch, self.me),
            None,
            &KeyId::Recovery,
            &body,
        )?;
        Ok(())
    }

    /// Escrow `folder`'s key of `epoch` under the recovery key.
    pub fn escrow_folder_epoch(&self, folder: &Id16, epoch: u32, k1: &RecoveryKey) -> Result<()> {
        let keys = self
            .granted
            .get(folder)
            .ok_or_else(|| anyhow!("this device holds no key of the folder"))?;
        self.write_escrow(keys, epoch, k1)
    }

    /// Every folder key the escrow holds, opened with K1 and this device's
    /// K3₀ (so the vault words and the recovery words together). Escrows
    /// count from devices that are owners of the folder in its records.
    /// The keys are kept (and merged into `granted`) from then on.
    pub fn recover_all_folders(&mut self, k1: &RecoveryKey) -> Result<GrantedKeys> {
        let k3_0 = self
            .vault_keys
            .k3_0()
            .ok_or_else(|| anyhow!("K3 of vault epoch 0 is not held here"))?
            .clone();
        let recs: Vec<Record<EscrowRecord>> = {
            let mut ring = KeyRing::vault_only(self.me, &self.vault_keys);
            ring.recovery = Some(k1.escrow_key(&self.vault, &k3_0));
            let trust = self.trust();
            let mut counter = RecordsRefused::default();
            let r = store::read_all(
                self.storages,
                self.vault,
                Kind::Escrow,
                "vault/escrow/",
                &ring,
                &trust,
                &mut counter,
            )?;
            for (k, v) in counter.by_kind {
                *self.refused.by_kind.entry(k).or_insert(0) += v;
            }
            r
        };
        let mut out = GrantedKeys::default();
        for r in recs {
            let b = &r.body;
            let Some(st) = self.registry.get(&b.folder) else {
                continue;
            };
            if st.role(&r.meta.device) != Some(Role::Owner) && st.creator != r.meta.device {
                continue;
            }
            let fk = FolderKeys {
                folder: b.folder,
                epochs: BTreeMap::from([(b.epoch, SecretKey(b.k9))]),
                k11: SecretKey(b.k11),
            };
            if b.epoch == 0 && k11_of(&b.folder, &fk.epochs[&0]).0 != fk.k11.0 {
                continue;
            }
            out.add(fk);
        }
        for (_, k) in out.folders.clone() {
            self.recovered.add(k);
        }
        self.refresh()?;
        Ok(out)
    }

    /// Folder epochs this device holds the key of with no escrow on the
    /// storages signed by an owner of the folder (the "no recovery copy"
    /// warning).
    pub fn missing_escrows(&self) -> Result<Vec<MissingEscrow>> {
        let mut out = Vec::new();
        for (folder, keys) in &self.granted.folders {
            let Some(st) = self.registry.get(folder) else {
                continue;
            };
            for epoch in keys.epochs.keys() {
                if !self.escrow_exists(st, *epoch)? {
                    out.push(MissingEscrow {
                        folder: *folder,
                        name: st.name.clone(),
                        epoch: *epoch,
                    });
                }
            }
        }
        Ok(out)
    }

    fn escrow_exists(&self, st: &FolderState, epoch: u32) -> Result<bool> {
        let prefix = format!("vault/escrow/{}/{epoch:010}/", hex::encode(st.id));
        for s in self.storages {
            for name in s.list(&prefix)? {
                let Some(n) = RecordName::parse_as(Kind::Escrow, &name) else {
                    continue;
                };
                let Some(dev) = n.device else { continue };
                if st.role(&dev) != Some(Role::Owner) && st.creator != dev {
                    continue;
                }
                let Some(pk): Option<VerifyingKey> = self.devices.signing_key(&dev) else {
                    continue;
                };
                let Ok(Some(b)) = s.get_bounded(&name, crate::record::MAX_PART_READ) else {
                    continue;
                };
                if SignedRecord::decode(&b).is_ok_and(|e| {
                    e.vault == self.vault && e.device == dev && e.verify(&pk).is_ok()
                }) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Keep `issuer`'s record of folder epoch `epoch` where two owners
    /// wrote one (the data side of WP8b's resolve command).
    pub fn resolve_folder_epoch(&mut self, folder: &Id16, epoch: u32, issuer: &Id16) -> Result<()> {
        let mut ep = self.folder_epochs(folder);
        ep.resolve(epoch, *issuer)?;
        self.kept.insert((*folder, epoch), *issuer);
        self.refresh()
    }
}
