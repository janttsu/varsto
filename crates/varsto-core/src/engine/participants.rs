// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The signed participants of a folder (`docs/spec/format-2-design.md`
//! section 4).
//!
//! Every device of the vault that holds a folder as an owner publishes the
//! folder's participants as it knows them: a signed record of kind
//! `folder-roles` at
//! `vault/folder-participants/<folder>/<epoch>/<issuer>/<seq>.json`, sealed
//! under the registry key (so every device of the vault reads it, a device
//! that holds no folder key too), listing the vault's devices that hold the
//! folder's key at that epoch with their roles (owner, editor, viewer). The
//! body carries a proof that the issuer holds the epoch's key: a MAC of the
//! body under a key derived from it.
//!
//! **Which records count.** A reader builds the list epoch by epoch. In an
//! epoch, the records of trusted full devices count in this order: those
//! of the folder's creator (first epoch) or of the previous epoch's owners;
//! then those of any device an accepted record lists as an owner; then
//! those whose key proof the reader can check with a key it holds (a device
//! that came back with the recovery words, or approved by a device that
//! did), unless an accepted record lists their issuer below owner; and
//! again those of the owners they list. A record never lowers the role of a
//! device accepted before it, and otherwise the lowest role any accepted
//! record gives a device is its role.
//!
//! **What it decides.** A grant counts only when the newest list names its
//! issuer as an owner: a viewer that holds the key (it can read) cannot
//! hand the key to another device, and a device that holds only the vault
//! words cannot make itself an owner (it cannot make the key proof, and no
//! owner lists it). `varsto folder participants <folder>` shows the list.

use super::*;
use crate::record::{self, RecordKind, SignedRecord};
use crate::share::ShareRole;

/// `vault/folder-participants/<folder>/<epoch>/<issuer>/<seq>.json`.
pub const PARTICIPANTS_PREFIX: &str = "vault/folder-participants/";

/// One participant in a published list.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantEntry {
    pub role: ShareRole,
    /// The device's name as the issuer knew it (shown only).
    #[serde(default)]
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ParticipantsBody {
    folder: FolderId,
    epoch: u32,
    seq: u64,
    issuer: DeviceId,
    participants: BTreeMap<DeviceId, ParticipantEntry>,
    /// MAC of the body (with this field empty) under a key derived from the
    /// epoch's folder key.
    #[serde(default)]
    key_proof: String,
}

/// A folder's participants as this device reads them.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderParticipants {
    pub folder: String,
    pub folder_id: String,
    /// The folder key epoch the list is for.
    pub epoch: u32,
    pub participants: Vec<FolderParticipant>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FolderParticipant {
    pub device_id: String,
    pub device: String,
    pub role: ShareRole,
    pub this_device: bool,
}

/// Records found for one folder: epoch -> issuer -> its newest record.
type Found = BTreeMap<u32, BTreeMap<DeviceId, ParticipantsBody>>;

fn storage_key(folder: &FolderId, epoch: u32, issuer: &DeviceId, seq: u64) -> String {
    format!("{PARTICIPANTS_PREFIX}{folder}/{epoch:010}/{issuer}/{seq:020}.json")
}

fn rank(r: ShareRole) -> u8 {
    match r {
        ShareRole::Viewer => 0,
        ShareRole::Editor => 1,
        ShareRole::Owner => 2,
    }
}

fn key_proof(key: &SecretKey, body: &ParticipantsBody) -> Result<String> {
    let mut b = body.clone();
    b.key_proof.clear();
    Ok(hex::encode(crypto::keyed_hash(
        &key.derive("folder-participants", &[body.folder.as_str().as_bytes()]),
        &serde_json::to_vec(&b)?,
    )))
}

/// Resolve one epoch's list from the newest record of each issuer.
/// `strong`: issuers whose records count first; `key`: the epoch's key,
/// when the reader holds it (key proofs are checked with it).
fn resolve_epoch(
    records: &BTreeMap<DeviceId, ParticipantsBody>,
    strong: &BTreeSet<DeviceId>,
    key: Option<&SecretKey>,
) -> Option<BTreeMap<DeviceId, ParticipantEntry>> {
    let mut eff: BTreeMap<DeviceId, ParticipantEntry> = BTreeMap::new();
    let mut fixed: BTreeSet<DeviceId> = BTreeSet::new();
    let accept = |i: &DeviceId,
                  eff: &mut BTreeMap<DeviceId, ParticipantEntry>,
                  fixed: &mut BTreeSet<DeviceId>| {
        let b = &records[i];
        let name = b
            .participants
            .get(i)
            .map(|e| e.name.clone())
            .unwrap_or_default();
        eff.insert(
            i.clone(),
            ParticipantEntry {
                role: ShareRole::Owner,
                name,
            },
        );
        fixed.insert(i.clone());
        for (d, e) in &b.participants {
            if fixed.contains(d) {
                continue;
            }
            match eff.get(d) {
                Some(cur) if rank(cur.role) <= rank(e.role) => {}
                _ => {
                    eff.insert(d.clone(), e.clone());
                }
            }
        }
    };
    let below_owner = |eff: &BTreeMap<DeviceId, ParticipantEntry>, i: &DeviceId| {
        eff.get(i).is_some_and(|e| e.role != ShareRole::Owner)
    };
    // The owners the accepted records name, until nothing changes.
    let spread = |eff: &mut BTreeMap<DeviceId, ParticipantEntry>,
                  fixed: &mut BTreeSet<DeviceId>| loop {
        let next = records.keys().find(|i| {
            !fixed.contains(*i) && eff.get(*i).is_some_and(|e| e.role == ShareRole::Owner)
        });
        match next.cloned() {
            Some(i) => accept(&i, eff, fixed),
            None => break,
        }
    };
    for i in strong {
        if records.contains_key(i) && !fixed.contains(i) && !below_owner(&eff, i) {
            accept(i, &mut eff, &mut fixed);
        }
    }
    spread(&mut eff, &mut fixed);
    if let Some(k) = key {
        loop {
            let next = records.iter().find(|(i, b)| {
                !fixed.contains(*i)
                    && !below_owner(&eff, i)
                    && key_proof(k, b)
                        .is_ok_and(|p| crypto::ct_eq(p.as_bytes(), b.key_proof.as_bytes()))
            });
            match next.map(|(i, _)| i.clone()) {
                Some(i) => {
                    accept(&i, &mut eff, &mut fixed);
                    spread(&mut eff, &mut fixed);
                }
                None => break,
            }
        }
    }
    (!fixed.is_empty()).then_some(eff)
}

impl Engine {
    /// The verified participant records of a folder on the storages.
    fn read_participant_records(
        &self,
        storages: &OpenStorages,
        folder: &FolderId,
    ) -> Result<Found> {
        let prefix = format!("{PARTICIPANTS_PREFIX}{folder}/");
        let mut out: Found = BTreeMap::new();
        let mut tried: BTreeSet<String> = BTreeSet::new();
        let key_for = |id: &str| self.registry_key_for(id);
        for (_, b) in storages {
            for key in b.list(&prefix)? {
                if !tried.insert(key.clone()) {
                    continue;
                }
                let parts: Vec<&str> = key
                    .strip_prefix(&prefix)
                    .and_then(|r| r.strip_suffix(".json"))
                    .unwrap_or_default()
                    .split('/')
                    .collect();
                let [e, who, seq] = parts.as_slice() else {
                    continue;
                };
                let (Ok(e), Ok(who), Ok(seq)) = (
                    e.parse::<u32>(),
                    DeviceId::from_hex(who),
                    seq.parse::<u64>(),
                ) else {
                    continue;
                };
                if !self.trusted(&who)
                    || out
                        .get(&e)
                        .and_then(|m| m.get(&who))
                        .is_some_and(|b| b.seq >= seq)
                {
                    continue;
                }
                let Some(blob) = b.get(&key)? else {
                    continue;
                };
                let Ok(env) = SignedRecord::parse(&blob) else {
                    continue;
                };
                let Ok(plain) = env.accept(
                    &record::Expect::new(RecordKind::FolderRoles, &self.vault.vault_id)
                        .scope(folder.as_str())
                        .device(&who)
                        .seq(seq),
                    &|d: &DeviceId| {
                        (d == &who && self.trusted(d))
                            .then(|| self.device_key(d))
                            .flatten()
                    },
                    &key_for,
                ) else {
                    continue;
                };
                let Ok(body) = serde_json::from_slice::<ParticipantsBody>(&plain) else {
                    continue;
                };
                if &body.folder != folder
                    || body.epoch != e
                    || body.issuer != who
                    || body.seq != seq
                {
                    continue;
                }
                out.entry(e).or_default().insert(who, body);
            }
        }
        Ok(out)
    }

    /// The newest list of a folder's participants: (epoch, list). `extra`:
    /// keys by epoch the reader holds besides its keyring (those of a grant
    /// it is checking).
    fn resolve_participants(
        &self,
        rec: &FolderRecord,
        found: &Found,
        extra: &BTreeMap<u32, SecretKey>,
    ) -> Option<(u32, BTreeMap<DeviceId, ParticipantEntry>)> {
        let mut strong = BTreeSet::from([rec.created_by.clone()]);
        let mut out = None;
        for (e, records) in found {
            let key = extra
                .get(e)
                .cloned()
                .or_else(|| self.share_epoch_key(rec, *e));
            if let Some(eff) = resolve_epoch(records, &strong, key.as_ref()) {
                strong = eff
                    .iter()
                    .filter(|(_, p)| p.role == ShareRole::Owner)
                    .map(|(d, _)| d.clone())
                    .collect();
                out = Some((*e, eff));
            }
        }
        out
    }

    /// Whether the newest participants list (read with the keys of the
    /// grant being checked) names `issuer` as an owner of the folder. A
    /// folder whose owners published no list yet: only its creator.
    pub(super) fn grant_issuer_listed(
        &self,
        storages: &OpenStorages,
        rec: &FolderRecord,
        e: u32,
        issuer: &DeviceId,
        c: &crate::share::GrantContents,
    ) -> Result<bool> {
        let found = self.read_participant_records(storages, &rec.folder_id)?;
        let mut extra = BTreeMap::from([(e, c.key.clone())]);
        if let Some(b) = &c.base {
            extra.insert(0, b.clone());
        }
        for (oe, k) in &c.older {
            if let Ok(k) = SecretKey::from_hex(k) {
                extra.entry(*oe).or_insert(k);
            }
        }
        Ok(match self.resolve_participants(rec, &found, &extra) {
            Some((_, eff)) => eff.get(issuer).is_some_and(|p| p.role == ShareRole::Owner),
            None => issuer == &rec.created_by,
        })
    }

    /// The participants of a folder, as the vault's signed lists say.
    pub fn folder_participants(&self, folder: &str) -> Result<FolderParticipants> {
        let rec = self
            .keyring
            .find(folder)
            .or_else(|| self.keyring.find_backup(folder))
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let storages = self.metadata_storages(false)?;
        let found = self.read_participant_records(&storages, &rec.folder_id)?;
        let (epoch, eff) = self
            .resolve_participants(&rec, &found, &BTreeMap::new())
            .unwrap_or_default();
        Ok(FolderParticipants {
            folder: rec.name.clone(),
            folder_id: rec.folder_id.to_string(),
            epoch,
            participants: eff
                .into_iter()
                .map(|(d, p)| FolderParticipant {
                    device: if self.devices.devices.contains_key(&d) || d == self.vault.device_id {
                        self.device_name(&d)
                    } else {
                        crate::names::display(&p.name).into_owned()
                    },
                    this_device: d == self.vault.device_id,
                    device_id: d.to_string(),
                    role: p.role,
                })
                .collect(),
        })
    }

    /// Owners: make sure the newest list of a folder names this device as
    /// an owner and each of `add` (a device about to get a grant) with a
    /// role: its listed one, else the role given. Publishes a new list when
    /// something is missing.
    pub(super) fn ensure_participants(
        &self,
        rec: &FolderRecord,
        add: &[(DeviceId, ShareRole)],
    ) -> Result<bool> {
        if self.vault.member || rec.is_strongroom() || rec.key_hex.is_empty() {
            return Ok(false);
        }
        let storages = self.metadata_storages(false)?;
        let found = self.read_participant_records(&storages, &rec.folder_id)?;
        let epoch = Self::newest_share_epoch(rec);
        let current = self.resolve_participants(rec, &found, &BTreeMap::new());
        let mut list = match &current {
            Some((_, eff)) => eff.clone(),
            None => BTreeMap::new(),
        };
        let at_epoch = current.as_ref().is_some_and(|(e, _)| *e == epoch);
        let me = self.vault.device_id.clone();
        let mut missing = !at_epoch || list.get(&me).is_none_or(|p| p.role != ShareRole::Owner);
        for (d, role) in add {
            if !self.devices.devices.contains_key(d) && d != &me {
                continue;
            }
            match list.get(d) {
                Some(p) if p.role == *role || *role == ShareRole::Owner => {}
                _ => {
                    list.insert(
                        d.clone(),
                        ParticipantEntry {
                            role: *role,
                            name: self.device_name(d),
                        },
                    );
                    missing = true;
                }
            }
        }
        if !missing {
            return Ok(false);
        }
        // Devices removed from the vault leave the list.
        list.retain(|d, _| self.trusted(d));
        list.insert(
            me.clone(),
            ParticipantEntry {
                role: ShareRole::Owner,
                name: self.vault.device_name.clone(),
            },
        );
        let key = self
            .share_epoch_key(rec, epoch)
            .ok_or_else(|| anyhow!("no key of {} on this device", rec.name))?;
        let last = found
            .get(&epoch)
            .and_then(|m| m.get(&me))
            .map(|b| b.seq)
            .unwrap_or(0);
        let seq = (util::now_utc().max(0) as u64).max(last + 1);
        let mut body = ParticipantsBody {
            folder: rec.folder_id.clone(),
            epoch,
            seq,
            issuer: me.clone(),
            participants: list,
            key_proof: String::new(),
        };
        body.key_proof = key_proof(&key, &body)?;
        let (key_id, reg) = self.registry_key_id_now();
        let env = record::Header {
            kind: RecordKind::FolderRoles,
            vault: &self.vault.vault_id,
            scope: rec.folder_id.as_str(),
            device: &me,
            seq,
            key_id: &key_id,
        }
        .seal(&reg, &serde_json::to_vec(&body)?, &self.keys.signer)?;
        let path = storage_key(&rec.folder_id, epoch, &me, seq);
        let own_prefix = format!("{PARTICIPANTS_PREFIX}{}/{epoch:010}/{me}/", rec.folder_id);
        let mut written = 0;
        for (_, b) in self.metadata_storages(true)? {
            if b.put_if_absent(&path, &env.to_bytes())? {
                written += 1;
            }
            // This device's older lists of the same epoch are superseded.
            for old in b.list(&own_prefix)? {
                if old != path {
                    b.delete(&old)?;
                }
            }
        }
        if written == 0 {
            bail!("no storage to publish the folder's participants to");
        }
        Ok(true)
    }

    /// Every sync, on owner devices: publish the participants of each folder
    /// this device may grant when the newest list does not name it yet (a
    /// new folder, a new epoch, a device that came back with the recovery
    /// words).
    pub(super) fn keep_participants(&self) -> Result<bool> {
        if self.vault.member || self.removal.is_some() {
            return Ok(false);
        }
        let mut wrote = false;
        let recs: Vec<FolderRecord> = self
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed() && self.may_grant(r))
            .cloned()
            .collect();
        for rec in recs {
            match self.ensure_participants(&rec, &[]) {
                Ok(w) => wrote |= w,
                Err(e) => {
                    log::warn!(folder:% = rec.folder_id, error:% = e; "could not publish the folder's participants")
                }
            }
        }
        Ok(wrote)
    }

    /// Tests: what a modified client could publish: a participants list of
    /// `folder` at `epoch` signed by this device, with a key proof under
    /// `key` (a key it holds, or a guess).
    #[doc(hidden)]
    pub fn forge_participants_for_tests(
        &self,
        folder: &FolderId,
        epoch: u32,
        key: &SecretKey,
        list: &[(DeviceId, ShareRole)],
    ) -> Result<()> {
        let me = self.vault.device_id.clone();
        let seq = util::now_utc().max(0) as u64 + 1_000_000;
        let mut body = ParticipantsBody {
            folder: folder.clone(),
            epoch,
            seq,
            issuer: me.clone(),
            participants: list
                .iter()
                .map(|(d, r)| {
                    (
                        d.clone(),
                        ParticipantEntry {
                            role: *r,
                            name: String::new(),
                        },
                    )
                })
                .collect(),
            key_proof: String::new(),
        };
        body.key_proof = key_proof(key, &body)?;
        let (key_id, reg) = self.registry_key_id_now();
        let env = record::Header {
            kind: RecordKind::FolderRoles,
            vault: &self.vault.vault_id,
            scope: folder.as_str(),
            device: &me,
            seq,
            key_id: &key_id,
        }
        .seal(&reg, &serde_json::to_vec(&body)?, &self.keys.signer)?;
        for (_, b) in self.metadata_storages(true)? {
            b.put_if_absent(&storage_key(folder, epoch, &me, seq), &env.to_bytes())?;
        }
        Ok(())
    }

    /// Tests: what a modified client holding a folder's key as a viewer
    /// could do: seal the key to `to` although it may not grant.
    #[doc(hidden)]
    pub fn grant_regardless_for_tests(&mut self, folder: &str, to: &DeviceId) -> Result<()> {
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let storages = self.metadata_storages(false)?;
        let ek = self
            .device_kem_key(&storages, to)?
            .ok_or_else(|| anyhow!("no key-exchange key of {to}"))?;
        self.write_grant(&rec, to, &ek)?;
        Ok(())
    }

    /// The newest epoch's key of a folder this device holds (tests).
    #[doc(hidden)]
    pub fn folder_epoch_key_for_tests(&self, folder: &str) -> Option<(FolderId, u32, SecretKey)> {
        let rec = self.keyring.find(folder)?;
        let e = Self::newest_share_epoch(rec);
        Some((rec.folder_id.clone(), e, self.share_epoch_key(rec, e)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(issuer: &DeviceId, list: &[(&DeviceId, ShareRole)]) -> ParticipantsBody {
        ParticipantsBody {
            folder: FolderId::from_bytes(&[1; 16]),
            epoch: 0,
            seq: 1,
            issuer: issuer.clone(),
            participants: list
                .iter()
                .map(|(d, r)| {
                    (
                        (*d).clone(),
                        ParticipantEntry {
                            role: *r,
                            name: String::new(),
                        },
                    )
                })
                .collect(),
            key_proof: String::new(),
        }
    }

    #[test]
    fn owners_spread_viewers_stay_viewers_and_strangers_need_the_key() {
        let a = DeviceId::from_bytes(&[0xa; 16]);
        let b = DeviceId::from_bytes(&[0xb; 16]);
        let v = DeviceId::from_bytes(&[0xc; 16]);
        let x = DeviceId::from_bytes(&[0xd; 16]);
        let key = SecretKey::random();
        let mut records = BTreeMap::new();
        // The creator lists b as an owner and v as a viewer.
        records.insert(
            a.clone(),
            body(
                &a,
                &[
                    (&a, ShareRole::Owner),
                    (&b, ShareRole::Owner),
                    (&v, ShareRole::Viewer),
                ],
            ),
        );
        records.insert(
            b.clone(),
            body(&b, &[(&b, ShareRole::Owner), (&a, ShareRole::Viewer)]),
        );
        // The viewer makes itself an owner, with a valid key proof.
        let mut vb = body(&v, &[(&v, ShareRole::Owner), (&a, ShareRole::Viewer)]);
        vb.key_proof = key_proof(&key, &vb).unwrap();
        records.insert(v.clone(), vb);
        // A device without the key lists itself.
        records.insert(x.clone(), body(&x, &[(&x, ShareRole::Owner)]));
        let strong = BTreeSet::from([a.clone()]);
        let eff = resolve_epoch(&records, &strong, Some(&key)).unwrap();
        assert_eq!(
            eff[&a].role,
            ShareRole::Owner,
            "b cannot demote the creator"
        );
        assert_eq!(eff[&b].role, ShareRole::Owner);
        assert_eq!(
            eff[&v].role,
            ShareRole::Viewer,
            "a viewer cannot promote itself"
        );
        assert!(
            !eff.contains_key(&x),
            "no key proof, not listed by an owner"
        );
        // A device the owners do not list, with the key (it came back with
        // the recovery words), counts.
        let mut rb = body(&x, &[(&x, ShareRole::Owner)]);
        rb.key_proof = key_proof(&key, &rb).unwrap();
        records.insert(x.clone(), rb);
        let eff = resolve_epoch(&records, &strong, Some(&key)).unwrap();
        assert_eq!(eff[&x].role, ShareRole::Owner);
        // Without the key, only the chain from the creator counts.
        let eff = resolve_epoch(&records, &strong, None).unwrap();
        assert!(!eff.contains_key(&x));
        // A proof under another key does not count.
        let eff = resolve_epoch(&records, &strong, Some(&SecretKey::random())).unwrap();
        assert!(!eff.contains_key(&x));
        // No accepted record: no list.
        assert!(resolve_epoch(&records, &BTreeSet::new(), None).is_none());
    }
}
