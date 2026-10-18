// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `folder` records (format 3 design, section 6): `vault/folders/<folder>/
//! <device>/`, key_id `registry@<e>`. Name, settings, participants with
//! roles and denied devices; never key material, so a device that holds K3
//! alone sees names, settings and who takes part, and opens no content.
//!
//! The creator's first record (the one with `creation`) makes it the owner;
//! later entries count only when their writer was an owner just before the
//! entry's stamp. Participants and denied entries merge per device by the
//! largest (Lamport, device) stamp, so two owners editing at once converge.

use super::epochs::FolderEpochs;
use super::{store, Role, Stamp, MAX_NAME, MAX_PARTICIPANTS};
use crate::crypto;
use crate::record::{
    Id16, Kind, Record, RecordBody, RecordKeys, RecordMeta, RecordTrust, RecordsRefused, StreamRef,
};
use crate::storage::Storage;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The folder id a creator's nonce gives: BLAKE3("varsto folder id 3" ||
/// creator || nonce)[..16]. Binding the creator into the id lets exactly
/// one device make the first record of a folder.
pub fn folder_id(creator: &Id16, nonce: &[u8; 16]) -> Id16 {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(b"varsto folder id 3");
    b.extend_from_slice(creator);
    b.extend_from_slice(nonce);
    let mut id = [0u8; 16];
    id.copy_from_slice(&crypto::hash(&b)[..16]);
    id
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Participant {
    pub device: Id16,
    pub role: Role,
    pub stamp: Stamp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Denied {
    pub device: Id16,
    pub stamp: Stamp,
}

/// A member device of another person's vault, as an owner lists it: the
/// keys of its request code (section 6, "Other people's devices ask out of
/// band with the `vsr1` request code"), so every device of this vault can
/// check what the member writes and seal grants to it. The role is a
/// participant entry like any other.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MemberKeys {
    pub device: Id16,
    pub name: String,
    /// K6 public key; BLAKE3 of it gives `device`.
    pub k6: Vec<u8>,
    /// K8 public key.
    pub k8: Vec<u8>,
    pub stamp: Stamp,
}

/// The body of a `folder` record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderRecord {
    pub id: Id16,
    pub name: String,
    /// Folder settings by name (trash and history days, kind, ...), as
    /// the engine defines them; opaque here.
    pub settings: BTreeMap<String, String>,
    /// Stamp of `name` and `settings`.
    pub stamp: Stamp,
    /// The creator's nonce, in its first record only: `folder_id(writer,
    /// nonce)` must be `id`.
    pub creation: Option<[u8; 16]>,
    pub participants: Vec<Participant>,
    pub denied: Vec<Denied>,
    /// Member devices (other people's) this record lists.
    pub members: Vec<MemberKeys>,
    /// The folder is removed from the vault from this stamp on (every
    /// device stops syncing it; files stay on disk). Counts from an owner,
    /// like every entry, and is final: adding the folder again makes a new
    /// folder.
    pub removed: Option<Stamp>,
}

impl RecordBody for FolderRecord {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if self.id != meta.scope {
            return Err("folder id differs from the record's scope".into());
        }
        if self.name.len() > MAX_NAME {
            return Err("folder name longer than 128 bytes".into());
        }
        if self.participants.len() > MAX_PARTICIPANTS
            || self.denied.len() > MAX_PARTICIPANTS
            || self.members.len() > MAX_PARTICIPANTS
        {
            return Err("too many entries".into());
        }
        if self.settings.len() > 1024
            || self
                .settings
                .iter()
                .any(|(k, v)| k.len() > MAX_NAME || v.len() > 4096)
        {
            return Err("settings too large".into());
        }
        let mine = |s: &Stamp| s.device == meta.device;
        if !mine(&self.stamp)
            || self.removed.as_ref().is_some_and(|s| !mine(s))
            || !self.participants.iter().all(|p| mine(&p.stamp))
            || !self.denied.iter().all(|d| mine(&d.stamp))
            || !self.members.iter().all(|m| mine(&m.stamp))
        {
            return Err("an entry carries another device's stamp".into());
        }
        for m in &self.members {
            if m.name.len() > MAX_NAME || m.k6.len() > 4096 || m.k8.len() > 4096 {
                return Err("a member entry is too large".into());
            }
            if crate::crypto::hash(&m.k6)[..16] != m.device {
                return Err("a member's keys do not give its device id".into());
            }
        }
        if let Some(nonce) = &self.creation {
            if folder_id(&meta.device, nonce) != self.id {
                return Err("the creation nonce does not give the folder id".into());
            }
            if !self
                .participants
                .iter()
                .any(|p| p.device == meta.device && p.role == Role::Owner)
            {
                return Err("the creator does not list itself as owner".into());
            }
        }
        Ok(())
    }
}

/// One folder as the accepted records describe it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderState {
    pub id: Id16,
    pub name: String,
    pub settings: BTreeMap<String, String>,
    pub creator: Id16,
    /// Per device: its role, or `None` when denied (or removed), with the
    /// stamp of the entry that decided.
    pub entries: BTreeMap<Id16, (Option<Role>, Stamp)>,
    /// Entries from writers that were not owners at their stamp.
    pub entries_refused: u64,
    /// The largest Lamport time of any accepted entry.
    pub max_lamport: u64,
    /// Per device, every accepted change of its role in stamp order (the
    /// creator's first entry has the zero stamp): what its role was at a
    /// given Lamport time (`role_at`).
    pub history: BTreeMap<Id16, Vec<(Stamp, Option<Role>)>>,
    /// Member devices (other people's) the owners listed, newest entry
    /// per device.
    pub members: BTreeMap<Id16, MemberKeys>,
    /// The oldest accepted removal of the folder (an owner's record with
    /// `removed`): the folder is gone from then on.
    pub removed: Option<Stamp>,
}

/// Ordered so that the replay is the same in any reading order, even for
/// entries of one writer under one stamp.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Entry {
    Name(String, BTreeMap<String, String>),
    Set(Id16, Option<Role>),
    Member(MemberKeys),
    Removed,
}

impl FolderState {
    /// Replay every record of one folder. `None` without a valid creation
    /// record (nothing of the folder counts then).
    pub fn build(records: &[Record<FolderRecord>]) -> Option<FolderState> {
        Self::build_with(records, &std::collections::BTreeSet::new())
    }

    /// `build`, knowing which devices were removed from the vault: a
    /// device that makes itself an owner counts when every owner of the
    /// folder at that stamp was removed (it recovered the folder's keys
    /// from escrow and is the only holder left; `alpha-0-format.md`
    /// section 77.6, "As built").
    pub fn build_with(
        records: &[Record<FolderRecord>],
        revoked: &std::collections::BTreeSet<Id16>,
    ) -> Option<FolderState> {
        let genesis = records
            .iter()
            .filter(|r| r.body.creation.is_some())
            .min_by_key(|r| r.body.stamp)?;
        let creator = genesis.meta.device;
        let mut st = FolderState {
            id: genesis.body.id,
            name: genesis.body.name.clone(),
            settings: genesis.body.settings.clone(),
            creator,
            entries: BTreeMap::from([(creator, (Some(Role::Owner), Stamp::default()))]),
            entries_refused: 0,
            max_lamport: 0,
            history: BTreeMap::from([(creator, vec![(Stamp::default(), Some(Role::Owner))])]),
            members: BTreeMap::new(),
            removed: None,
        };
        let mut all: Vec<(Stamp, Id16, Entry)> = Vec::new();
        for r in records {
            let w = r.meta.device;
            all.push((
                r.body.stamp,
                w,
                Entry::Name(r.body.name.clone(), r.body.settings.clone()),
            ));
            for p in &r.body.participants {
                all.push((p.stamp, w, Entry::Set(p.device, Some(p.role))));
            }
            for d in &r.body.denied {
                all.push((d.stamp, w, Entry::Set(d.device, None)));
            }
            for m in &r.body.members {
                all.push((m.stamp, w, Entry::Member(m.clone())));
            }
            if let Some(stamp) = r.body.removed {
                all.push((stamp, w, Entry::Removed));
            }
        }
        all.sort();
        let mut name_stamp = Stamp::default();
        for (stamp, writer, entry) in all {
            let recovered = matches!(&entry, Entry::Set(d, Some(Role::Owner)) if *d == writer)
                && !revoked.contains(&writer)
                && st.owners().iter().all(|o| revoked.contains(o));
            if st.role(&writer) != Some(Role::Owner) && !recovered {
                st.entries_refused += 1;
                continue;
            }
            st.max_lamport = st.max_lamport.max(stamp.lamport);
            match entry {
                Entry::Name(n, s) => {
                    if stamp >= name_stamp {
                        name_stamp = stamp;
                        st.name = n;
                        st.settings = s;
                    }
                }
                Entry::Set(device, role) => {
                    let newer = st.entries.get(&device).is_none_or(|(_, old)| stamp > *old);
                    if newer {
                        st.entries.insert(device, (role, stamp));
                        st.history.entry(device).or_default().push((stamp, role));
                    }
                }
                Entry::Member(m) => {
                    let newer = st
                        .members
                        .get(&m.device)
                        .is_none_or(|old| stamp > old.stamp);
                    if newer {
                        st.members.insert(m.device, m);
                    }
                }
                Entry::Removed => {
                    if st.removed.is_none_or(|r| stamp < r) {
                        st.removed = Some(stamp);
                    }
                }
            }
        }
        Some(st)
    }

    /// The device's current role (`None`: not a participant, or denied).
    pub fn role(&self, device: &Id16) -> Option<Role> {
        self.entries.get(device).and_then(|(r, _)| *r)
    }

    /// Whether an owner removed the folder from the vault.
    pub fn is_removed(&self) -> bool {
        self.removed.is_some()
    }

    pub fn is_denied(&self, device: &Id16) -> bool {
        matches!(self.entries.get(device), Some((None, _)))
    }

    /// The device's role at Lamport time `lamport`: the newest accepted
    /// entry for it whose stamp is not later (`None`: no role then).
    pub fn role_at(&self, device: &Id16, lamport: u64) -> Option<Role> {
        self.history
            .get(device)?
            .iter()
            .rev()
            .find(|(s, _)| s.lamport <= lamport)
            .and_then(|(_, r)| *r)
    }

    pub fn participants(&self) -> Vec<Participant> {
        self.entries
            .iter()
            .filter_map(|(d, (r, s))| {
                r.map(|role| Participant {
                    device: *d,
                    role,
                    stamp: *s,
                })
            })
            .collect()
    }

    pub fn owners(&self) -> Vec<Id16> {
        self.participants()
            .into_iter()
            .filter(|p| p.role == Role::Owner)
            .map(|p| p.device)
            .collect()
    }
}

/// Every folder of the vault, from every device's folder records, with the
/// folder epochs this device could read.
#[derive(Clone, Debug, Default)]
pub struct FolderRegistry {
    pub folders: BTreeMap<Id16, FolderState>,
    pub epochs: BTreeMap<Id16, FolderEpochs>,
}

impl FolderRegistry {
    /// Read `vault/folders/` on every storage.
    pub fn read(
        storages: &[&dyn Storage],
        vault: Id16,
        keys: &dyn RecordKeys,
        trust: &dyn RecordTrust,
        counter: &mut RecordsRefused,
    ) -> Result<FolderRegistry> {
        Self::read_with(storages, vault, keys, trust, counter, &Default::default())
    }

    /// `read`, knowing the devices removed from the vault (`build_with`).
    pub fn read_with(
        storages: &[&dyn Storage],
        vault: Id16,
        keys: &dyn RecordKeys,
        trust: &dyn RecordTrust,
        counter: &mut RecordsRefused,
        revoked: &std::collections::BTreeSet<Id16>,
    ) -> Result<FolderRegistry> {
        let recs: Vec<Record<FolderRecord>> = store::read_all(
            storages,
            vault,
            Kind::Folder,
            "vault/folders/",
            keys,
            trust,
            counter,
        )?;
        let mut by_folder: BTreeMap<Id16, Vec<Record<FolderRecord>>> = BTreeMap::new();
        for r in recs {
            by_folder.entry(r.meta.scope).or_default().push(r);
        }
        let mut out = FolderRegistry::default();
        for (id, recs) in by_folder {
            if let Some(st) = FolderState::build_with(&recs, revoked) {
                out.folders.insert(id, st);
            }
        }
        Ok(out)
    }

    pub fn get(&self, folder: &Id16) -> Option<&FolderState> {
        self.folders.get(folder)
    }

    /// The role of `device` in `folder` at folder epoch `epoch`: its role
    /// in the folder records, unless an accepted folder epoch record at or
    /// below `epoch` removed it (and no later one up to `epoch` kept it).
    pub fn role(&self, device: &Id16, folder: &Id16, epoch: u32) -> Option<Role> {
        let st = self.folders.get(folder)?;
        let ep = self.epochs.get(folder);
        if ep.is_some_and(|ep| ep.removed_at(device, epoch)) {
            return None;
        }
        if let Some(r) = st.role(device) {
            return Some(r);
        }
        // Removed by a later folder epoch (its `denied` entry came with
        // that epoch): at `epoch` it still took part, with the role it had.
        let later = ep.is_some_and(|ep| {
            ep.applied
                .range(epoch.saturating_add(1)..)
                .any(|(_, r)| r.removed.iter().any(|x| x.device == *device))
        });
        if later {
            return st.history.get(device)?.iter().rev().find_map(|(_, r)| *r);
        }
        None
    }

    /// The role a device's records of `folder` under `epoch` are judged
    /// with: the highest role it held while it took part (so what an
    /// editor wrote before it became a viewer stays). When it wrote is
    /// decided by the ledger: its announcements count only while it was
    /// an owner or editor (`ledger3::scope::FolderRoles`).
    pub fn writer_role(&self, device: &Id16, folder: &Id16, epoch: u32) -> Option<Role> {
        let now = self.role(device, folder, epoch)?;
        let best = self
            .folders
            .get(folder)
            .and_then(|st| st.history.get(device))
            .and_then(|h| h.iter().filter_map(|(_, r)| *r).min());
        Some(best.map_or(now, |b| b.min(now)))
    }

    pub fn is_owner(&self, device: &Id16, folder: &Id16, epoch: u32) -> bool {
        self.role(device, folder, epoch) == Some(Role::Owner)
    }

    /// The role of `device` in `folder` at Lamport time `lamport`, for
    /// ledger events: `None` when this registry does not know the folder
    /// (no judgement), `Some(None)` when the device had no role then.
    pub fn role_at(&self, device: &Id16, folder: &Id16, lamport: u64) -> Option<Option<Role>> {
        Some(self.folders.get(folder)?.role_at(device, lamport))
    }

    /// The stream of `device`'s folder records of `folder`.
    pub fn stream(folder: Id16, device: Id16) -> StreamRef {
        StreamRef::new(Kind::Folder, folder, device)
    }
}

/// Which full devices may make folder events in the ledger (section 9):
/// owners and editors at the batch's Lamport time.
impl crate::ledger3::scope::FolderRoles for FolderRegistry {
    fn writes_at(&self, device: &Id16, folder: &Id16, lamport: u64) -> Option<bool> {
        self.role_at(device, folder, lamport)
            .map(|r| matches!(r, Some(Role::Owner | Role::Editor)))
    }
}
