// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A shared folder as a member device of another vault sees it (format 3
//! design, sections 6 and 9; `alpha-0-format.md` section 77.6 "As built").
//!
//! A member holds no vault key: it cannot read the owner's registry (device
//! records, folder records) or the vault ledger. What it reads is what the
//! owners sealed to its K8 or encrypted under the folder's keys:
//!
//! - its **grants** (`vault/grants/<folder>/<epoch>/<me>/<issuer>/`): the
//!   folder keys, and the folder's [`Directory`] (every participant with
//!   its K6 and K8 public keys, its role history and, once removed, its
//!   ledger cut-off). The directory of the grant with the largest stamp
//!   counts;
//! - the **folder epoch records**, under the folder keys it holds.
//!
//! Trust starts from one owner device: the one whose six words the person
//! confirmed when accepting (or, without words, the only issuer that
//! granted the folder to this device then), kept in the member's device
//! directory. A grant counts when its issuer is that device or an owner
//! that an already accepted directory lists with its keys, and when the
//! issuer's signature verifies against the K6 the directory gives
//! (BLAKE3 of it must be the issuer's id). From the directory the member
//! builds the same registries a device of the vault holds
//! ([`DeviceRegistry`] of the owner's devices, a [`FolderRegistry`] of the
//! one folder, a [`MemberRegistry`] of the other members), so that every
//! record of the folder is judged by the same `Trust` and section 9's rows.

use super::devices::{DeviceRecord, DeviceRegistry};
use super::epochs::{FolderEpochRecord, FolderEpochs};
use super::folders::{FolderRegistry, FolderState, MemberKeys};
use super::grants::{k10_of, k11_of, Directory, FolderKeys, GrantRecord, GrantedKeys};
use super::keys::{KeyRing, VaultKeys};
use super::members::{MemberDevice, MemberRegistry};
use super::trust::Trust;
use super::{store, Role, VAULT_SCOPE};
use crate::crypto::{SecretKey, VerifyingKey};
use crate::kem::DecapsKey;
use crate::record::envelope::decode_body;
use crate::record::{
    Acceptor, Id16, KeyId, Kind, Outcome, RecordKeys, RecordName, RecordTrust, RecordsRefused,
    SignedRecord, MAX_PART_READ,
};
use crate::storage::Storage;
use anyhow::{bail, Result};
use std::collections::{BTreeMap, BTreeSet};

/// Trusts one key for the grants of one issuer.
struct Seed {
    issuer: Id16,
    key: VerifyingKey,
}

impl RecordTrust for Seed {
    fn signer_key(&self, device: &Id16, kind: Kind, _: &Id16) -> Option<VerifyingKey> {
        (kind == Kind::Grant && *device == self.issuer).then(|| self.key.clone())
    }
    fn may_write(&self, device: &Id16, kind: Kind, _: &Id16, _: &KeyId) -> bool {
        kind == Kind::Grant && *device == self.issuer
    }
}

/// One grant to this device found on a storage, opened but not trusted yet.
struct Candidate {
    issuer: Id16,
    parts: Vec<(String, Vec<u8>)>,
    body: GrantRecord,
}

/// What a member device knows of its shared folder.
#[derive(Clone, Default)]
pub struct MemberView {
    pub folder: Id16,
    /// The directory with the largest stamp among the accepted grants.
    pub directory: Option<Directory>,
    /// The issuers whose grants counted (owners of the folder).
    pub owners: BTreeSet<Id16>,
    pub granted: GrantedKeys,
    /// The owner's devices, as the directory gives them.
    pub devices: DeviceRegistry,
    /// The one folder, built from the directory, with its epochs.
    pub registry: FolderRegistry,
    /// Other people's devices in the folder (this one among them).
    pub members: MemberRegistry,
    /// Devices removed from the vault or the folder: their newest ledger
    /// batch that counts.
    pub cutoffs: BTreeMap<Id16, u64>,
    /// The role grants give this device (the newest epoch's).
    pub role: Option<Role>,
    /// An owner started a folder epoch whose key no grant gave this
    /// device: it was removed (or nobody granted it yet).
    pub access_lost: bool,
    pub refused: RecordsRefused,
}

impl MemberView {
    /// Every grant to `me` (of `folder`, when given) on the storages,
    /// opened with this device's K8.
    fn candidates(
        storages: &[&dyn Storage],
        vault: Id16,
        me: Id16,
        kem: &DecapsKey,
        folder: Option<Id16>,
    ) -> Result<Vec<Candidate>> {
        let prefix = match folder {
            Some(f) => format!("vault/grants/{}/", hex::encode(f)),
            None => "vault/grants/".to_string(),
        };
        let empty = VaultKeys::default();
        let mut ring = KeyRing::vault_only(me, &empty);
        ring.kem = Some(kem);
        let mut out: Vec<Candidate> = Vec::new();
        let mut seen = BTreeSet::new();
        for s in storages {
            let mut records: BTreeMap<(Id16, u32, Id16, u64), Vec<String>> = BTreeMap::new();
            for name in s.list(&prefix)? {
                let Some(n) = RecordName::parse_as(Kind::Grant, &name) else {
                    continue;
                };
                if n.recipient != Some(me) || n.scope == VAULT_SCOPE {
                    continue;
                }
                let (Some(epoch), Some(issuer)) = (n.epoch, n.device) else {
                    continue;
                };
                records
                    .entry((n.scope, epoch, issuer, n.seq))
                    .or_default()
                    .push(name);
            }
            for ((_, _, issuer, _), mut names) in records {
                names.sort();
                let mut parts = Vec::new();
                for name in &names {
                    if let Some(b) = s.get_bounded(name, MAX_PART_READ)? {
                        parts.push((name.clone(), b));
                    }
                }
                let mut compressed = Vec::new();
                let mut ok = !parts.is_empty();
                for (_, b) in &parts {
                    match SignedRecord::decode(b)
                        .ok()
                        .filter(|e| e.vault == vault && e.device == issuer)
                        .and_then(|e| e.open_part(&ring as &dyn RecordKeys).ok())
                    {
                        Some(p) => compressed.extend_from_slice(&p),
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok {
                    continue;
                }
                let Ok(body) = decode_body::<GrantRecord>(&compressed) else {
                    continue;
                };
                let id = crate::crypto::hash(&compressed);
                if !seen.insert(id) {
                    continue;
                }
                out.push(Candidate {
                    issuer,
                    parts,
                    body,
                });
            }
        }
        Ok(out)
    }

    /// The owner devices that granted this device a folder, with their
    /// six words (the person compares them with what the owner shows), by
    /// folder: what `accept` picks from.
    pub fn issuers(
        storages: &[&dyn Storage],
        vault: Id16,
        me: Id16,
        kem: &DecapsKey,
    ) -> Result<Vec<(Id16, Id16, String, String)>> {
        let mut out = BTreeSet::new();
        for c in Self::candidates(storages, vault, me, kem, None)? {
            let Some(d) = &c.body.directory else { continue };
            let Some(e) = d.get(&c.issuer) else { continue };
            if !e.full || !e.id_matches() {
                continue;
            }
            out.insert((
                c.body.folder,
                c.issuer,
                d.name.clone(),
                super::requests::fingerprint(&e.k6, &e.k8),
            ));
        }
        Ok(out.into_iter().collect())
    }

    /// Read the folder as member `me`, trusting grants that lead back to
    /// the owner device `anchor`.
    pub fn read(
        storages: &[&dyn Storage],
        vault: Id16,
        me: Id16,
        kem: &DecapsKey,
        folder: Id16,
        anchor: Id16,
    ) -> Result<MemberView> {
        let cands = Self::candidates(storages, vault, me, kem, Some(folder))?;
        let empty = VaultKeys::default();
        let mut ring = KeyRing::vault_only(me, &empty);
        ring.kem = Some(kem);
        let mut v = MemberView {
            folder,
            ..MemberView::default()
        };
        let mut trusted: BTreeSet<Id16> = BTreeSet::from([anchor]);
        let mut accepted = vec![false; cands.len()];
        let mut keys: Option<FolderKeys> = None;
        loop {
            let mut changed = false;
            for (i, c) in cands.iter().enumerate() {
                if accepted[i] || !trusted.contains(&c.issuer) || c.body.folder != folder {
                    continue;
                }
                let Some(d) = &c.body.directory else { continue };
                let Some(e) = d.get(&c.issuer) else { continue };
                if !e.full || !e.id_matches() || e.role() != Some(Role::Owner) {
                    continue;
                }
                let Ok(key) = VerifyingKey::from_bytes(&e.k6) else {
                    continue;
                };
                let seed = Seed {
                    issuer: c.issuer,
                    key,
                };
                let acc = Acceptor {
                    vault,
                    keys: &ring,
                    trust: &seed,
                };
                match acc.accept::<GrantRecord>(&c.parts) {
                    Outcome::Accepted(_) => {}
                    Outcome::Refused(r) => {
                        v.refused.note(&r);
                        continue;
                    }
                    Outcome::Waiting(_) => continue,
                }
                let b = &c.body;
                let mut gk = FolderKeys {
                    folder,
                    epochs: BTreeMap::from([(b.epoch, SecretKey(b.k9))]),
                    k11: SecretKey(b.k11),
                };
                for (oe, ok9) in &b.older {
                    gk.epochs.insert(*oe, SecretKey(*ok9));
                }
                if let Some(k0) = gk.epochs.get(&0) {
                    if k11_of(&folder, k0).0 != gk.k11.0 {
                        continue;
                    }
                }
                let fits = match &mut keys {
                    None => {
                        keys = Some(gk);
                        true
                    }
                    Some(have) => have.merge(&gk),
                };
                if !fits {
                    continue;
                }
                accepted[i] = true;
                changed = true;
                v.owners.insert(c.issuer);
                if v
                    .directory
                    .as_ref()
                    .is_none_or(|old| d.stamp > old.stamp)
                {
                    v.directory = Some(d.clone());
                }
                for o in &d.entries {
                    if o.full && o.role() == Some(Role::Owner) && o.id_matches() {
                        trusted.insert(o.device);
                    }
                }
            }
            if !changed {
                break;
            }
        }
        let Some(dir) = v.directory.clone() else {
            bail!("no grant of this folder to this device from the owner it was accepted from");
        };
        // The newest role a grant gave this device.
        v.role = cands
            .iter()
            .zip(&accepted)
            .filter(|(_, a)| **a)
            .max_by_key(|(c, _)| (c.body.epoch, c.body.directory.as_ref().map(|d| d.stamp)))
            .map(|(c, _)| c.body.role);
        if let Some(k) = keys {
            v.granted.add(k);
        }
        v.build(&dir);
        v.read_epochs(storages, vault, me)?;
        Ok(v)
    }

    /// The registries a device of the vault would hold, from the directory.
    fn build(&mut self, dir: &Directory) {
        let folder = self.folder;
        let mut st = FolderState {
            id: folder,
            name: dir.name.clone(),
            settings: BTreeMap::new(),
            creator: dir.creator,
            entries: BTreeMap::new(),
            entries_refused: 0,
            max_lamport: dir.stamp.lamport,
            history: BTreeMap::new(),
            members: BTreeMap::new(),
            removed: None,
        };
        for e in &dir.entries {
            if !e.id_matches() {
                continue;
            }
            let Some((stamp, role)) = e.history.last().copied() else {
                continue;
            };
            st.entries.insert(e.device, (role, stamp));
            st.history.insert(e.device, e.history.clone());
            for (s, _) in &e.history {
                st.max_lamport = st.max_lamport.max(s.lamport);
            }
            if let Some(c) = e.cutoff {
                self.cutoffs.insert(e.device, c);
            }
            if e.full {
                self.devices.insert(
                    DeviceRecord {
                        device: e.device,
                        name: e.name.clone(),
                        sign_pub: e.k6.clone(),
                        kem_pub: e.k8.clone(),
                        stamp,
                        details: None,
                    },
                    0,
                );
            } else {
                st.members.insert(
                    e.device,
                    MemberKeys {
                        device: e.device,
                        name: e.name.clone(),
                        k6: e.k6.clone(),
                        k8: e.k8.clone(),
                        stamp,
                    },
                );
                self.members.insert(MemberDevice {
                    device: e.device,
                    folder,
                    name: e.name.clone(),
                    k6: e.k6.clone(),
                    k8: e.k8.clone(),
                });
            }
        }
        self.registry.folders.insert(folder, st);
    }

    /// The folder epoch records this device holds the keys of, in order.
    fn read_epochs(&mut self, storages: &[&dyn Storage], vault: Id16, me: Id16) -> Result<()> {
        let folder = self.folder;
        let prefix = FolderEpochRecord::stream(folder, [0u8; 16])
            .prefix()
            .unwrap_or_default();
        let devices = &self.devices;
        let envs = store::numbered(storages, vault, Kind::ShareEpoch, &prefix, &|d| {
            devices.signing_key(d)
        })?;
        let mut ep = FolderEpochs::default();
        let empty = VaultKeys::default();
        let none = BTreeSet::new();
        let trust = Trust {
            devices: &self.devices,
            revoked: &none,
            folders: None,
            members: None,
        };
        for (seq, cands) in &envs {
            let Ok(e) = u32::try_from(*seq) else { continue };
            if e == 0 {
                continue;
            }
            let owners: Vec<&store::Numbered> = cands
                .iter()
                .filter(|n| self.owners.contains(&n.device) || self.is_owner(&n.device))
                .collect();
            if owners.is_empty() {
                continue;
            }
            ep.seen.insert(e, owners.iter().map(|n| n.device).collect());
            if e != ep.current() + 1 {
                continue;
            }
            let Some(k9) = self.granted.get(&folder).and_then(|k| k.epochs.get(&e)).cloned() else {
                continue;
            };
            let mut ring = KeyRing::vault_only(me, &empty);
            ring.extra.push((KeyId::Meta { folder, epoch: e }, k10_of(&folder, &k9)));
            let mut found = None;
            for n in &owners {
                if let Some(r) = store::accept_numbered::<FolderEpochRecord>(
                    vault,
                    &ring,
                    &trust,
                    n,
                    &mut self.refused,
                ) {
                    found = Some(r.body);
                    break;
                }
            }
            if let Some(r) = found {
                ep.applied.insert(e, r);
            }
        }
        let newest_key = self
            .granted
            .get(&folder)
            .and_then(|k| k.newest())
            .map(|(e, _)| e)
            .unwrap_or(0);
        self.access_lost = ep.newest_seen() > newest_key;
        self.registry.epochs.insert(folder, ep);
        Ok(())
    }

    fn is_owner(&self, device: &Id16) -> bool {
        self.registry
            .get(&self.folder)
            .and_then(|s| s.role(device))
            == Some(Role::Owner)
    }
}
