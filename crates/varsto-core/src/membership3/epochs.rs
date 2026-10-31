// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Folder epochs, vault epochs and revocations as signed records (format 3
//! design, sections 1, 5 and 6; format 2's section 21 and 58 rules).
//!
//! - **Folder epochs** (`share-epoch`, `vault/folder-epochs/<folder>/
//!   <epoch>`, put-if-absent at the number, key_id `meta:<folder>@<e>` of
//!   the NEW epoch): the issuer, the participants that stay (with their
//!   roles) and the removed devices with their ledger cut-off. One sequence
//!   0, 1, 2, ... per folder serves removals of own devices and of members
//!   alike; epoch 0 has no record.
//! - **Vault epochs** (`epoch`, `vault/epochs/<epoch>`, key_id `epoch@<e>`
//!   = derive(K3ₑ, "epoch-record")): the previous epoch and its K3, the
//!   full devices that stay and the removed ones. The chain of records
//!   leads from any vault key down to K3₀.
//! - **Revocations** (`revocation`, `vault/revocations/<device>/<issuer>/`,
//!   scope = the removed device, key_id `registry@0` so the removed device
//!   reads it too).
//! - **Two epochs under one number** (section 58): signed records of two
//!   issuers (or two different records) under one number are both
//!   recorded and neither is applied until the user keeps one.

use super::folders::Participant;
use super::keys::VaultKeys;
use super::{Role, VAULT_SCOPE};
use crate::crypto::SecretKey;
use crate::record::envelope::decode_body;
use crate::record::{Id16, Kind, RecordBody, RecordKeys, RecordMeta, SignedRecord, StreamRef};
use crate::storage::Storage;
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroize;

/// A device removed in a folder epoch, with the newest ledger batch of it
/// that stays valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Removed {
    pub device: Id16,
    pub cutoff: u64,
}

/// The body of a folder epoch record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderEpochRecord {
    pub folder: Id16,
    pub epoch: u32,
    pub issuer: Id16,
    /// Who stays, with the role each keeps.
    pub participants: Vec<Participant>,
    pub removed: Vec<Removed>,
}

impl RecordBody for FolderEpochRecord {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if self.folder != meta.scope || meta.scope == VAULT_SCOPE {
            return Err("folder differs from the record's scope".into());
        }
        if u64::from(self.epoch) != meta.seq || self.epoch == 0 {
            return Err("epoch differs from the record's number".into());
        }
        if self.issuer != meta.device {
            return Err("issuer is not the writer".into());
        }
        if self.participants.len() > super::MAX_PARTICIPANTS
            || self.removed.len() > super::MAX_PARTICIPANTS
        {
            return Err("too many entries".into());
        }
        if self
            .removed
            .iter()
            .any(|r| self.participants.iter().any(|p| p.device == r.device))
        {
            return Err("a device both stays and is removed".into());
        }
        Ok(())
    }
}

impl FolderEpochRecord {
    pub fn stream(folder: Id16, issuer: Id16) -> StreamRef {
        StreamRef::new(Kind::ShareEpoch, folder, issuer)
    }
}

/// What this device knows of one folder's epochs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FolderEpochs {
    /// Epoch records in force, 1..=current without gaps.
    pub applied: BTreeMap<u32, FolderEpochRecord>,
    /// Issuers of signed records found under each number (by owners).
    pub seen: BTreeMap<u32, BTreeSet<Id16>>,
    /// Numbers with two records and no choice made: neither is applied,
    /// and nothing above them.
    pub forks: BTreeMap<u32, BTreeSet<Id16>>,
    /// The issuer the user kept for a number (`resolve`, WP8b's command).
    pub kept: BTreeMap<u32, Id16>,
}

impl FolderEpochs {
    /// The epoch new records of the folder are written under.
    pub fn current(&self) -> u32 {
        self.applied.keys().next_back().copied().unwrap_or(0)
    }

    /// The highest number any owner wrote a record under (it may not open
    /// here: this device was removed, or has no grant yet).
    pub fn newest_seen(&self) -> u32 {
        self.seen.keys().next_back().copied().unwrap_or(0)
    }

    pub fn unresolved(&self) -> Vec<u32> {
        self.forks.keys().copied().collect()
    }

    /// Whether an applied record at or below `epoch` removed `device` (and
    /// no later one up to `epoch` kept it).
    pub fn removed_at(&self, device: &Id16, epoch: u32) -> bool {
        for (_, r) in self.applied.range(..=epoch).rev() {
            if r.removed.iter().any(|x| x.device == *device) {
                return true;
            }
            if r.participants.iter().any(|p| p.device == *device) {
                return false;
            }
        }
        false
    }

    /// The role `device` kept at the start of `epoch` (from the newest
    /// applied record at or below it that names the device).
    pub fn role_kept(&self, device: &Id16, epoch: u32) -> Option<Role> {
        self.applied.range(..=epoch).rev().find_map(|(_, r)| {
            r.participants
                .iter()
                .find(|p| p.device == *device)
                .map(|p| p.role)
        })
    }

    /// Keep `issuer`'s record of `epoch` (the data side of `varsto folder
    /// resolve-epoch`, WP8b). The caller stores `kept` and passes it back
    /// on the next load.
    pub fn resolve(&mut self, epoch: u32, issuer: Id16) -> Result<()> {
        let Some(found) = self.forks.get(&epoch) else {
            bail!("folder epoch {epoch} has no second record to choose from");
        };
        if !found.contains(&issuer) {
            bail!("no record of folder epoch {epoch} was written by that device");
        }
        self.kept.insert(epoch, issuer);
        Ok(())
    }
}

/// The body of a vault epoch record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEpochRecord {
    pub epoch: u32,
    pub issuer: Id16,
    pub previous_epoch: u32,
    /// K3 of `previous_epoch`: the chain down to K3₀.
    pub previous_k3: [u8; 32],
    /// Full devices that stay (they get vault grants).
    pub members: Vec<Id16>,
    pub revoked: Vec<Id16>,
}

crate::redacted_debug!(VaultEpochRecord { epoch, issuer, previous_epoch, members, revoked ; previous_k3 });

impl Drop for VaultEpochRecord {
    fn drop(&mut self) {
        self.previous_k3.zeroize();
    }
}

impl RecordBody for VaultEpochRecord {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if meta.scope != VAULT_SCOPE {
            return Err("a vault epoch is vault-wide".into());
        }
        if u64::from(self.epoch) != meta.seq || self.epoch == 0 {
            return Err("epoch differs from the record's number".into());
        }
        if self.previous_epoch >= self.epoch {
            return Err("the previous epoch is not below this one".into());
        }
        if self.issuer != meta.device {
            return Err("issuer is not the writer".into());
        }
        if self.members.len() > super::MAX_PARTICIPANTS
            || self.revoked.len() > super::MAX_PARTICIPANTS
        {
            return Err("too many entries".into());
        }
        Ok(())
    }
}

/// One registry stream of a removed device (`folder`, `grant` or `escrow`):
/// records with a higher seq than `seq` do not count. A stream that is not
/// listed had nothing at removal, so none of its records count. Lamport
/// stamps can be backdated; the seq of a stream cannot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamCut {
    pub kind: u8,
    pub scope: Id16,
    pub epoch: u32,
    pub recipient: Id16,
    /// Highest seq of this stream that still counts.
    pub seq: u64,
}

/// The body of a revocation.
///
/// `registry_cuts` is serialized after the fields a revocation always had.
/// Decoding reads those first and takes the cut-off from whatever bytes
/// remain, so a revocation written before the field still opens (`None`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevocationRecord {
    pub device: Id16,
    pub name: String,
    pub issuer: Id16,
    /// Highest ledger batch of the removed device that stays valid.
    pub cutoff_seq: u64,
    pub wipe: bool,
    /// The vault epoch this revocation started (it backs the revocation).
    pub new_epoch: u32,
    /// Per-stream sequence cut-off of the removed device's `folder`,
    /// `grant` and `escrow` records (spec 77.20: after removal those
    /// records do not count). `None` on a revocation written before the
    /// field existed.
    pub registry_cuts: Option<Vec<StreamCut>>,
}

#[derive(Deserialize)]
struct RevocationHead {
    device: Id16,
    name: String,
    issuer: Id16,
    cutoff_seq: u64,
    wipe: bool,
    new_epoch: u32,
}

impl<'de> Deserialize<'de> for RevocationRecord {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let h = RevocationHead::deserialize(deserializer)?;
        Ok(RevocationRecord {
            device: h.device,
            name: h.name,
            issuer: h.issuer,
            cutoff_seq: h.cutoff_seq,
            wipe: h.wipe,
            new_epoch: h.new_epoch,
            registry_cuts: None,
        })
    }
}

impl RecordBody for RevocationRecord {
    fn take_tail(&mut self, tail: &[u8]) -> Result<(), String> {
        if tail.is_empty() {
            return Ok(());
        }
        let (cuts, rest): (Option<Vec<StreamCut>>, &[u8]) =
            postcard::take_from_bytes(tail).map_err(|e| e.to_string())?;
        if !rest.is_empty() {
            return Err(format!("{} bytes after the body", rest.len()));
        }
        self.registry_cuts = cuts;
        Ok(())
    }

    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if self.device != meta.scope || self.issuer != meta.device {
            return Err("device or issuer differ from the record's name".into());
        }
        if self.new_epoch == 0 || self.name.len() > super::MAX_NAME {
            return Err("invalid revocation".into());
        }
        Ok(())
    }
}

impl RevocationRecord {
    pub fn stream(device: Id16, issuer: Id16) -> StreamRef {
        StreamRef::new(Kind::Revocation, device, issuer)
    }
}

/// What `Membership::remove_device` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovalReport {
    pub vault_epoch: u32,
    /// Devices the new vault key was granted to.
    pub vault_keys_sent_to: Vec<Id16>,
    /// Folder epochs started: (folder, epoch).
    pub folder_epochs: Vec<(Id16, u32)>,
    /// Folders the device held that this device cannot rotate (it is not
    /// an owner there or holds no key of it).
    pub folders_not_rotated: Vec<Id16>,
}

/// One vault epoch record opened with its key, envelope included (its
/// signature is checked once the device registry is known).
pub(crate) struct OpenedEpoch {
    pub record: VaultEpochRecord,
    pub envelope: Vec<SignedRecord>,
}

/// Open the record of vault epoch `epoch` with `k3` from the first storage
/// where it opens: envelope parsed, every part's hash checked, body opened
/// with `epoch@<e>`. The signature is not checked here (the issuer's
/// device record may be under an older registry key not held yet).
fn open_vault_epoch(
    storages: &[&dyn Storage],
    vault: Id16,
    epoch: u32,
    k3: &SecretKey,
) -> Option<OpenedEpoch> {
    let keys = VaultKeys {
        keys: BTreeMap::from([(epoch, k3.clone())]),
    };
    let ring = super::keys::KeyRing::vault_only([0u8; 16], &keys);
    for s in storages {
        let stream = StreamRef::new(Kind::Epoch, VAULT_SCOPE, [0u8; 16]);
        let prefix = stream.prefix()?;
        let Ok(names) = s.list(&prefix) else { continue };
        let mut envs = Vec::new();
        for name in names {
            let Some(n) = crate::record::RecordName::parse_as(Kind::Epoch, &name) else {
                continue;
            };
            if n.seq != u64::from(epoch) {
                continue;
            }
            if let Ok(Some(b)) = s.get_bounded(&name, crate::record::MAX_PART_READ) {
                if let Ok(e) = SignedRecord::decode(&b) {
                    envs.push(e);
                }
            }
        }
        envs.sort_by_key(|e| e.part);
        let Some(e0) = envs.first() else { continue };
        if envs.len() != usize::from(e0.parts)
            || envs.iter().enumerate().any(|(i, e)| {
                usize::from(e.part) != i
                    || e.device != e0.device
                    || e.vault != vault
                    || e.body.is_empty()
                    || crate::crypto::hash(&e.body) != e.body_hash
            })
        {
            continue;
        }
        let mut compressed = Vec::new();
        let mut ok = true;
        for e in &envs {
            match e.open_part(&ring as &dyn RecordKeys) {
                Ok(p) => compressed.extend_from_slice(&p),
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            continue;
        }
        let Ok(record) = decode_body::<VaultEpochRecord>(&compressed) else {
            continue;
        };
        if record.epoch != epoch || record.issuer != e0.device || record.previous_epoch >= epoch {
            continue;
        }
        return Some(OpenedEpoch {
            record,
            envelope: envs,
        });
    }
    None
}

/// From the key of vault epoch `top`, follow the epoch records down to
/// epoch 0: every K3 on the way (K3₀ included) and the opened records.
/// This is how K3₀, which the escrow key binds, is reached from a newer
/// vault key (the recovery kit prints the newest one).
pub(crate) fn walk_vault_chain(
    storages: &[&dyn Storage],
    vault: Id16,
    top: u32,
    k3_top: SecretKey,
) -> Result<(VaultKeys, Vec<OpenedEpoch>)> {
    let mut keys = BTreeMap::new();
    let mut opened = Vec::new();
    let mut e = top;
    let mut k = k3_top;
    while e > 0 {
        let o = open_vault_epoch(storages, vault, e, &k).ok_or_else(|| {
            anyhow!("the record of vault epoch {e} is missing or does not open with its key")
        })?;
        keys.insert(e, k);
        k = SecretKey(o.record.previous_k3);
        e = o.record.previous_epoch;
        opened.push(o);
    }
    keys.insert(0, k);
    Ok((VaultKeys { keys }, opened))
}

/// The highest epoch number any object under `prefix` is named with (0:
/// none). A seq that does not fit in an epoch, or that has no successor
/// (`u32::MAX`), is skipped: a name of sixteen 9s is a valid record name
/// and must not become the next number.
pub(crate) fn highest_listed(storages: &[&dyn Storage], prefix: &str, kind: Kind) -> Result<u32> {
    let mut top = 0u32;
    for s in storages {
        for name in s.list(prefix)? {
            let Some(n) = crate::record::RecordName::parse_as(kind, &name) else {
                continue;
            };
            let Ok(e) = u32::try_from(n.seq) else {
                continue;
            };
            if e < u32::MAX {
                top = top.max(e);
            }
        }
    }
    Ok(top)
}

/// The highest vault epoch number any object on the storages is named
/// with (0: none).
pub(crate) fn highest_number(storages: &[&dyn Storage]) -> Result<u32> {
    highest_listed(storages, "vault/epochs/", Kind::Epoch)
}

/// The vault epoch a vault key belongs to: the highest number on the
/// storages whose record opens with it (0 when none does, which is right
/// for K3₀ of a vault that never rotated, and wrong otherwise: the chain
/// walk then fails at the first newer record the caller expects).
pub(crate) fn epoch_of_key(storages: &[&dyn Storage], vault: Id16, k3: &SecretKey) -> Result<u32> {
    let mut numbers = BTreeSet::new();
    for s in storages {
        for name in s.list("vault/epochs/")? {
            if let Some(n) = crate::record::RecordName::parse_as(Kind::Epoch, &name) {
                if let Ok(e) = u32::try_from(n.seq) {
                    numbers.insert(e);
                }
            }
        }
    }
    for e in numbers.into_iter().rev() {
        if open_vault_epoch(storages, vault, e, k3).is_some() {
            return Ok(e);
        }
    }
    Ok(0)
}
