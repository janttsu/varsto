// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The user-facing side of format-3 folder membership (design section 6,
//! work package 8b): requests, approval, roles, removal and recovery
//! copies as operations of the engine, so that the command line, the local
//! API and the pages share one implementation. Built behind the `format3`
//! feature.
//!
//! The engine of a format-2 vault stands in for the device keys that
//! format 3 needs until work package 12 flips the format: K6 is the
//! device's signing key, K8 its KEM key (made on first use and kept in
//! `vault-keys.enc` like today), K3 the vault key. Every operation opens a
//! [`Membership`] over the metadata storages, enrols this device in the
//! registry when it is not there yet, and runs one step.
//!
//! Nothing here runs by itself: the background service never calls an
//! operation that approves, denies, grants or removes (a test in
//! `service.rs` checks its source). A person at a command line or a page
//! does, after comparing the six words.

use super::*;
use crate::membership3::escrow::MissingEscrow;
use crate::membership3::{EpochStart, Membership, PendingRequest, RecoveryKey, Removed, Role};
use crate::record::{id16, Id16};
use std::collections::BTreeMap;

/// A request waiting for an owner's answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FolderRequest {
    pub folder_id: String,
    pub folder: String,
    pub device_id: String,
    /// The requesting device's name as its device record says.
    pub device: String,
    pub role_wanted: String,
    /// Six words over the requester's K6 and K8 public keys: the requester
    /// shows the same words.
    pub fingerprint: String,
}

/// One participant of a folder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FolderMember {
    pub device_id: String,
    pub device: String,
    pub role: String,
    pub this_device: bool,
}

/// A folder's participants, denied devices and pending requests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FolderMembers {
    pub folder_id: String,
    pub folder: String,
    /// The folder epoch this device sees as current.
    pub epoch: u32,
    /// This device's role (none: it is not a participant).
    pub your_role: Option<String>,
    pub participants: Vec<FolderMember>,
    /// Devices an owner denied or removed.
    pub denied: Vec<FolderMember>,
    pub pending: Vec<FolderRequest>,
    /// Epoch numbers that two owners started at once (`resolve-epoch`).
    pub unresolved_epochs: Vec<u32>,
}

/// What removing a device from a folder did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FolderRemoval {
    pub folder_id: String,
    pub folder: String,
    pub removed: String,
    /// The folder epoch that was started.
    pub epoch: u32,
    pub granted_to: Vec<String>,
    /// Participants that stay but have no device record here yet.
    pub pending: Vec<String>,
    pub escrowed: bool,
}

/// A folder epoch this device holds with no recovery copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MissingRecoveryCopy {
    pub folder_id: String,
    pub folder: String,
    pub epoch: u32,
    /// The sentence `varsto status` prints.
    pub warning: String,
}

fn role_text(r: Role) -> String {
    r.as_str().to_string()
}

/// `owner`, `editor` or `viewer`.
pub fn parse_role(text: &str) -> Result<Role> {
    match text.trim().to_ascii_lowercase().as_str() {
        "owner" => Ok(Role::Owner),
        "editor" => Ok(Role::Editor),
        "viewer" => Ok(Role::Viewer),
        other => bail!("unknown role \"{other}\": use owner, editor or viewer"),
    }
}

fn request_view(m: &Membership<'_>, r: &PendingRequest) -> FolderRequest {
    FolderRequest {
        folder_id: hex::encode(r.folder),
        folder: m
            .registry
            .get(&r.folder)
            .map(|s| s.name.clone())
            .unwrap_or_default(),
        device_id: hex::encode(r.device),
        device: r.name.clone(),
        role_wanted: role_text(r.role_wanted),
        fingerprint: r.fingerprint.clone(),
    }
}

fn member_view(m: &Membership<'_>, device: &Id16, role: &str) -> FolderMember {
    FolderMember {
        device_id: hex::encode(device),
        device: m.devices.name(device),
        role: role.to_string(),
        this_device: *device == m.me,
    }
}

/// A folder of the registry by name or by (a prefix of) its id.
fn find_folder(m: &Membership<'_>, text: &str) -> Result<Id16> {
    let t = text.trim();
    let by_name: Vec<Id16> = m
        .registry
        .folders
        .values()
        .filter(|s| s.name == t)
        .map(|s| s.id)
        .collect();
    match by_name.as_slice() {
        [one] => return Ok(*one),
        [] => {}
        _ => bail!("several folders are named {t}: give the id (varsto folder members shows it)"),
    }
    if t.len() >= 4 {
        let by_id: Vec<Id16> = m
            .registry
            .folders
            .keys()
            .filter(|id| hex::encode(id).starts_with(&t.to_ascii_lowercase()))
            .copied()
            .collect();
        match by_id.as_slice() {
            [one] => return Ok(*one),
            [] => {}
            _ => bail!("the id prefix {t} fits several folders: give more of it"),
        }
    }
    bail!("no folder {t} in this vault (format 3 folders: varsto folder members <folder>)")
}

/// A device of the registry by name or by (a prefix of) its id.
fn find_device(m: &Membership<'_>, text: &str) -> Result<Id16> {
    let t = text.trim();
    let by_name: Vec<Id16> = m
        .devices
        .devices
        .values()
        .filter(|(d, _)| d.name == t)
        .map(|(d, _)| d.device)
        .collect();
    match by_name.as_slice() {
        [one] => return Ok(*one),
        [] => {}
        _ => bail!("several devices are named {t}: give the id"),
    }
    if t.len() >= 4 {
        let by_id: Vec<Id16> = m
            .devices
            .devices
            .keys()
            .filter(|id| hex::encode(id).starts_with(&t.to_ascii_lowercase()))
            .copied()
            .collect();
        match by_id.as_slice() {
            [one] => return Ok(*one),
            [] => {}
            _ => bail!("the id prefix {t} fits several devices: give more of it"),
        }
    }
    bail!("no device {t} in this vault")
}

impl Engine {
    /// Run `f` over this device's [`Membership`]. With `enrol`, the device
    /// first makes its K8 (when it has none) and publishes its device
    /// record if the registry lacks it; without, a device that never did
    /// that gets `None`.
    fn with_membership3<R>(
        &mut self,
        enrol: bool,
        f: impl FnOnce(&mut Membership<'_>) -> Result<R>,
    ) -> Result<Option<R>> {
        if self.vault.member {
            bail!("this device is a member of a shared folder only; it has no folder membership of its own");
        }
        if enrol {
            return self.with_enrolled3(f);
        }
        Ok(self
            .with_members3(|m| {
                if m.devices.get(&m.me).is_none() {
                    return Ok(None);
                }
                f(m).map(Some)
            })?
            .flatten())
    }

    fn enrolled3<R>(&mut self, f: impl FnOnce(&mut Membership<'_>) -> Result<R>) -> Result<R> {
        self.with_membership3(true, f)?
            .ok_or_else(|| anyhow!("this device could not be enrolled: add a storage first"))
    }

    /// Create a folder in the membership records (this device the owner).
    /// The command line's `folder add` will call this once format 3 is the
    /// format (work package 12); until then it is how a format-3 folder
    /// comes to be. Returns the folder id (hex).
    pub fn f3_folder_create(&mut self, name: &str, k1: Option<&RecoveryKey>) -> Result<String> {
        crate::names::check_display_name(name)?;
        self.enrolled3(|m| {
            if m.registry.folders.values().any(|s| s.name == name) {
                bail!("a folder named {name} exists already");
            }
            let id = m.create_folder(name, BTreeMap::new(), k1)?;
            Ok(hex::encode(id))
        })
    }

    /// Ask the owners for `folder` (name or id), as editor or viewer.
    /// Returns this device's fingerprint: the owner compares it.
    pub fn f3_folder_request(&mut self, folder: &str, role: &str) -> Result<FolderRequest> {
        let role = parse_role(role)?;
        if role == Role::Owner {
            bail!("a request asks for editor or viewer; an owner makes you an owner afterwards");
        }
        self.enrolled3(|m| {
            let id = find_folder(m, folder)?;
            if m.registry.get(&id).and_then(|s| s.role(&m.me)).is_some() {
                bail!("this device is a participant of the folder already");
            }
            m.request_folder(&id, role)?;
            let me = m.devices.get(&m.me).cloned().expect("enrolled");
            Ok(FolderRequest {
                folder_id: hex::encode(id),
                folder: m
                    .registry
                    .get(&id)
                    .map(|s| s.name.clone())
                    .unwrap_or_default(),
                device_id: hex::encode(m.me),
                device: me.name.clone(),
                role_wanted: role_text(role),
                fingerprint: crate::membership3::fingerprint(&me.sign_pub, &me.kem_pub),
            })
        })
    }

    /// This device's own fingerprint: the six words an owner compares.
    pub fn f3_own_fingerprint(&mut self) -> Result<String> {
        self.enrolled3(|m| {
            let me = m.devices.get(&m.me).cloned().expect("enrolled");
            Ok(crate::membership3::fingerprint(&me.sign_pub, &me.kem_pub))
        })
    }

    /// Pending requests for `folder`, or for every folder this device owns.
    pub fn f3_requests(&mut self, folder: Option<&str>) -> Result<Vec<FolderRequest>> {
        let Some(out) = self.with_membership3(false, |m| {
            let ids: Vec<Id16> = match folder {
                Some(f) => vec![find_folder(m, f)?],
                None => m
                    .registry
                    .folders
                    .values()
                    .filter(|s| {
                        let epoch = m.folder_epochs(&s.id).current();
                        m.registry.is_owner(&m.me, &s.id, epoch)
                    })
                    .map(|s| s.id)
                    .collect(),
            };
            let mut out = Vec::new();
            for id in ids {
                for r in m.list_requests(&id)? {
                    out.push(request_view(m, &r));
                }
            }
            Ok(out)
        })?
        else {
            return Ok(Vec::new());
        };
        Ok(out)
    }

    /// Approve `device` for `folder`. The caller has shown the person the
    /// device's name and fingerprint and got a yes; `fingerprint` is the
    /// words they confirmed, and the approval is refused when the request
    /// now carries other words (its keys changed in between).
    pub fn f3_approve(
        &mut self,
        folder: &str,
        device: &str,
        role: Option<&str>,
        fingerprint: Option<&str>,
    ) -> Result<FolderMembers> {
        let role = role.map(parse_role).transpose()?;
        self.enrolled3(|m| {
            let id = find_folder(m, folder)?;
            let dev = find_device(m, device)?;
            let pending = m.list_requests(&id)?;
            let req = pending
                .iter()
                .find(|r| r.device == dev)
                .ok_or_else(|| anyhow!("there is no pending request of that device for the folder"))?;
            if let Some(seen) = fingerprint {
                if !fingerprint_matches(&req.fingerprint, seen) {
                    bail!(
                        "the words you confirmed (\"{seen}\") are not the request's (\"{}\"): the request changed; compare again",
                        req.fingerprint
                    );
                }
            }
            let role = role.unwrap_or(req.role_wanted);
            if role == Role::Owner {
                bail!("a request is approved as editor or viewer; make an owner with `folder role` afterwards");
            }
            m.approve(&id, &dev, role)?;
            members_of(m, &id)
        })
    }

    /// Deny `device` for `folder`.
    pub fn f3_deny(&mut self, folder: &str, device: &str) -> Result<FolderMembers> {
        self.enrolled3(|m| {
            let id = find_folder(m, folder)?;
            let dev = find_device(m, device)?;
            m.deny(&id, &dev)?;
            members_of(m, &id)
        })
    }

    /// Participants, denied devices and pending requests of `folder`.
    pub fn f3_members(&mut self, folder: &str) -> Result<FolderMembers> {
        self.enrolled3(|m| {
            let id = find_folder(m, folder)?;
            members_of(m, &id)
        })
    }

    /// Every folder of the membership records this device can see.
    pub fn f3_folders(&mut self) -> Result<Vec<FolderMembers>> {
        let Some(v) = self.with_membership3(false, |m| {
            let ids: Vec<Id16> = m.registry.folders.keys().copied().collect();
            ids.iter().map(|id| members_of(m, id)).collect()
        })?
        else {
            return Ok(Vec::new());
        };
        Ok(v)
    }

    /// Change `device`'s role in `folder`: a folder record by an owner and
    /// a grant that carries the new role. (A lower role does not take
    /// keys back; removing the device does, with a new folder epoch.)
    pub fn f3_set_role(&mut self, folder: &str, device: &str, role: &str) -> Result<FolderMembers> {
        let role = parse_role(role)?;
        self.enrolled3(|m| {
            let id = find_folder(m, folder)?;
            let dev = find_device(m, device)?;
            let epoch = m.folder_epochs(&id).current();
            if !m.registry.is_owner(&m.me, &id, epoch) {
                bail!("this device is not an owner of the folder");
            }
            let st = m
                .registry
                .get(&id)
                .ok_or_else(|| anyhow!("no such folder"))?;
            if st.role(&dev).is_none() {
                bail!("that device is not a participant of the folder");
            }
            if dev == m.me && role != Role::Owner && st.owners().len() <= 1 {
                bail!("this device is the folder's only owner; make another owner first");
            }
            m.approve(&id, &dev, role)?;
            members_of(m, &id)
        })
    }

    /// Remove `device` from `folder`: starts a new folder epoch that it
    /// never gets, and denies it. What it already read it keeps.
    pub fn f3_remove(
        &mut self,
        folder: &str,
        device: &str,
        k1: Option<&RecoveryKey>,
    ) -> Result<FolderRemoval> {
        // The ledger cut-off is read before the membership borrows the engine.
        let heads: BTreeMap<Id16, u64> = self
            .devices_list()
            .into_iter()
            .filter_map(|d| {
                let dev = DeviceId::from_hex(&d.device_id).ok()?;
                let id = id16(&dev)?;
                Some((id, self.f3.ledger.head(&id).seq))
            })
            .collect();
        self.enrolled3(|m| {
            let id = find_folder(m, folder)?;
            let dev = find_device(m, device)?;
            let started: EpochStart = m.start_folder_epoch(
                &id,
                &[Removed {
                    device: dev,
                    cutoff: heads.get(&dev).copied().unwrap_or(0),
                }],
                k1,
            )?;
            Ok(FolderRemoval {
                folder_id: hex::encode(id),
                folder: m
                    .registry
                    .get(&id)
                    .map(|s| s.name.clone())
                    .unwrap_or_default(),
                removed: m.devices.name(&dev),
                epoch: started.epoch,
                granted_to: started
                    .granted_to
                    .iter()
                    .map(|d| m.devices.name(d))
                    .collect(),
                pending: started.pending.iter().map(hex::encode).collect(),
                escrowed: started.escrowed,
            })
        })
    }

    /// Two owners started the same folder epoch: keep `keep`'s.
    pub fn f3_resolve_epoch(
        &mut self,
        folder: &str,
        epoch: u32,
        keep: &str,
    ) -> Result<FolderMembers> {
        self.enrolled3(|m| {
            let id = find_folder(m, folder)?;
            let issuer = find_device(m, keep)?;
            m.resolve_folder_epoch(&id, epoch, &issuer)?;
            members_of(m, &id)
        })
    }

    /// Folder epochs this device holds with no recovery copy (empty for a
    /// device that never took part in format 3).
    pub fn f3_missing_escrows(&mut self) -> Result<Vec<MissingRecoveryCopy>> {
        let Some(v) = self.with_membership3(false, |m| {
            Ok(m.missing_escrows()?
                .into_iter()
                .map(|e: MissingEscrow| MissingRecoveryCopy {
                    folder_id: hex::encode(e.folder),
                    warning: e.warning(),
                    folder: e.name,
                    epoch: e.epoch,
                })
                .collect::<Vec<_>>())
        })?
        else {
            return Ok(Vec::new());
        };
        Ok(v)
    }

    /// Write the recovery copies that are missing, for `folder` or for
    /// every folder, under the recovery key from the 24 words.
    pub fn f3_write_escrows(
        &mut self,
        folder: Option<&str>,
        k1: &RecoveryKey,
    ) -> Result<Vec<MissingRecoveryCopy>> {
        self.enrolled3(|m| {
            let only = folder.map(|f| find_folder(m, f)).transpose()?;
            let mut written = Vec::new();
            for e in m.missing_escrows()? {
                if only.is_some_and(|f| f != e.folder) {
                    continue;
                }
                m.escrow_folder_epoch(&e.folder, e.epoch, k1)?;
                written.push(MissingRecoveryCopy {
                    folder_id: hex::encode(e.folder),
                    warning: e.warning(),
                    folder: e.name,
                    epoch: e.epoch,
                });
            }
            Ok(written)
        })
    }

    /// The printable kit with both word sets: the newest vault key and the
    /// recovery key.
    pub fn f3_kit_text(&self, k1: &RecoveryKey) -> Result<String> {
        let vault = id16(&self.vault.vault_id)
            .ok_or_else(|| anyhow!("the vault id is not 16 bytes of hex"))?;
        let (epoch, k3) = self
            .epochs
            .keys
            .iter()
            .next_back()
            .map(|(e, k)| (*e, k.clone()))
            .ok_or_else(|| anyhow!("no vault key"))?;
        crate::membership3::escrow::kit_text(&vault, epoch, &k3, k1)
    }

    /// Pairing (the offering device, after the person ticked folders for
    /// the joining device): grants as an editor for every folder in
    /// `folders` (names or ids). Returns the joining device's id.
    pub fn f3_pair_grants(
        &mut self,
        name: &str,
        k6_public: &[u8],
        k8_public: &[u8],
        folders: &[String],
        role: &str,
    ) -> Result<String> {
        let role = parse_role(role)?;
        self.enrolled3(|m| {
            let ids = folders
                .iter()
                .map(|f| find_folder(m, f))
                .collect::<Result<Vec<_>>>()?;
            let dev = m.grant_to_joiner(name, k6_public, k8_public, &ids, role)?;
            Ok(hex::encode(dev))
        })
    }
}

/// The six words compared ignoring case and spacing.
fn fingerprint_matches(a: &str, b: &str) -> bool {
    let norm = |s: &str| {
        s.split_whitespace()
            .map(str::to_lowercase)
            .collect::<Vec<_>>()
            .join(" ")
    };
    norm(a) == norm(b)
}

fn members_of(m: &mut Membership<'_>, id: &Id16) -> Result<FolderMembers> {
    m.refresh()?;
    let epochs = m.folder_epochs(id);
    let epoch = epochs.current();
    let unresolved_epochs = epochs.unresolved();
    let st = m
        .registry
        .get(id)
        .cloned()
        .ok_or_else(|| anyhow!("no such folder"))?;
    let participants = st
        .participants()
        .into_iter()
        .filter(|p| m.registry.role(&p.device, id, epoch).is_some())
        .map(|p| member_view(m, &p.device, p.role.as_str()))
        .collect();
    let denied = st
        .entries
        .iter()
        .filter(|(d, (r, _))| r.is_none() || m.registry.role(d, id, epoch).is_none())
        .map(|(d, _)| member_view(m, d, "denied"))
        .collect();
    let pending = m
        .list_requests(id)?
        .iter()
        .map(|r| request_view(m, r))
        .collect();
    Ok(FolderMembers {
        folder_id: hex::encode(id),
        folder: st.name.clone(),
        epoch,
        your_role: m.registry.role(&m.me, id, epoch).map(role_text),
        participants,
        denied,
        pending,
        unresolved_epochs,
    })
}
