// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Sharing folders with other people on storage format 3
//! (`docs/spec/format-3-design.md` section 6; `alpha-0-format.md` section
//! 77.6, "Members of other vaults", "As built").
//!
//! - **Asking.** The other person's device makes a request code (`vsr1`:
//!   its K6 and K8 public keys and a name, `vault::ShareRequest`) and reads
//!   out the six words of its fingerprint.
//! - **Answering** (`share_add`): an owner device compares the words, then
//!   writes a folder record that lists the member with its keys and role
//!   and a grant of the folder's keys sealed to the code's K8, carrying the
//!   folder's directory (`membership3::Directory`). Nothing secret travels
//!   out of band: the owner tells the member the storage to use and its own
//!   six words.
//! - **Accepting** (`accept_share`): the member's device reads the grants
//!   to it on that storage, picks the one whose issuer's six words the
//!   person confirmed, and from then on trusts what that owner (and the
//!   owners its directory names) writes (`membership3::MemberView`).
//! - **Removing** (`share_revoke`): a folder epoch without the member; the
//!   members that stay get its key in new grants, and the removed member's
//!   ledger batches count up to its cut-off.
//!
//! The owners' devices write their events of a shared folder into
//! folder-scoped batches under the folder's share-ledger key, which the
//! members read (`ledger3_ops`).

use super::*;
use crate::membership3::{MemberView, Removed, Role};
use crate::share::{self, ShareRole};
use crate::vault::{RequestCode, ShareRequest};

/// One entry of a shared folder's access list.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareMember {
    pub id: String,
    pub name: String,
    /// `owner-device` (a device of the owner's vault) or `member`.
    pub kind: String,
    /// `active` or `removed`.
    pub status: String,
    /// The member's six words (its request code's fingerprint).
    pub fingerprint: String,
    pub this_device: bool,
    pub since_utc: i64,
    pub removed_utc: Option<i64>,
    pub removed_by: Option<String>,
    /// `owner`, `editor` or `viewer`.
    #[serde(default)]
    pub role: String,
}

/// Who has access to a shared folder.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareMembers {
    pub folder: String,
    pub folder_id: String,
    /// The folder's newest epoch this device holds (0: never re-keyed).
    pub share_epoch: u32,
    pub members: Vec<ShareMember>,
    /// This member device no longer receives new content of the folder.
    pub access_lost: bool,
    /// This device's role: `owner`, `editor` or `viewer`.
    #[serde(default)]
    pub this_role: String,
    /// Some participant is a viewer.
    #[serde(default)]
    pub roles_in_use: bool,
}

/// What a removal did.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ShareRevokeReport {
    pub folder: String,
    /// The folder epoch started.
    pub share_epoch: u32,
    /// Members removed (names).
    pub removed: Vec<String>,
    /// Participants that got the new key.
    pub grants_sealed: usize,
    /// Participants that stay but whose keys this device does not know.
    pub grants_pending: Vec<String>,
}

/// What `share_add` did: what the owner tells the member.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareAdded {
    pub folder: String,
    pub folder_id: String,
    pub vault_id: String,
    pub member_id: String,
    pub name: String,
    /// The member's six words, as confirmed.
    pub fingerprint: String,
    pub role: String,
    /// This owner device's six words: the member compares them when it
    /// accepts.
    pub owner_fingerprint: String,
}

/// A folder some owner shared with this (requesting) device, as the grants
/// on a storage show it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareOffer {
    pub folder_id: String,
    pub folder: String,
    pub owner_id: String,
    /// The owner device's six words.
    pub owner_fingerprint: String,
}

fn bin16(hex_id: &str) -> Option<crate::record::Id16> {
    hex::decode(hex_id).ok()?.try_into().ok()
}

impl Engine {
    /// The keys, name and fingerprint a request code carries.
    pub fn share_request_info(code: &str) -> Result<RequestCode> {
        ShareRequest::parse(code)
    }

    /// Owner: share `folder` with another person's device, from its request
    /// code. `confirmed` is the six words the person compared with the
    /// requester (refused when they are not the code's).
    pub fn share_add(
        &mut self,
        folder: &str,
        code: &str,
        confirmed: Option<&str>,
        role: ShareRole,
    ) -> Result<ShareAdded> {
        crate::logged_op!("share add", folder, {
            self.share_add_inner(folder, code, confirmed, role)
        })
    }

    fn share_add_inner(
        &mut self,
        folder: &str,
        code: &str,
        confirmed: Option<&str>,
        role: ShareRole,
    ) -> Result<ShareAdded> {
        if self.vault.member {
            bail!("a member device cannot share the owner's folders");
        }
        self.ensure_active()?;
        self.org_allows(|p| p.members_may_share, "share folders with other people")?;
        let req = ShareRequest::parse(code)?;
        if let Some(words) = confirmed {
            if !share::fingerprint_matches(&req.fingerprint, words) {
                bail!(
                    "the words you confirmed (\"{words}\") are not this request code's (\"{}\"): the code was changed on its way; ask for it again",
                    req.fingerprint
                );
            }
        }
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        if rec.is_strongroom() {
            bail!("a Strongroom folder cannot be shared");
        }
        if rec.is_backup() {
            bail!("a backup cannot be shared");
        }
        let id = members3::bin(&rec.folder_id)?;
        let name = if req.name.is_empty() {
            "member".to_string()
        } else {
            req.name.clone()
        };
        let k8 = req.key.to_bytes();
        let (device, owner_fingerprint) = self
            .with_enrolled3(|m| {
                let d = m.add_member(&id, &name, &req.k6, &k8, role.role3())?;
                let me = m.devices.get(&m.me).cloned().expect("enrolled");
                Ok((d, crate::membership3::fingerprint(&me.sign_pub, &me.kem_pub)))
            })?
            .ok_or_else(|| anyhow!("this device has no storage to share through"))?;
        // The folder's earlier claims and records, where the member reads them.
        self.commit3()?;
        Ok(ShareAdded {
            folder: rec.name.clone(),
            folder_id: rec.folder_id.to_string(),
            vault_id: self.vault.vault_id.to_string(),
            member_id: hex::encode(device),
            name,
            fingerprint: req.fingerprint,
            role: role.as_str().into(),
            owner_fingerprint,
        })
    }

    /// Owner: remove members of a shared folder (`who`: a name, an id or id
    /// prefix, the member's six words, or `all`): a new folder epoch
    /// without them. They keep what they read; what they write from now on
    /// counts nowhere.
    pub fn share_revoke(&mut self, folder: &str, who: &str) -> Result<ShareRevokeReport> {
        crate::logged_op!("share revoke", format!("{folder} {who}"), {
            self.share_revoke_inner(folder, who)
        })
    }

    fn share_revoke_inner(&mut self, folder: &str, who: &str) -> Result<ShareRevokeReport> {
        if self.vault.member {
            bail!("only the owner's devices can remove members of a shared folder");
        }
        self.ensure_active()?;
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        // Up to date first: the cut-offs are the newest batches held here.
        self.pull_ledger_once()?;
        let list = self.share_members(folder)?;
        let who = who.trim();
        let all = who.eq_ignore_ascii_case("all");
        let mut removed = Vec::new();
        let mut names = Vec::new();
        for m in &list.members {
            let hit = all
                || m.id == who
                || (who.len() >= 8 && m.id.starts_with(who))
                || m.name == who
                || (!m.fingerprint.is_empty() && share::fingerprint_matches(&m.fingerprint, who));
            if !hit {
                continue;
            }
            match (m.kind.as_str(), m.status.as_str()) {
                ("member", "active") => {
                    let Some(d) = bin16(&m.id) else { continue };
                    removed.push(Removed {
                        device: d,
                        cutoff: self.f3.ledger.head(&d).seq,
                    });
                    names.push(m.name.clone());
                }
                ("owner-device", _) if !all => bail!(
                    "{} is one of your own devices; remove it from the vault under Devices instead",
                    m.name
                ),
                _ => {}
            }
        }
        if removed.is_empty() {
            bail!(
                "no member of {} matches {who} (see `varsto share members {}`)",
                rec.name,
                rec.name
            );
        }
        let id = members3::bin(&rec.folder_id)?;
        let k1 = self.f3.recovery.clone();
        let start = self
            .with_enrolled3(|m| m.start_folder_epoch(&id, &removed, k1.as_ref()))?
            .ok_or_else(|| anyhow!("this device has no storage to write to"))?;
        self.reset_view3();
        Ok(ShareRevokeReport {
            folder: rec.name.clone(),
            share_epoch: start.epoch,
            removed: names,
            grants_sealed: start.granted_to.len(),
            grants_pending: start.pending.iter().map(hex::encode).collect(),
        })
    }

    /// Whether this member device no longer receives new content of
    /// `folder` (an owner started a folder epoch it holds no key of).
    pub(super) fn share_access_lost(&self, folder: &FolderId) -> bool {
        self.f3
            .members
            .member
            .as_ref()
            .is_some_and(|m| m.access_lost && members3::bin(folder).ok() == Some(m.folder))
    }

    /// Who has access to a folder: the owner's devices and other people's
    /// member devices (current and removed), with their roles.
    pub fn share_members(&self, folder: &str) -> Result<ShareMembers> {
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let id = members3::bin(&rec.folder_id)?;
        let m = &self.f3.members;
        let me = self.me3();
        let mut out = Vec::new();
        let mut roles_in_use = false;
        if let Some(st) = m.registry.get(&id) {
            let ep = m.registry.epochs.get(&id).cloned().unwrap_or_default();
            let removed_in: BTreeMap<crate::record::Id16, (u32, crate::record::Id16)> = ep
                .applied
                .iter()
                .flat_map(|(e, r)| r.removed.iter().map(move |x| (x.device, (*e, r.issuer))))
                .collect();
            for (d, (role, _)) in &st.entries {
                let full = m.devices.get(d).is_some();
                let member = st.members.get(d);
                if !full && member.is_none() {
                    continue;
                }
                let gone = role.is_none() || m.revoked.contains(d) || removed_in.contains_key(d);
                if role == &Some(Role::Viewer) {
                    roles_in_use = true;
                }
                let name = match (m.devices.get(d), member) {
                    (Some(r), _) => r.name.clone(),
                    (None, Some(k)) => k.name.clone(),
                    _ => hex::encode(d),
                };
                let fingerprint = member
                    .map(|k| share::fingerprint(&k.k6, &k.k8, &k.name))
                    .unwrap_or_default();
                let shown_role = st
                    .history
                    .get(d)
                    .and_then(|h| h.iter().rev().find_map(|(_, r)| *r))
                    .map(|r| r.as_str())
                    .unwrap_or("viewer");
                out.push(ShareMember {
                    id: hex::encode(d),
                    name,
                    kind: if full { "owner-device" } else { "member" }.into(),
                    status: if gone { "removed" } else { "active" }.into(),
                    fingerprint,
                    this_device: *d == me,
                    since_utc: 0,
                    removed_utc: None,
                    removed_by: removed_in.get(d).map(|(_, by)| {
                        m.devices
                            .get(by)
                            .map(|r| r.name.clone())
                            .unwrap_or_else(|| hex::encode(by))
                    }),
                    role: shown_role.into(),
                });
            }
        }
        let share_epoch = m
            .granted
            .get(&id)
            .and_then(|k| k.newest())
            .map(|(e, _)| e)
            .unwrap_or(0);
        let this_role = m
            .role(&me, &id)
            .map(|r| r.as_str())
            .unwrap_or(if self.vault.member { "viewer" } else { "owner" });
        Ok(ShareMembers {
            folder: rec.name.clone(),
            folder_id: rec.folder_id.to_string(),
            share_epoch,
            members: out,
            access_lost: self.share_access_lost(&rec.folder_id),
            this_role: this_role.into(),
            roles_in_use,
        })
    }

    // ----- the member's side ----------------------------------------------------

    /// The folders owners shared with the request kept in `home`, as the
    /// grants on `storage` show them, with each owner device's six words.
    pub fn share_offers(
        home: &Path,
        storage: &StorageSpec,
        secret: Option<String>,
    ) -> Result<Vec<ShareOffer>> {
        let (sign, dk, _) = ShareRequest::device_keys(home)?;
        let backend = storage.open_with(&|_| secret.clone())?;
        let meta: VaultMeta = serde_json::from_slice(
            &backend
                .get(VaultMeta::STORAGE_KEY)?
                .ok_or_else(|| anyhow!("storage {} holds no vault", storage.name()))?,
        )?;
        let vault = members3::bin(&meta.vault_id)?;
        let me = crate::membership3::device_id(&sign.public());
        let refs: Vec<&dyn Storage> = vec![backend.as_ref()];
        Ok(MemberView::issuers(&refs, vault, me, &dk)?
            .into_iter()
            .map(|(f, o, name, words)| ShareOffer {
                folder_id: hex::encode(f),
                folder: name,
                owner_id: hex::encode(o),
                owner_fingerprint: words,
            })
            .collect())
    }

    /// Become a member of one shared folder of another person's vault
    /// (F-047), with the request kept in `home` (its keys become this
    /// device's K6 and K8). `owner_words` are the six words the owner's
    /// device showed; without them the folder must be the only one shared
    /// with this request on the storage, from one owner device. This
    /// device reads and writes that folder through the storage, nothing
    /// else of the vault.
    pub fn accept_share(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        owner_words: Option<&str>,
        storage: StorageSpec,
    ) -> Result<Engine> {
        Self::accept_share_with_secret(home, device_name, passphrase, owner_words, storage, None)
    }

    /// Like `accept_share`, through a storage that needs a secret (an S3
    /// bucket both people can reach); the secret goes into this device's
    /// encrypted secret store.
    pub fn accept_share_with_secret(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        owner_words: Option<&str>,
        storage: StorageSpec,
        secret: Option<String>,
    ) -> Result<Engine> {
        crate::logged_op_plain!("accept share with secret", device_name, {
            Self::accept_share_inner(home, device_name, passphrase, owner_words, storage, secret)
        })
    }

    fn accept_share_inner(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        owner_words: Option<&str>,
        storage: StorageSpec,
        secret: Option<String>,
    ) -> Result<Engine> {
        crypto::check_passphrase(passphrase)?;
        crate::names::check_display_name(device_name)?;
        ensure_no_vault(home)?;
        let offers = Self::share_offers(home, &storage, secret.clone())?;
        let picked: Vec<&ShareOffer> = offers
            .iter()
            .filter(|o| owner_words.is_none_or(|w| share::fingerprint_matches(&o.owner_fingerprint, w)))
            .collect();
        let offer = match (picked.as_slice(), owner_words) {
            ([one], _) => (*one).clone(),
            ([], Some(w)) => bail!(
                "no owner device with the words \"{w}\" shared a folder with this request on storage {}{}",
                storage.name(),
                if offers.is_empty() {
                    String::new()
                } else {
                    format!(
                        " (shared by: {})",
                        offers
                            .iter()
                            .map(|o| format!("{} from \"{}\"", o.folder, o.owner_fingerprint))
                            .collect::<Vec<_>>()
                            .join("; ")
                    )
                }
            ),
            ([], None) => bail!(
                "no folder is shared with this request on storage {} yet: give the request code to the owner and accept once it was added",
                storage.name()
            ),
            _ => bail!(
                "several owner devices shared folders with this request: give the six words of the owner's device ({})",
                offers
                    .iter()
                    .map(|o| format!("{}: \"{}\"", o.folder, o.owner_fingerprint))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        };
        let (signer, kem, _) = ShareRequest::device_keys(home)?;
        let backend = storage.open_with(&|_| secret.clone())?;
        let meta: VaultMeta = serde_json::from_slice(
            &backend
                .get(VaultMeta::STORAGE_KEY)?
                .ok_or_else(|| anyhow!("storage {} holds no vault", storage.name()))?,
        )?;
        if meta.format_version != crate::FORMAT_VERSION {
            bail!("{}", crate::format_mismatch(meta.format_version));
        }
        let folder = bin16(&offer.folder_id).ok_or_else(|| anyhow!("bad folder id"))?;
        let anchor = bin16(&offer.owner_id).ok_or_else(|| anyhow!("bad owner id"))?;
        // The grants must lead back to the confirmed owner before anything
        // is written here.
        {
            let refs: Vec<&dyn Storage> = vec![backend.as_ref()];
            MemberView::read(
                &refs,
                members3::bin(&meta.vault_id)?,
                crate::membership3::device_id(&signer.public()),
                &kem,
                folder,
                anchor,
            )?;
        }
        util::private_home(home)?;
        // The "master" of a member is a local random root used only for its
        // local files; it never leaves the device and opens nothing shared.
        let keys = Keys {
            master: SecretKey::random(),
            signer,
        };
        let device_id = ledger::device_id_for(&keys.signer.public());
        let vault = LocalVault {
            format_version: crate::FORMAT_VERSION,
            vault_id: meta.vault_id.clone(),
            device_id,
            device_name: device_name.to_string(),
            created_utc: meta.created_utc,
            member: true,
        };
        let mut epochs = membership::VaultEpochs::genesis(&keys.master);
        epochs.kem = Some(kem);
        let mut engine = Self::write_new(home, vault, keys, passphrase, epochs)?;
        engine.save_epochs()?;
        engine.save_member_state3(&folder, &anchor)?;
        ShareRequest::clear(home);
        engine.add_storage_internal(storage, secret)?;
        engine.refresh_members3()?;
        engine.pending.push(Event::DeviceEnrolled {
            name: engine.vault.device_name.clone(),
        });
        engine.commit_batch()?;
        Ok(engine)
    }
}
