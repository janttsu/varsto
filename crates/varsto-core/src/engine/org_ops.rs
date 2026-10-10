// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Organizations on the engine (`docs/spec/alpha-0-format.md` section 27):
//! creating one, approving and adding devices, removing a user with every
//! device at once, the policy, the log, and what every device checks on
//! sync. See `crate::org` for the objects.
//!
//! Without an organization nothing here runs: `Engine::org` is `None`, every
//! full device is trusted as before, and the interface shows none of it.

use super::*;
use crate::crypto::SigningKey;
use crate::org::{
    self, Approval, LogEntry, Manifest, Member, OrgEvent, OrgPolicy, OrgRequest, OrgState,
    RemovedMember, RequestInfo, Roster, SealedApproval, SignedLogEntry, SignedManifest,
    SignedRoster, LOG_PREFIX, MANIFEST_PREFIX,
};

/// One device as the organization page shows it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgDevice {
    pub device_id: String,
    pub name: String,
    pub admin: bool,
    pub this_device: bool,
    pub revoked: bool,
    pub added_utc: i64,
    #[serde(default)]
    pub details: Option<super::devinfo::DeviceDetails>,
}

/// One person with their devices.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgUser {
    pub user: String,
    pub devices: Vec<OrgDevice>,
}

/// A device of the vault that the roster does not list: it joined with the
/// vault key without an approval, or before the organization existed and
/// the founding device did not know it. Not trusted until an admin adds it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnlistedDevice {
    pub device_id: String,
    pub name: String,
    pub enrolled_utc: i64,
}

/// One log entry as shown or exported.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogView {
    pub utc: i64,
    pub issuer: String,
    pub issuer_name: String,
    pub seq: u64,
    pub event: OrgEvent,
    /// One line in words.
    pub text: String,
}

/// The organization as this device sees it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgSummary {
    pub org_id: String,
    pub name: String,
    pub manifest_seq: u32,
    pub roster_seq: u32,
    pub this_device_admin: bool,
    /// The roster lists this device (a device that joined with the vault key
    /// but was never approved is not trusted by the others).
    pub this_device_listed: bool,
    pub this_user: Option<String>,
    pub admins: Vec<OrgDevice>,
    pub users: Vec<OrgUser>,
    pub removed: Vec<RemovedMember>,
    pub unlisted: Vec<UnlistedDevice>,
    pub policy: OrgPolicy,
    pub log: Vec<LogView>,
}

/// What `org_create` hands back, once.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgCreated {
    pub org_id: String,
    pub name: String,
    /// The 24 words of the root key, shown once and never stored.
    pub root_words: String,
    /// The printable kit around them.
    pub root_kit: String,
    pub devices: Vec<String>,
}

/// What `org_approve` hands back.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgApproved {
    pub token: String,
    pub device_id: String,
    pub name: String,
    pub user: String,
    pub fingerprint: String,
}

/// What `org_remove_user` did.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgRemoveReport {
    pub user: String,
    pub devices: Vec<String>,
    pub revoke: RevokeReport,
}

/// A short line about the organization inside `StatusReport`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrgBrief {
    pub org_id: String,
    pub name: String,
    pub admin: bool,
    pub listed: bool,
    pub user: Option<String>,
}

fn names(list: &[String]) -> String {
    if list.is_empty() {
        "no device".to_string()
    } else {
        list.join(", ")
    }
}

impl Engine {
    // ----- what the rest of the engine asks -------------------------------------

    /// The organization this device has verified, if the vault has one.
    pub fn org(&self) -> Option<&OrgState> {
        self.org.as_ref()
    }

    /// Admin of the organization (always false without one).
    pub fn org_is_admin(&self, device: &DeviceId) -> bool {
        self.org.as_ref().is_some_and(|o| o.is_admin(device))
    }

    /// Refuse an action the organization's policy leaves to admins.
    pub(super) fn org_allows(&self, what: fn(&OrgPolicy) -> bool, action: &str) -> Result<()> {
        if let Some(o) = &self.org {
            if !o.is_admin(&self.vault.device_id) && !what(&o.policy()) {
                bail!(
                    "in the organization {}, only an administrator can {action}",
                    o.name
                );
            }
        }
        Ok(())
    }

    fn require_admin(&self) -> Result<&OrgState> {
        let o = self
            .org
            .as_ref()
            .ok_or_else(|| anyhow!("this vault has no organization (see `varsto org create`)"))?;
        if !o.is_admin(&self.vault.device_id) {
            bail!(
                "this device is not an administrator of the organization {}",
                o.name
            );
        }
        Ok(o)
    }

    pub(super) fn org_brief(&self) -> Option<OrgBrief> {
        let o = self.org.as_ref()?;
        let me = &self.vault.device_id;
        Some(OrgBrief {
            org_id: o.org_id.clone(),
            name: o.name.clone(),
            admin: o.is_admin(me),
            listed: o.lists(me),
            user: o.user_of(me),
        })
    }

    fn save_org(&self) -> Result<()> {
        match &self.org {
            Some(o) => o.save(&self.home),
            None => Ok(()),
        }
    }

    // ----- publishing ---------------------------------------------------------

    /// Put an organization object where it is missing. A collision on the
    /// first storage means another admin wrote the same sequence number.
    fn org_publish(&self, key: &str, bytes: &[u8]) -> Result<()> {
        let storages = self.metadata_storages(true)?;
        if storages.is_empty() {
            bail!("this device has no storage to publish the organization to");
        }
        for (i, (_, b)) in storages.iter().enumerate() {
            if !b.put_if_absent(key, bytes)? && i == 0 {
                bail!("another administrator changed the organization at the same time; sync, then try again");
            }
        }
        Ok(())
    }

    fn publish_org_manifest(&mut self, mut m: Manifest, root: &SigningKey) -> Result<()> {
        let (seq, previous) = {
            let state = self.org.as_ref().expect("organization state set");
            (state.manifest_seq() + 1, state.manifest_hash.clone())
        };
        m.seq = seq;
        m.previous_hash = previous;
        m.issued_utc = util::now_utc();
        let sm = SignedManifest::seal(
            &m,
            &self.vault.vault_id,
            self.key_epoch(),
            self.current_vault_key(),
            root,
        )?;
        let bytes = serde_json::to_vec(&sm)?;
        self.org_publish(&SignedManifest::storage_key(m.seq), &bytes)?;
        let state = self.org.as_mut().expect("organization state set");
        state.manifest_hash = hex::encode(crypto::hash(&bytes));
        state.name = m.name.clone();
        state.manifests.insert(m.seq, m);
        self.save_org()
    }

    fn publish_roster(&mut self, mut r: Roster) -> Result<()> {
        let me = self.vault.device_id.clone();
        let state = self.org.as_ref().expect("organization state set");
        r.org_id = state.org_id.clone();
        r.seq = state.roster_seq() + 1;
        r.previous_hash = state.roster_hash.clone();
        r.manifest_seq = state.manifest_seq();
        r.issuer = me;
        r.issued_utc = util::now_utc();
        let sr = SignedRoster::seal(
            &r,
            &self.vault.vault_id,
            self.key_epoch(),
            self.current_vault_key(),
            &self.keys.signer,
        )?;
        let bytes = serde_json::to_vec(&sr)?;
        self.org_publish(&SignedRoster::storage_key(r.seq), &bytes)?;
        let state = self.org.as_mut().expect("organization state set");
        state.roster_hash = hex::encode(crypto::hash(&bytes));
        state.roster = Some(r);
        self.save_org()
    }

    fn org_log(&mut self, event: OrgEvent) -> Result<()> {
        let me = self.vault.device_id.clone();
        let state = self.org.as_ref().expect("organization state set");
        let seq = state
            .log
            .get(&me)
            .and_then(|m| m.keys().next_back().copied())
            .unwrap_or(0)
            + 1;
        let e = LogEntry {
            org_id: state.org_id.clone(),
            issuer: me.clone(),
            seq,
            previous_hash: state.log_hashes.get(&me).cloned().unwrap_or_default(),
            utc: util::now_utc(),
            event,
        };
        let se = SignedLogEntry::seal(
            &e,
            &self.vault.vault_id,
            self.key_epoch(),
            self.current_vault_key(),
            &self.keys.signer,
        )?;
        let bytes = serde_json::to_vec(&se)?;
        self.org_publish(&SignedLogEntry::storage_key(&me, seq), &bytes)?;
        let state = self.org.as_mut().expect("organization state set");
        state
            .log_hashes
            .insert(me.clone(), hex::encode(crypto::hash(&bytes)));
        state.log.entry(me).or_default().insert(seq, e);
        self.save_org()
    }

    fn current_roster(&self) -> Roster {
        self.org
            .as_ref()
            .and_then(|o| o.roster.clone())
            .unwrap_or_else(|| Roster {
                org_id: String::new(),
                seq: 0,
                previous_hash: String::new(),
                manifest_seq: 0,
                issuer: self.vault.device_id.clone(),
                issued_utc: 0,
                members: vec![],
                removed: vec![],
                policy: OrgPolicy::default(),
            })
    }

    // ----- creating -------------------------------------------------------------

    /// Turn this vault into an organization's vault: this device becomes the
    /// first administrator, every current device belongs to `founder`, and
    /// the root key is returned as 24 words, once.
    pub fn org_create(&mut self, name: &str, founder: &str) -> Result<OrgCreated> {
        if self.vault.member {
            bail!("a member device holds shared folders only; organizations are created on a full device");
        }
        self.ensure_active()?;
        let name = name.trim();
        let founder = founder.trim();
        if name.is_empty() || founder.is_empty() {
            bail!("give the organization a name and the founder a user name");
        }
        self.pull_registry()?;
        self.sync_org()?;
        if let Some(o) = &self.org {
            bail!("this vault already belongs to the organization {}", o.name);
        }
        for (_, b) in self.metadata_storages(false)? {
            if !b.list(MANIFEST_PREFIX)?.is_empty() {
                bail!("a storage already holds an organization this device cannot read; sync first, or remove the stale objects");
            }
        }
        let root = SecretKey::random();
        let signer = org::root_signer(&root);
        let org_id = org::org_id_for(&signer.public());
        let me = self.vault.device_id.clone();
        self.org = Some(OrgState {
            org_id: org_id.clone(),
            name: name.to_string(),
            root_pubkey_hex: hex::encode(signer.public().to_bytes()),
            ..OrgState::default()
        });
        let manifest = Manifest {
            org_id: org_id.clone(),
            name: name.to_string(),
            seq: 0,
            previous_hash: String::new(),
            issued_utc: 0,
            root_pubkey_hex: hex::encode(signer.public().to_bytes()),
            admins: vec![org::Admin {
                device: me.clone(),
                name: self.vault.device_name.clone(),
            }],
        };
        if let Err(e) = self.publish_org_manifest(manifest, &signer) {
            self.org = None;
            return Err(e);
        }
        // Every device this one trusts belongs to the founder.
        let now = util::now_utc();
        let mut devices: Vec<(DeviceId, String, i64)> = self
            .devices
            .devices
            .iter()
            .filter(|(id, _)| self.trusted(id))
            .map(|(id, r)| (id.clone(), r.name.clone(), r.enrolled_utc))
            .collect();
        if !devices.iter().any(|(id, _, _)| *id == me) {
            devices.push((me.clone(), self.vault.device_name.clone(), now));
        }
        devices.sort();
        let mut roster = self.current_roster();
        roster.members = devices
            .iter()
            .map(|(id, dev_name, _)| Member {
                device: id.clone(),
                user: founder.to_string(),
                name: dev_name.clone(),
                added_utc: now,
                added_by: me.clone(),
            })
            .collect();
        self.publish_roster(roster)?;
        let device_names: Vec<String> = devices.iter().map(|(_, n, _)| n.clone()).collect();
        self.org_log(OrgEvent::OrgCreated {
            name: name.to_string(),
            founder: founder.to_string(),
            devices: device_names.clone(),
        })?;
        let root_hex = root.to_hex();
        Ok(OrgCreated {
            org_id: org_id.clone(),
            name: name.to_string(),
            root_words: crate::recovery::words_from_key(&root_hex)?,
            root_kit: org::root_kit_text(name, &org_id, &root_hex)?,
            devices: device_names,
        })
    }

    // ----- devices and users ----------------------------------------------------------

    /// Admin: approve a request code. The device is added to the roster
    /// under `user` and gets a token sealed to its request key with the
    /// vault key and the storage settings. `confirmed`, when given, is the
    /// fingerprint the admin compared with the person; it must match.
    pub fn org_approve(
        &mut self,
        code: &str,
        user: &str,
        confirmed: Option<&str>,
    ) -> Result<OrgApproved> {
        self.ensure_active()?;
        self.sync_org()?;
        self.require_admin()?;
        let info: RequestInfo = OrgRequest::parse(code)?;
        if let Some(c) = confirmed {
            if !crate::share::fingerprint_matches(&info.fingerprint, c) {
                bail!(
                    "the fingerprint you confirmed does not match this request code (it shows \"{}\"); do not approve it",
                    info.fingerprint
                );
            }
        }
        let user = user.trim();
        if user.is_empty() {
            bail!("give the user the device belongs to");
        }
        if self.is_revoked(&info.device) {
            bail!(
                "this device was removed from the vault; it needs a new request (reset it first)"
            );
        }
        let mut roster = self.current_roster();
        if roster.member(&info.device).is_some() {
            bail!("this device is already in the organization");
        }
        let me = self.vault.device_id.clone();
        roster.members.push(Member {
            device: info.device.clone(),
            user: user.to_string(),
            name: info.name.clone(),
            added_utc: util::now_utc(),
            added_by: me.clone(),
        });
        self.publish_roster(roster)?;
        self.org_log(OrgEvent::DeviceApproved {
            device: info.device.clone(),
            user: user.to_string(),
            name: info.name.clone(),
        })?;
        let o = self.org.as_ref().expect("organization");
        let approval = Approval {
            bundle: self.pairing_bundle()?,
            org_id: o.org_id.clone(),
            org_name: o.name.clone(),
            user: user.to_string(),
            approver: me,
            fingerprint: info.fingerprint.clone(),
        };
        let token = SealedApproval::seal(&approval, &info.key)?.encode();
        Ok(OrgApproved {
            token,
            device_id: info.device.to_string(),
            name: info.name,
            user: user.to_string(),
            fingerprint: info.fingerprint,
        })
    }

    /// Join a vault with an approval token (the request must have been made
    /// in `home`). The device keeps the signing key it made with the
    /// request, so it has the device id the admin put in the roster.
    pub fn org_join(
        home: &Path,
        device_name: &str,
        passphrase: &str,
        token: &str,
    ) -> Result<(Engine, Vec<String>, Approval)> {
        let (approval, signer) = org::open_approval(home, token)?;
        let (engine, notes) = Self::join_paired_with(
            home,
            device_name,
            passphrase,
            &approval.bundle,
            Some(signer),
        )?;
        OrgRequest::clear(home);
        Ok((engine, notes, approval))
    }

    /// Admin: add a device that already holds the vault key (it paired, or
    /// joined with the key) to the roster under `user`.
    pub fn org_add_device(&mut self, name_or_id: &str, user: &str) -> Result<()> {
        self.ensure_active()?;
        self.pull_registry()?;
        self.sync_org()?;
        self.require_admin()?;
        let user = user.trim();
        if user.is_empty() {
            bail!("give the user the device belongs to");
        }
        let wanted = name_or_id.trim();
        let found: Vec<(DeviceId, String)> = self
            .devices
            .devices
            .iter()
            .filter(|(id, rec)| {
                rec.name == wanted
                    || id.as_str() == wanted
                    || (wanted.len() >= 8 && id.as_str().starts_with(wanted))
            })
            .map(|(id, rec)| (id.clone(), rec.name.clone()))
            .collect();
        let (device, dev_name) = match found.as_slice() {
            [] => bail!("no device named {wanted} has published a record in this vault"),
            [one] => one.clone(),
            _ => bail!("several devices are named {wanted}: use the device id instead"),
        };
        if self.is_revoked(&device) {
            bail!("{wanted} was removed from the vault");
        }
        let mut roster = self.current_roster();
        if roster.member(&device).is_some() {
            bail!("{wanted} is already in the organization");
        }
        let me = self.vault.device_id.clone();
        roster.members.push(Member {
            device: device.clone(),
            user: user.to_string(),
            name: dev_name.clone(),
            added_utc: util::now_utc(),
            added_by: me,
        });
        self.publish_roster(roster)?;
        self.org_log(OrgEvent::DeviceAdded {
            device,
            user: user.to_string(),
            name: dev_name,
        })
    }

    /// Admin: remove a person. Every device of theirs is revoked in one key
    /// epoch (optionally with a wipe order), the roster moves them to the
    /// removed list, and the log records it.
    pub fn org_remove_user(&mut self, user: &str, wipe: bool) -> Result<OrgRemoveReport> {
        self.ensure_active()?;
        self.sync_org()?;
        self.require_admin()?;
        let user = user.trim();
        let roster = self.current_roster();
        let mine: Vec<Member> = roster
            .members
            .iter()
            .filter(|m| m.user == user)
            .cloned()
            .collect();
        if mine.is_empty() {
            bail!("no user named {user} in the organization (see `varsto org status`)");
        }
        let me = self.vault.device_id.clone();
        if mine.iter().any(|m| m.device == me) {
            bail!("{user} owns this device: remove them from another administrator's device");
        }
        let targets: Vec<DeviceId> = mine
            .iter()
            .filter(|m| !self.is_revoked(&m.device))
            .map(|m| m.device.clone())
            .collect();
        let revoke = self.revoke_many(&targets, wipe)?;
        self.org_record_removed(&mine, wipe, revoke.key_epoch)?;
        self.org_log(OrgEvent::UserRemoved {
            user: user.to_string(),
            devices: mine.iter().map(|m| m.name.clone()).collect(),
            wipe,
            key_epoch: revoke.key_epoch,
        })?;
        Ok(OrgRemoveReport {
            user: user.to_string(),
            devices: mine.iter().map(|m| m.name.clone()).collect(),
            revoke,
        })
    }

    /// Move members to the removed list and publish the roster.
    fn org_record_removed(&mut self, gone: &[Member], wipe: bool, _epoch: u32) -> Result<()> {
        let me = self.vault.device_id.clone();
        let now = util::now_utc();
        let mut roster = self.current_roster();
        let ids: BTreeSet<DeviceId> = gone.iter().map(|m| m.device.clone()).collect();
        roster.members.retain(|m| !ids.contains(&m.device));
        for m in gone {
            roster.removed.push(RemovedMember {
                device: m.device.clone(),
                user: m.user.clone(),
                name: m.name.clone(),
                removed_utc: now,
                removed_by: me.clone(),
                wipe,
            });
        }
        self.publish_roster(roster)
    }

    /// After `revoke_device` on an admin device: keep the roster and the log
    /// in step. A device the roster does not list leaves nothing to record.
    pub(super) fn org_after_revoke(
        &mut self,
        device: &DeviceId,
        wipe: bool,
        epoch: u32,
    ) -> Result<()> {
        let Some(o) = &self.org else {
            return Ok(());
        };
        if !o.is_admin(&self.vault.device_id) {
            return Ok(());
        }
        let Some(m) = o.roster.as_ref().and_then(|r| r.member(device).cloned()) else {
            return Ok(());
        };
        self.org_record_removed(std::slice::from_ref(&m), wipe, epoch)?;
        self.org_log(OrgEvent::DeviceRemoved {
            device: m.device.clone(),
            user: m.user.clone(),
            name: m.name.clone(),
            wipe,
            key_epoch: epoch,
        })
    }

    /// Admin: change what members may do.
    pub fn org_set_policy(&mut self, policy: OrgPolicy) -> Result<()> {
        self.ensure_active()?;
        self.sync_org()?;
        self.require_admin()?;
        let mut roster = self.current_roster();
        roster.policy = policy.clone();
        self.publish_roster(roster)?;
        self.org_log(OrgEvent::PolicyChanged { policy })
    }

    /// Root key holder: make a device of the organization an administrator.
    pub fn org_admin_add(&mut self, name_or_id: &str, root_words: &str) -> Result<()> {
        self.ensure_active()?;
        self.pull_registry()?;
        self.sync_org()?;
        let (_, root) = org::root_from_words(root_words)?;
        let o = self
            .org
            .as_ref()
            .ok_or_else(|| anyhow!("this vault has no organization"))?;
        if hex::encode(root.public().to_bytes()) != o.root_pubkey_hex {
            bail!(
                "these words are not the root key of the organization {}",
                o.name
            );
        }
        let device = self.org_resolve(name_or_id)?;
        let dev_name = self.device_name(&device);
        let mut m = o
            .manifest()
            .cloned()
            .expect("an organization has a manifest");
        if m.is_admin(&device) {
            bail!("{dev_name} is already an administrator");
        }
        if !o.lists(&device) {
            bail!(
                "{dev_name} is not in the organization yet: add it first (`varsto org add-device`)"
            );
        }
        m.admins.push(org::Admin {
            device: device.clone(),
            name: dev_name.clone(),
        });
        self.publish_org_manifest(m, &root)?;
        if self.org_is_admin(&self.vault.device_id) {
            self.org_log(OrgEvent::AdminAdded {
                device,
                name: dev_name,
            })?;
        }
        Ok(())
    }

    /// Root key holder: take the admin role from a device (it stays a member).
    pub fn org_admin_remove(&mut self, name_or_id: &str, root_words: &str) -> Result<()> {
        self.ensure_active()?;
        self.pull_registry()?;
        self.sync_org()?;
        let (_, root) = org::root_from_words(root_words)?;
        let o = self
            .org
            .as_ref()
            .ok_or_else(|| anyhow!("this vault has no organization"))?;
        if hex::encode(root.public().to_bytes()) != o.root_pubkey_hex {
            bail!(
                "these words are not the root key of the organization {}",
                o.name
            );
        }
        let device = self.org_resolve(name_or_id)?;
        let dev_name = self.device_name(&device);
        let mut m = o
            .manifest()
            .cloned()
            .expect("an organization has a manifest");
        if !m.is_admin(&device) {
            bail!("{dev_name} is not an administrator");
        }
        m.admins.retain(|a| a.device != device);
        if m.admins.is_empty() {
            bail!("an organization needs at least one administrator; add another first");
        }
        let was_me_admin = self.org_is_admin(&self.vault.device_id);
        self.publish_org_manifest(m, &root)?;
        if was_me_admin && self.org_is_admin(&self.vault.device_id) {
            self.org_log(OrgEvent::AdminRemoved {
                device,
                name: dev_name,
            })?;
        }
        Ok(())
    }

    fn org_resolve(&self, name_or_id: &str) -> Result<DeviceId> {
        let wanted = name_or_id.trim();
        let me = self.vault.device_id.clone();
        let own = self.own_record();
        let found: Vec<DeviceId> = self
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
        match found.as_slice() {
            [] => bail!("no device named {wanted} in this vault"),
            [one] => Ok(one.clone()),
            _ => bail!("several devices are named {wanted}: use the device id instead"),
        }
    }

    // ----- showing ----------------------------------------------------------------

    fn log_text(&self, e: &LogEntry) -> String {
        let who = self.device_name(&e.issuer);
        match &e.event {
            OrgEvent::OrgCreated {
                name,
                founder,
                devices,
            } => format!(
                "{who} created the organization {name}; {founder} owns {}",
                names(devices)
            ),
            OrgEvent::AdminAdded { name, .. } => format!("{who} made {name} an administrator"),
            OrgEvent::AdminRemoved { name, .. } => {
                format!("{who} took the administrator role from {name}")
            }
            OrgEvent::DeviceApproved { user, name, .. } => {
                format!("{who} approved {name} for {user}")
            }
            OrgEvent::DeviceAdded { user, name, .. } => format!("{who} added {name} for {user}"),
            OrgEvent::DeviceRemoved {
                user,
                name,
                wipe,
                key_epoch,
                ..
            } => format!(
                "{who} removed {name} ({user}){}; vault key epoch {key_epoch}",
                if *wipe { " with a wipe order" } else { "" }
            ),
            OrgEvent::UserRemoved {
                user,
                devices,
                wipe,
                key_epoch,
            } => format!(
                "{who} removed {user} with {}{}; vault key epoch {key_epoch}",
                names(devices),
                if *wipe { " and ordered a wipe" } else { "" }
            ),
            OrgEvent::PolicyChanged { policy } => format!(
                "{who} changed the policy: members may{} share,{} add storages,{} set policies,{} add devices",
                if policy.members_may_share { "" } else { " not" },
                if policy.members_may_add_storages { "" } else { " not" },
                if policy.members_may_set_policies { "" } else { " not" },
                if policy.members_may_add_devices { "" } else { " not" },
            ),
            OrgEvent::Unknown => format!("{who}: an event this version does not know"),
        }
    }

    /// The accepted log, oldest first.
    pub fn org_log_entries(&self) -> Vec<LogView> {
        let Some(o) = &self.org else {
            return Vec::new();
        };
        o.entries()
            .iter()
            .map(|e| LogView {
                utc: e.utc,
                issuer: e.issuer.to_string(),
                issuer_name: self.device_name(&e.issuer),
                seq: e.seq,
                event: e.event.clone(),
                text: self.log_text(e),
            })
            .collect()
    }

    /// Everything the organization page shows; `None` without an organization.
    pub fn org_summary(&self) -> Option<OrgSummary> {
        let o = self.org.as_ref()?;
        let me = &self.vault.device_id;
        let device = |id: &DeviceId, name: &str, added: i64| OrgDevice {
            device_id: id.to_string(),
            name: name.to_string(),
            admin: o.is_admin(id),
            this_device: id == me,
            revoked: self.is_revoked(id),
            added_utc: added,
            details: self.devices.details.get(id).cloned(),
        };
        let roster = o.roster.clone().unwrap_or_else(|| self.current_roster());
        let mut users: BTreeMap<String, Vec<OrgDevice>> = BTreeMap::new();
        for m in &roster.members {
            users
                .entry(m.user.clone())
                .or_default()
                .push(device(&m.device, &m.name, m.added_utc));
        }
        let admins = o
            .manifest()
            .map(|m| {
                m.admins
                    .iter()
                    .map(|a| {
                        let added = roster.member(&a.device).map(|m| m.added_utc).unwrap_or(0);
                        device(&a.device, &self.device_name(&a.device), added)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let unlisted = self
            .devices
            .devices
            .iter()
            .filter(|(id, _)| *id != me && !self.is_revoked(id) && roster.member(id).is_none())
            .map(|(id, r)| UnlistedDevice {
                device_id: id.to_string(),
                name: r.name.clone(),
                enrolled_utc: r.enrolled_utc,
            })
            .collect();
        Some(OrgSummary {
            org_id: o.org_id.clone(),
            name: o.name.clone(),
            manifest_seq: o.manifest_seq(),
            roster_seq: roster.seq,
            this_device_admin: o.is_admin(me),
            this_device_listed: roster.member(me).is_some(),
            this_user: roster.member(me).map(|m| m.user.clone()),
            admins,
            users: users
                .into_iter()
                .map(|(user, devices)| OrgUser { user, devices })
                .collect(),
            removed: roster.removed.clone(),
            unlisted,
            policy: roster.policy.clone(),
            log: self.org_log_entries(),
        })
    }

    // ----- what every device checks on sync --------------------------------------------

    /// Read new manifests, rosters and log entries from the storages and
    /// adopt those that verify. Run before revocations are read, so that
    /// "only an admin revokes" uses the newest admin list.
    pub(super) fn sync_org(&mut self) -> Result<()> {
        if self.vault.member || self.removal.is_some() {
            return Ok(());
        }
        let open = self.metadata_storages(false)?;
        let storages: Vec<&dyn Storage> = open.iter().map(|(_, b)| b.as_ref()).collect();
        let mut state = self.org.clone().unwrap_or_default();
        let mut have = self.org.is_some();
        let mut changed = false;
        let vault = self.vault.vault_id.clone();

        // Manifests: contiguous from the one after the newest held; the
        // first one pins the root key.
        loop {
            let want = state.manifest_seq() + 1;
            let key = SignedManifest::storage_key(want);
            let mut adopted = false;
            for b in &storages {
                let Some(blob) = b.get(&key)? else { continue };
                let Ok(sm) = serde_json::from_slice::<SignedManifest>(&blob) else {
                    continue;
                };
                if sm.seq != want || (have && sm.org_id != state.org_id) {
                    continue;
                }
                let Some(vk) = self.epochs.keys.get(&sm.key_epoch) else {
                    continue;
                };
                let pinned = if have { state.root_key().ok() } else { None };
                let Ok(m) = sm.open(&vault, vk, pinned.as_ref()) else {
                    continue;
                };
                if have && m.previous_hash != state.manifest_hash {
                    continue;
                }
                if !have {
                    state.org_id = m.org_id.clone();
                    state.root_pubkey_hex = m.root_pubkey_hex.clone();
                    have = true;
                }
                state.manifest_hash = hex::encode(crypto::hash(&blob));
                state.name = m.name.clone();
                state.manifests.insert(want, m);
                changed = true;
                adopted = true;
                break;
            }
            if !adopted {
                break;
            }
        }
        if !have {
            return Ok(());
        }

        // Rosters: contiguous, signed by an admin of the manifest they name.
        loop {
            let want = state.roster_seq() + 1;
            let key = SignedRoster::storage_key(want);
            let mut adopted = false;
            for b in &storages {
                let Some(blob) = b.get(&key)? else { continue };
                let Ok(sr) = serde_json::from_slice::<SignedRoster>(&blob) else {
                    continue;
                };
                if sr.seq != want || sr.org_id != state.org_id {
                    continue;
                }
                let (Some(pk), Some(vk)) = (
                    self.device_key(&sr.issuer),
                    self.epochs.keys.get(&sr.key_epoch),
                ) else {
                    continue;
                };
                if self.is_revoked(&sr.issuer) && sr.issuer != self.vault.device_id {
                    continue;
                }
                let Ok(r) = sr.open(&vault, vk, &pk) else {
                    continue;
                };
                if r.previous_hash != state.roster_hash
                    || r.manifest_seq > state.manifest_seq()
                    || !state.was_admin(&r.issuer, r.manifest_seq)
                {
                    continue;
                }
                state.roster_hash = hex::encode(crypto::hash(&blob));
                state.roster = Some(r);
                changed = true;
                adopted = true;
                break;
            }
            if !adopted {
                break;
            }
        }

        // Log entries: one chain per admin device (current or former).
        let mut issuers: BTreeSet<DeviceId> = BTreeSet::new();
        for b in &storages {
            for k in b.list(LOG_PREFIX)? {
                if let Some(dev) = k
                    .strip_prefix(LOG_PREFIX)
                    .and_then(|r| r.split('/').next())
                    .and_then(|d| DeviceId::from_hex(d).ok())
                {
                    issuers.insert(dev);
                }
            }
        }
        for issuer in issuers {
            if !state.ever_admin(&issuer) {
                continue;
            }
            let Some(pk) = self.device_key(&issuer) else {
                continue;
            };
            loop {
                let want = state
                    .log
                    .get(&issuer)
                    .and_then(|m| m.keys().next_back().copied())
                    .unwrap_or(0)
                    + 1;
                let key = SignedLogEntry::storage_key(&issuer, want);
                let mut adopted = false;
                for b in &storages {
                    let Some(blob) = b.get(&key)? else { continue };
                    let Ok(se) = serde_json::from_slice::<SignedLogEntry>(&blob) else {
                        continue;
                    };
                    if se.seq != want || se.issuer != issuer || se.org_id != state.org_id {
                        continue;
                    }
                    let Some(vk) = self.epochs.keys.get(&se.key_epoch) else {
                        continue;
                    };
                    let Ok(e) = se.open(&vault, vk, &pk) else {
                        continue;
                    };
                    if e.previous_hash != state.log_hashes.get(&issuer).cloned().unwrap_or_default()
                    {
                        continue;
                    }
                    state
                        .log_hashes
                        .insert(issuer.clone(), hex::encode(crypto::hash(&blob)));
                    state.log.entry(issuer.clone()).or_default().insert(want, e);
                    changed = true;
                    adopted = true;
                    break;
                }
                if !adopted {
                    break;
                }
            }
        }
        drop(open);
        if changed || self.org.is_none() {
            self.org = Some(state);
            self.save_org()?;
        }
        Ok(())
    }
}

/// Files `reset_device` removes for organizations.
pub(super) const RESET_ORG: [&str; 2] = [org::STATE_FILE, org::REQUEST_FILE];
