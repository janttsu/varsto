// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Organizations on the engine (`docs/spec/alpha-0-format.md` section 27):
//! creating one, approving and adding devices, removing a user with every
//! device at once, the policy, the log, and what every device checks on
//! sync. See `crate::org` for the objects.
//!
//! Without an organization nothing here runs: `Engine::org` is `None`, every
//! full device is trusted as before, and the interface shows none of it.

use super::*;
use crate::crypto::{SigningKey, VerifyingKey};
use crate::org::{
    self, Approval, LogEntry, Manifest, Member, OrgEvent, OrgPolicy, OrgRequest, OrgState,
    RemovedMember, RequestInfo, Roster, SealedApproval, SignedLogEntry, SignedManifest,
    SignedRoster, LOG_PREFIX, MANIFEST_PREFIX, ROSTER_PREFIX,
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
    /// The issuer is no longer an administrator (a former one can still
    /// append to its own chain; readers see it here).
    #[serde(default)]
    pub former_admin: bool,
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
            // A state pinned on join, before the manifest arrived, binds nothing yet.
            if o.manifest().is_some() && !o.is_admin(&self.vault.device_id) && !what(&o.policy()) {
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

    /// Metadata storages that can be read.
    fn org_storages(&self) -> Result<OpenStorages> {
        self.metadata_storages(false)
    }

    /// The names under `prefix` on every storage, listed once.
    fn org_listing(storages: &[&dyn Storage], prefix: &str) -> Result<Vec<Vec<String>>> {
        storages.iter().map(|b| b.list(prefix)).collect()
    }

    /// The objects of one sequence number from every storage, in name
    /// order (ties by content hash), one per distinct content: name, hash
    /// of the bytes, bytes.
    fn org_candidates(
        storages: &[&dyn Storage],
        listing: &[Vec<String>],
        prefix: &str,
        seq: u32,
    ) -> Result<Vec<(String, String, Vec<u8>)>> {
        let mut out: Vec<(String, String, Vec<u8>)> = Vec::new();
        for (b, names) in storages.iter().zip(listing) {
            for k in names {
                let Some(name) = k.strip_prefix(prefix) else {
                    continue;
                };
                if org::seq_from_name(name) != Some(seq) {
                    continue;
                }
                if let Some(blob) = b.get(k)? {
                    let hash = hex::encode(crypto::hash(&blob));
                    if !out.iter().any(|(_, h, _)| *h == hash) {
                        out.push((name.to_string(), hash, blob));
                    }
                }
            }
        }
        out.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
        Ok(out)
    }

    /// Claim a sequence number: the lowest attempt that is free on the
    /// first storage takes `bytes` with put-if-absent, so two writers of
    /// the same sequence number cannot both succeed there. An occupied
    /// attempt whose object `valid` accepts means another writer won (an
    /// error); junk is skipped. The name is then written to the other
    /// storages where it is free.
    fn org_claim(
        &self,
        name_of: impl Fn(u32) -> String,
        valid: impl Fn(&[u8]) -> bool,
        bytes: &[u8],
        conflict: &str,
    ) -> Result<String> {
        let storages = self.metadata_storages(true)?;
        let Some((_, first)) = storages.first() else {
            bail!("this device has no storage to publish the organization to");
        };
        let mut chosen = None;
        for attempt in 1..=org::ATTEMPTS {
            let name = name_of(attempt);
            if first.put_if_absent(&name, bytes)? {
                chosen = Some(name);
                break;
            }
            if let Some(other) = first.get(&name)? {
                if other == bytes {
                    chosen = Some(name);
                    break;
                }
                if valid(&other) {
                    bail!("{conflict}");
                }
            }
        }
        let Some(name) = chosen else {
            bail!("the storage holds too many junk objects under this sequence number; remove them under org/ and try again");
        };
        for (_, b) in storages.iter().skip(1) {
            b.put_if_absent(&name, bytes)?;
        }
        Ok(name)
    }

    // ----- what verifies ------------------------------------------------------

    /// Manifest `want` from `blob`, if it extends `state` (or starts it when
    /// `state` has none yet): chained, in sequence, signed by the root key.
    fn try_manifest(&self, state: &OrgState, want: u32, blob: &[u8]) -> Option<Manifest> {
        let have = !state.org_id.is_empty();
        let sm = serde_json::from_slice::<SignedManifest>(blob).ok()?;
        if sm.seq != want || (have && sm.org_id != state.org_id) {
            return None;
        }
        let vk = self.epochs.keys.get(&sm.key_epoch)?;
        let pinned = if have && !state.root_pubkey_hex.is_empty() {
            Some(state.root_key().ok()?)
        } else {
            None
        };
        let m = sm.open(&self.vault.vault_id, vk, pinned.as_ref()).ok()?;
        if m.previous_hash != state.manifest_hash {
            return None;
        }
        if state.manifests.is_empty() && want != 1 {
            return None;
        }
        Some(m)
    }

    /// Roster `want` from `blob`, if it extends `state`: chained, in
    /// sequence, signed by a device that the manifest in force for this
    /// sequence number names as an administrator, that the previous roster
    /// lists as a member, and that is not revoked.
    fn try_roster(&self, state: &OrgState, want: u32, blob: &[u8]) -> Option<Roster> {
        let sr = serde_json::from_slice::<SignedRoster>(blob).ok()?;
        if sr.seq != want || sr.org_id != state.org_id {
            return None;
        }
        let pk = self.device_key(&sr.issuer)?;
        let vk = self.epochs.keys.get(&sr.key_epoch)?;
        if self.is_revoked(&sr.issuer) && sr.issuer != self.vault.device_id {
            return None;
        }
        let r = sr.open(&self.vault.vault_id, vk, &pk).ok()?;
        if r.previous_hash != state.roster_hash
            || r.manifest_seq > state.manifest_seq()
            || !state.governs_admin(&r.issuer, want)
        {
            return None;
        }
        if want > 1 && !state.lists(&r.issuer) {
            return None;
        }
        Some(r)
    }

    /// Log entry `want` of `issuer` from `blob`, if it extends that chain:
    /// signed by the issuer, which the manifest in force when it was
    /// written names as an administrator.
    fn try_log(
        &self,
        state: &OrgState,
        issuer: &DeviceId,
        pk: &VerifyingKey,
        want: u64,
        blob: &[u8],
    ) -> Option<LogEntry> {
        let se = serde_json::from_slice::<SignedLogEntry>(blob).ok()?;
        if se.seq != want || &se.issuer != issuer || se.org_id != state.org_id {
            return None;
        }
        let vk = self.epochs.keys.get(&se.key_epoch)?;
        let e = se.open(&self.vault.vault_id, vk, pk).ok()?;
        if e.previous_hash != state.log_hashes.get(issuer).cloned().unwrap_or_default()
            || e.roster_seq > state.roster_seq()
            || !state.governs_admin(issuer, e.roster_seq + 1)
        {
            return None;
        }
        Some(e)
    }

    fn publish_org_manifest(&mut self, mut m: Manifest, root: &SigningKey) -> Result<()> {
        let (seq, previous, roster_seq) = {
            let state = self.org.as_ref().expect("organization state set");
            (
                state.manifest_seq() + 1,
                state.manifest_hash.clone(),
                state.roster_seq(),
            )
        };
        m.seq = seq;
        m.previous_hash = previous;
        m.issued_utc = util::now_utc();
        m.roster_seq = roster_seq;
        let sm = SignedManifest::seal(
            &m,
            &self.vault.vault_id,
            self.key_epoch(),
            self.current_vault_key(),
            root,
        )?;
        let bytes = serde_json::to_vec(&sm)?;
        let state = self.org.as_ref().expect("organization state set");
        self.org_claim(
            |attempt| SignedManifest::storage_key(seq, attempt),
            |other| self.try_manifest(state, seq, other).is_some(),
            &bytes,
            "another change of the organization's administrators won this sequence number; sync, then try again",
        )?;
        let mine = hex::encode(crypto::hash(&bytes));
        let state = self.org.as_mut().expect("organization state set");
        state.manifest_hash = mine;
        state.name = m.name.clone();
        state.manifests.insert(seq, m);
        self.save_org()
    }

    fn publish_roster(&mut self, mut r: Roster) -> Result<()> {
        let me = self.vault.device_id.clone();
        let (seq, previous, manifest_seq, org_id) = {
            let state = self.org.as_ref().expect("organization state set");
            (
                state.roster_seq() + 1,
                state.roster_hash.clone(),
                state.manifest_seq(),
                state.org_id.clone(),
            )
        };
        r.org_id = org_id;
        r.seq = seq;
        r.previous_hash = previous;
        r.manifest_seq = manifest_seq;
        r.issuer = me.clone();
        r.issued_utc = util::now_utc();
        let sr = SignedRoster::seal(
            &r,
            &self.vault.vault_id,
            self.key_epoch(),
            self.current_vault_key(),
            &self.keys.signer,
        )?;
        let bytes = serde_json::to_vec(&sr)?;
        let state = self.org.as_ref().expect("organization state set");
        self.org_claim(
            |attempt| SignedRoster::storage_key(seq, attempt),
            |other| self.try_roster(state, seq, other).is_some(),
            &bytes,
            "another administrator changed the organization at the same time; sync, then try again",
        )?;
        let mine = hex::encode(crypto::hash(&bytes));
        let state = self.org.as_mut().expect("organization state set");
        state.roster_hash = mine.clone();
        state.roster = Some(r.clone());
        state.roster_history.insert(seq, (r, mine));
        Self::trim_history(state);
        self.save_org()
    }

    fn trim_history(state: &mut OrgState) {
        while state.roster_history.len() > 8 {
            let first = *state.roster_history.keys().next().expect("non-empty");
            state.roster_history.remove(&first);
        }
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
            roster_seq: state.roster_seq(),
        };
        let se = SignedLogEntry::seal(
            &e,
            &self.vault.vault_id,
            self.key_epoch(),
            self.current_vault_key(),
            &self.keys.signer,
        )?;
        let bytes = serde_json::to_vec(&se)?;
        self.org_claim(
            |attempt| SignedLogEntry::storage_key(&me, seq, attempt),
            |_| false,
            &bytes,
            "",
        )?;
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
            roster_seq: 0,
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
        let me = self.vault.device_id.clone();
        match roster.member(&info.device) {
            // Listed but never joined (the token was lost): a new token,
            // the roster stays as it is.
            Some(m) if !self.devices.devices.contains_key(&info.device) && m.user == user => {}
            Some(_) => bail!("this device is already in the organization"),
            None => {
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
            }
        }
        let o = self.org.as_ref().expect("organization");
        let approval = Approval {
            bundle: self.pairing_bundle()?,
            org_id: o.org_id.clone(),
            root_pubkey_hex: o.root_pubkey_hex.clone(),
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
        if home.join("vault.json").exists() {
            bail!("{} already holds a vault", home.display());
        }
        // Pin the organization before anything is read from the storages:
        // a manifest chain under another root key is then never adopted.
        std::fs::create_dir_all(home)?;
        if !approval.org_id.is_empty() {
            OrgState {
                org_id: approval.org_id.clone(),
                name: approval.org_name.clone(),
                root_pubkey_hex: approval.root_pubkey_hex.clone(),
                ..OrgState::default()
            }
            .save(home)?;
        }
        let joined = Self::join_paired_with(
            home,
            device_name,
            passphrase,
            &approval.bundle,
            Some(signer),
        );
        let (engine, notes) = match joined {
            Ok(j) => j,
            Err(e) => {
                let _ = std::fs::remove_file(home.join(org::STATE_FILE));
                return Err(e);
            }
        };
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
        // Like `revoke_device`: the newest ledger (for the cut-offs) and
        // registry (for who stays) first.
        self.pull_ledger()?;
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
                former_admin: !o.is_admin(&e.issuer),
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
    /// "only an admin revokes" uses the newest admin list, and again after
    /// a new key epoch is adopted.
    pub(super) fn sync_org(&mut self) -> Result<()> {
        if self.vault.member || self.removal.is_some() {
            return Ok(());
        }
        let open = self.org_storages()?;
        let storages: Vec<&dyn Storage> = open.iter().map(|(_, b)| b.as_ref()).collect();
        let mut state = self.org.clone().unwrap_or_default();
        let mut changed = false;

        // Manifests: contiguous from the one after the newest held; the
        // first one pins the root key.
        let listing = Self::org_listing(&storages, MANIFEST_PREFIX)?;
        loop {
            let want = state.manifest_seq() + 1;
            let mut adopted = false;
            for (_, hash, blob) in Self::org_candidates(&storages, &listing, MANIFEST_PREFIX, want)?
            {
                let Some(m) = self.try_manifest(&state, want, &blob) else {
                    continue;
                };
                if state.org_id.is_empty() {
                    state.org_id = m.org_id.clone();
                    state.root_pubkey_hex = m.root_pubkey_hex.clone();
                }
                state.manifest_hash = hash;
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
        if state.org_id.is_empty() {
            return Ok(());
        }

        // Rosters. First: did the newest roster this device holds (maybe
        // its own) win its sequence number? The storages decide (name
        // order, see `org::object_name`); if another one sorts first, step
        // back one and adopt that.
        let listing = Self::org_listing(&storages, ROSTER_PREFIX)?;
        let newest = state.roster_seq();
        if newest > 0 {
            let before = match state.roster_history.get(&(newest - 1)).cloned() {
                Some((r, h)) => Some((Some(r), h)),
                None if newest == 1 => Some((None, String::new())),
                None => None,
            };
            if let Some((roster, hash)) = before {
                let mut before_state = state.clone();
                before_state.roster = roster;
                before_state.roster_hash = hash;
                let winner = Self::org_candidates(&storages, &listing, ROSTER_PREFIX, newest)?
                    .into_iter()
                    .find_map(|(_, hash, blob)| {
                        self.try_roster(&before_state, newest, &blob)
                            .map(|r| (r, hash))
                    });
                if let Some((r, hash)) = winner {
                    if hash != state.roster_hash {
                        state.roster = Some(r.clone());
                        state.roster_hash = hash.clone();
                        state.roster_history.insert(newest, (r, hash));
                        changed = true;
                    }
                }
            }
        }
        loop {
            let want = state.roster_seq() + 1;
            let mut adopted = false;
            for (_, hash, blob) in Self::org_candidates(&storages, &listing, ROSTER_PREFIX, want)? {
                let Some(r) = self.try_roster(&state, want, &blob) else {
                    continue;
                };
                state.roster_hash = hash.clone();
                state.roster = Some(r.clone());
                state.roster_history.insert(want, (r, hash));
                Self::trim_history(&mut state);
                changed = true;
                adopted = true;
                break;
            }
            if !adopted {
                break;
            }
        }

        // Log entries: one chain per device that is or was an administrator.
        let listing = Self::org_listing(&storages, LOG_PREFIX)?;
        let mut issuers: BTreeSet<DeviceId> = BTreeSet::new();
        for names in &listing {
            for k in names {
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
            let prefix = format!("{LOG_PREFIX}{issuer}/");
            loop {
                let want = state
                    .log
                    .get(&issuer)
                    .and_then(|m| m.keys().next_back().copied())
                    .unwrap_or(0)
                    + 1;
                let Ok(want32) = u32::try_from(want) else {
                    break;
                };
                let mut adopted = false;
                for (_, hash, blob) in Self::org_candidates(&storages, &listing, &prefix, want32)? {
                    let Some(e) = self.try_log(&state, &issuer, &pk, want, &blob) else {
                        continue;
                    };
                    state.log_hashes.insert(issuer.clone(), hash);
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
