// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Organizations (`docs/spec/alpha-0-format.md` section 27): the objects
//! that let a company run one vault for many people, with administrators
//! who decide which devices belong, and nothing of it for a vault without
//! an organization.
//!
//! Three signed objects live under `org/` in every metadata storage:
//!
//! - the **manifest**, signed by the organization's root key: the admin
//!   devices. The root key is 24 words kept offline; it is used when the
//!   organization is created and whenever an admin is added or removed;
//! - the **roster**, signed by an admin device: every device of the
//!   organization with the user it belongs to, the devices removed so far,
//!   and the organization's policy (what members may do);
//! - the **log**, one hash-chained sequence per admin device: who approved,
//!   removed or changed what, and when, exportable as evidence.
//!
//! Bodies are encrypted under a key derived from the vault key of the
//! epoch named in the envelope; signatures cover the ciphertext hash, so the
//! storage can neither read nor alter them. A device accepts a manifest only
//! if it is signed by the root key it already knows (the first manifest it
//! sees pins the key), a roster only if its issuer is an admin of the
//! manifest it names, and a log entry only if its issuer is or was an admin.
//!
//! A device joins an organization through an **approval**: it prints a
//! request code (its key-exchange key and its device id), an admin compares
//! the six-word fingerprint with the person, and seals the vault key and
//! the storage settings to that code. The joining device uses the signing
//! key it made with the request, so its device id is already in the roster
//! when its first ledger batch arrives.

use crate::crypto::{self, SecretKey, SigningKey, VerifyingKey};
use crate::ids::{DeviceId, VaultId};
use crate::kem::{DecapsKey, EncapsKey};
use crate::util;
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use zeroize::Zeroizing;

/// `org/manifest/<seq, 8 digits>.json`
pub const MANIFEST_PREFIX: &str = "org/manifest/";
/// `org/roster/<seq, 8 digits>.json`
pub const ROSTER_PREFIX: &str = "org/roster/";
/// `org/log/<admin device>/<seq, 8 digits>.json`
pub const LOG_PREFIX: &str = "org/log/";
/// Request code prefix: `vor1.<kem key hex>.<device id>[.<name>]`.
pub const REQUEST_PREFIX: &str = "vor1.";
/// Approval token prefix: `vot1.<vault id>.<kem ct hex>.<sealed hex>`.
pub const TOKEN_PREFIX: &str = "vot1.";

/// The local, non-secret request file of a device waiting for approval.
pub const REQUEST_FILE: &str = "org-request.json";
/// The local cache of the organization as this device last verified it.
pub const STATE_FILE: &str = "org-state.json";

/// Object names are `<seq, 8 digits>-<attempt, 3 digits>.json`. A writer
/// claims the lowest attempt number that is free on its first storage with
/// put-if-absent, so that two writers of the same sequence number cannot
/// both succeed there, and so that a junk object someone wrote under a
/// name first (anyone with the storage credentials can) does not block the
/// sequence number: the writer moves on to the next attempt. A reader
/// takes, among the objects of one sequence number from every storage in
/// name order (ties by content hash), the first one that verifies.
pub const ATTEMPTS: u32 = 64;

pub fn object_name(seq: u32, attempt: u32) -> String {
    format!("{seq:08}-{attempt:03}.json")
}

/// Parse the sequence number from `<seq>-<attempt>.json`, `<seq>.json` or
/// `<seq>/...`.
pub fn seq_from_name(name: &str) -> Option<u32> {
    let head = name.split('/').next()?;
    let digits = head.split(['-', '.']).next()?;
    if digits.len() != 8 {
        return None;
    }
    digits.parse().ok()
}

// ----- root key -----------------------------------------------------------------

/// The organization's root signing key, derived from a 32-byte root secret
/// (the 24 words): Ed25519 and ML-DSA-65 seeds, each from its own purpose.
pub fn root_signer(root: &SecretKey) -> SigningKey {
    let ed = root.derive("org-root-ed25519", &[]);
    let pq = root.derive("org-root-ml-dsa", &[]);
    let mut bytes = Zeroizing::new(Vec::with_capacity(64));
    bytes.extend_from_slice(ed.as_bytes());
    bytes.extend_from_slice(pq.as_bytes());
    SigningKey::from_bytes(&bytes).expect("64 bytes")
}

/// The organization id: the first 16 bytes of the hash of the root public key.
pub fn org_id_for(root: &VerifyingKey) -> String {
    hex::encode(&crypto::hash(&root.to_bytes())[..16])
}

/// The root signer from the 24 words of the organization's root kit.
pub fn root_from_words(words: &str) -> Result<(SecretKey, SigningKey)> {
    let hex = crate::recovery::key_from_words(words)?;
    let root = SecretKey::from_hex(&hex)?;
    let signer = root_signer(&root);
    Ok((root, signer))
}

fn record_key(vault_key: &SecretKey) -> SecretKey {
    vault_key.derive("org-record", &[])
}

// ----- manifest -------------------------------------------------------------------

/// One admin device as the manifest lists it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Admin {
    pub device: DeviceId,
    pub name: String,
}

/// What the root key signs: who administers the organization.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub org_id: String,
    pub name: String,
    pub seq: u32,
    /// Hash (hex) of the previous signed manifest as stored; empty for seq 1.
    #[serde(default)]
    pub previous_hash: String,
    pub issued_utc: i64,
    pub root_pubkey_hex: String,
    pub admins: Vec<Admin>,
    /// The newest roster when this manifest was written: rosters and log
    /// entries after it are governed by this manifest, earlier ones by the
    /// manifest before. A dismissed administrator can therefore not keep
    /// writing by naming the manifest that still listed it.
    #[serde(default)]
    pub roster_seq: u32,
}

impl Manifest {
    pub fn root_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&hex::decode(&self.root_pubkey_hex)?)
    }
    pub fn is_admin(&self, device: &DeviceId) -> bool {
        self.admins.iter().any(|a| &a.device == device)
    }
}

/// The manifest as stored: body encrypted under the org record key of
/// `key_epoch`, signed by the root key over the envelope and the ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedManifest {
    pub format_version: u16,
    pub org_id: String,
    pub seq: u32,
    pub key_epoch: u32,
    pub body_hex: String,
    pub sig_alg: String,
    pub sig_hex: String,
}

impl SignedManifest {
    pub fn storage_key(seq: u32, attempt: u32) -> String {
        format!("{MANIFEST_PREFIX}{}", object_name(seq, attempt))
    }
    fn aad(vault: &VaultId, org_id: &str, seq: u32) -> Vec<u8> {
        crypto::aad(
            "org-manifest",
            &[
                vault.as_str().as_bytes(),
                org_id.as_bytes(),
                &seq.to_le_bytes(),
            ],
        )
    }
    fn message(
        vault: &VaultId,
        org_id: &str,
        seq: u32,
        key_epoch: u32,
        body_hash: &[u8],
    ) -> Vec<u8> {
        crypto::aad(
            "org-manifest-signature",
            &[
                vault.as_str().as_bytes(),
                org_id.as_bytes(),
                &seq.to_le_bytes(),
                &key_epoch.to_le_bytes(),
                body_hash,
            ],
        )
    }
    pub fn seal(
        m: &Manifest,
        vault: &VaultId,
        key_epoch: u32,
        vault_key: &SecretKey,
        root: &SigningKey,
    ) -> Result<Self> {
        if org_id_for(&root.public()) != m.org_id
            || m.root_pubkey_hex != hex::encode(root.public().to_bytes())
        {
            bail!("the manifest does not belong to this root key");
        }
        let ct = crypto::encrypt(
            &record_key(vault_key),
            &Self::aad(vault, &m.org_id, m.seq),
            &Zeroizing::new(serde_json::to_vec(m)?),
        )?;
        let sig = root.sign(&Self::message(
            vault,
            &m.org_id,
            m.seq,
            key_epoch,
            &crypto::hash(&ct),
        ));
        Ok(SignedManifest {
            format_version: crate::FORMAT_VERSION,
            org_id: m.org_id.clone(),
            seq: m.seq,
            key_epoch,
            body_hex: hex::encode(ct),
            sig_alg: root.alg().to_string(),
            sig_hex: hex::encode(sig),
        })
    }
    /// Decrypt, then check the root signature: with `pinned` when the device
    /// already knows the organization, otherwise with the key the body
    /// names (which must hash to the org id).
    pub fn open(
        &self,
        vault: &VaultId,
        vault_key: &SecretKey,
        pinned: Option<&VerifyingKey>,
    ) -> Result<Manifest> {
        let ct = hex::decode(&self.body_hex)?;
        let plain = Zeroizing::new(crypto::decrypt(
            &record_key(vault_key),
            &Self::aad(vault, &self.org_id, self.seq),
            &ct,
        )?);
        let m: Manifest = serde_json::from_slice(&plain)?;
        if m.org_id != self.org_id || m.seq != self.seq {
            bail!("manifest body does not match its envelope");
        }
        let root = match pinned {
            Some(k) => k.clone(),
            None => m.root_key()?,
        };
        if org_id_for(&root) != m.org_id || hex::encode(root.to_bytes()) != m.root_pubkey_hex {
            bail!("manifest names a root key that does not match the organization");
        }
        root.verify(
            &self.sig_alg,
            &Self::message(
                vault,
                &self.org_id,
                self.seq,
                self.key_epoch,
                &crypto::hash(&ct),
            ),
            &hex::decode(&self.sig_hex)?,
        )?;
        Ok(m)
    }
}

// ----- roster ---------------------------------------------------------------------

/// What members (devices that are not admins) may do on their own. Admins
/// may do everything. Defaults are the strict ones.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrgPolicy {
    /// Members may share folders with people outside the vault.
    #[serde(default)]
    pub members_may_share: bool,
    /// Members may add or remove storages on their device.
    #[serde(default)]
    pub members_may_add_storages: bool,
    /// Members may set durability policies and placement.
    #[serde(default)]
    pub members_may_set_policies: bool,
    /// Members may pair new devices and print the recovery kit (the vault
    /// key). Off: only admins hand out the key, through approvals.
    #[serde(default)]
    pub members_may_add_devices: bool,
}

/// One device of the organization.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Member {
    pub device: DeviceId,
    /// The person the device belongs to (a name or an account id chosen by
    /// the organization; never looked up anywhere).
    pub user: String,
    pub name: String,
    pub added_utc: i64,
    pub added_by: DeviceId,
}

/// A device removed from the organization.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemovedMember {
    pub device: DeviceId,
    pub user: String,
    pub name: String,
    pub removed_utc: i64,
    pub removed_by: DeviceId,
    pub wipe: bool,
}

/// What an admin signs: the devices of the organization and its policy.
/// A snapshot, not a delta: the newest valid roster is the truth.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Roster {
    pub org_id: String,
    pub seq: u32,
    #[serde(default)]
    pub previous_hash: String,
    /// The manifest that made the issuer an admin.
    pub manifest_seq: u32,
    pub issuer: DeviceId,
    pub issued_utc: i64,
    pub members: Vec<Member>,
    #[serde(default)]
    pub removed: Vec<RemovedMember>,
    #[serde(default)]
    pub policy: OrgPolicy,
}

impl Roster {
    pub fn member(&self, device: &DeviceId) -> Option<&Member> {
        self.members.iter().find(|m| &m.device == device)
    }
    pub fn users(&self) -> Vec<String> {
        let mut u: Vec<String> = self.members.iter().map(|m| m.user.clone()).collect();
        u.sort();
        u.dedup();
        u
    }
}

/// The roster as stored, signed by the admin device that issued it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedRoster {
    pub format_version: u16,
    pub org_id: String,
    pub seq: u32,
    pub key_epoch: u32,
    pub issuer: DeviceId,
    pub body_hex: String,
    pub sig_alg: String,
    pub sig_hex: String,
}

impl SignedRoster {
    pub fn storage_key(seq: u32, attempt: u32) -> String {
        format!("{ROSTER_PREFIX}{}", object_name(seq, attempt))
    }
    fn aad(vault: &VaultId, org_id: &str, seq: u32) -> Vec<u8> {
        crypto::aad(
            "org-roster",
            &[
                vault.as_str().as_bytes(),
                org_id.as_bytes(),
                &seq.to_le_bytes(),
            ],
        )
    }
    fn message(
        vault: &VaultId,
        org_id: &str,
        seq: u32,
        key_epoch: u32,
        issuer: &DeviceId,
        body_hash: &[u8],
    ) -> Vec<u8> {
        crypto::aad(
            "org-roster-signature",
            &[
                vault.as_str().as_bytes(),
                org_id.as_bytes(),
                &seq.to_le_bytes(),
                &key_epoch.to_le_bytes(),
                issuer.as_str().as_bytes(),
                body_hash,
            ],
        )
    }
    pub fn seal(
        r: &Roster,
        vault: &VaultId,
        key_epoch: u32,
        vault_key: &SecretKey,
        signer: &SigningKey,
    ) -> Result<Self> {
        let ct = crypto::encrypt(
            &record_key(vault_key),
            &Self::aad(vault, &r.org_id, r.seq),
            &Zeroizing::new(serde_json::to_vec(r)?),
        )?;
        let sig = signer.sign(&Self::message(
            vault,
            &r.org_id,
            r.seq,
            key_epoch,
            &r.issuer,
            &crypto::hash(&ct),
        ));
        Ok(SignedRoster {
            format_version: crate::FORMAT_VERSION,
            org_id: r.org_id.clone(),
            seq: r.seq,
            key_epoch,
            issuer: r.issuer.clone(),
            body_hex: hex::encode(ct),
            sig_alg: signer.alg().to_string(),
            sig_hex: hex::encode(sig),
        })
    }
    /// Verify the issuer's signature, then decrypt.
    pub fn open(
        &self,
        vault: &VaultId,
        vault_key: &SecretKey,
        issuer_key: &VerifyingKey,
    ) -> Result<Roster> {
        let ct = hex::decode(&self.body_hex)?;
        issuer_key.verify(
            &self.sig_alg,
            &Self::message(
                vault,
                &self.org_id,
                self.seq,
                self.key_epoch,
                &self.issuer,
                &crypto::hash(&ct),
            ),
            &hex::decode(&self.sig_hex)?,
        )?;
        let plain = Zeroizing::new(crypto::decrypt(
            &record_key(vault_key),
            &Self::aad(vault, &self.org_id, self.seq),
            &ct,
        )?);
        let r: Roster = serde_json::from_slice(&plain)?;
        if r.org_id != self.org_id || r.seq != self.seq || r.issuer != self.issuer {
            bail!("roster body does not match its envelope");
        }
        Ok(r)
    }
}

// ----- log ------------------------------------------------------------------------

/// What happened. Names are the device and user names at the time.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OrgEvent {
    OrgCreated {
        name: String,
        founder: String,
        devices: Vec<String>,
    },
    AdminAdded {
        device: DeviceId,
        name: String,
    },
    AdminRemoved {
        device: DeviceId,
        name: String,
    },
    DeviceApproved {
        device: DeviceId,
        user: String,
        name: String,
    },
    DeviceAdded {
        device: DeviceId,
        user: String,
        name: String,
    },
    DeviceRemoved {
        device: DeviceId,
        user: String,
        name: String,
        wipe: bool,
        key_epoch: u32,
    },
    UserRemoved {
        user: String,
        devices: Vec<String>,
        wipe: bool,
        key_epoch: u32,
    },
    PolicyChanged {
        policy: OrgPolicy,
    },
    /// An event this version does not know (written by a newer one).
    #[serde(other)]
    Unknown,
}

/// One entry of an admin device's log.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
    pub org_id: String,
    pub issuer: DeviceId,
    pub seq: u64,
    /// Hash (hex) of this issuer's previous signed entry as stored; empty for seq 1.
    #[serde(default)]
    pub previous_hash: String,
    pub utc: i64,
    pub event: OrgEvent,
    /// The newest roster when the entry was written (which manifest governs it).
    #[serde(default)]
    pub roster_seq: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedLogEntry {
    pub format_version: u16,
    pub org_id: String,
    pub issuer: DeviceId,
    pub seq: u64,
    pub key_epoch: u32,
    pub body_hex: String,
    pub sig_alg: String,
    pub sig_hex: String,
}

impl SignedLogEntry {
    pub fn storage_key(issuer: &DeviceId, seq: u64, attempt: u32) -> String {
        format!("{LOG_PREFIX}{issuer}/{seq:08}-{attempt:03}.json")
    }
    fn aad(vault: &VaultId, org_id: &str, issuer: &DeviceId, seq: u64) -> Vec<u8> {
        crypto::aad(
            "org-log",
            &[
                vault.as_str().as_bytes(),
                org_id.as_bytes(),
                issuer.as_str().as_bytes(),
                &seq.to_le_bytes(),
            ],
        )
    }
    fn message(
        vault: &VaultId,
        org_id: &str,
        issuer: &DeviceId,
        seq: u64,
        key_epoch: u32,
        body_hash: &[u8],
    ) -> Vec<u8> {
        crypto::aad(
            "org-log-signature",
            &[
                vault.as_str().as_bytes(),
                org_id.as_bytes(),
                issuer.as_str().as_bytes(),
                &seq.to_le_bytes(),
                &key_epoch.to_le_bytes(),
                body_hash,
            ],
        )
    }
    pub fn seal(
        e: &LogEntry,
        vault: &VaultId,
        key_epoch: u32,
        vault_key: &SecretKey,
        signer: &SigningKey,
    ) -> Result<Self> {
        let ct = crypto::encrypt(
            &record_key(vault_key),
            &Self::aad(vault, &e.org_id, &e.issuer, e.seq),
            &Zeroizing::new(serde_json::to_vec(e)?),
        )?;
        let sig = signer.sign(&Self::message(
            vault,
            &e.org_id,
            &e.issuer,
            e.seq,
            key_epoch,
            &crypto::hash(&ct),
        ));
        Ok(SignedLogEntry {
            format_version: crate::FORMAT_VERSION,
            org_id: e.org_id.clone(),
            issuer: e.issuer.clone(),
            seq: e.seq,
            key_epoch,
            body_hex: hex::encode(ct),
            sig_alg: signer.alg().to_string(),
            sig_hex: hex::encode(sig),
        })
    }
    pub fn open(
        &self,
        vault: &VaultId,
        vault_key: &SecretKey,
        issuer_key: &VerifyingKey,
    ) -> Result<LogEntry> {
        let ct = hex::decode(&self.body_hex)?;
        issuer_key.verify(
            &self.sig_alg,
            &Self::message(
                vault,
                &self.org_id,
                &self.issuer,
                self.seq,
                self.key_epoch,
                &crypto::hash(&ct),
            ),
            &hex::decode(&self.sig_hex)?,
        )?;
        let plain = Zeroizing::new(crypto::decrypt(
            &record_key(vault_key),
            &Self::aad(vault, &self.org_id, &self.issuer, self.seq),
            &ct,
        )?);
        let e: LogEntry = serde_json::from_slice(&plain)?;
        if e.org_id != self.org_id || e.seq != self.seq || e.issuer != self.issuer {
            bail!("log entry body does not match its envelope");
        }
        Ok(e)
    }
}

// ----- local state -----------------------------------------------------------------

/// The organization as this device last verified it (`org-state.json`,
/// nothing secret). Absent for a vault without an organization.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct OrgState {
    pub org_id: String,
    pub name: String,
    /// Pinned on first sight: later manifests must be signed by it.
    pub root_pubkey_hex: String,
    /// Every manifest accepted so far, by seq (small: one per admin change).
    pub manifests: BTreeMap<u32, Manifest>,
    pub roster: Option<Roster>,
    /// The last few rosters adopted with the hash of their bytes, by seq:
    /// a device whose own roster lost its sequence number to another
    /// administrator's (the storages decide, see `object_name`) steps back
    /// one and adopts the winner.
    #[serde(default)]
    pub roster_history: BTreeMap<u32, (Roster, String)>,
    /// Log entries accepted so far, by issuer then seq.
    #[serde(default)]
    pub log: BTreeMap<DeviceId, BTreeMap<u64, LogEntry>>,
    /// Hash of the newest stored object per chain, to extend it.
    #[serde(default)]
    pub manifest_hash: String,
    #[serde(default)]
    pub roster_hash: String,
    #[serde(default)]
    pub log_hashes: BTreeMap<DeviceId, String>,
}

impl OrgState {
    pub fn load(home: &Path) -> Option<OrgState> {
        util::read_json(&home.join(STATE_FILE)).ok()
    }
    pub fn save(&self, home: &Path) -> Result<()> {
        util::write_json(&home.join(STATE_FILE), self)
    }
    pub fn manifest(&self) -> Option<&Manifest> {
        self.manifests.values().next_back()
    }
    pub fn manifest_seq(&self) -> u32 {
        self.manifests.keys().next_back().copied().unwrap_or(0)
    }
    pub fn root_key(&self) -> Result<VerifyingKey> {
        VerifyingKey::from_bytes(&hex::decode(&self.root_pubkey_hex)?)
    }
    /// Admin of the current manifest.
    pub fn is_admin(&self, device: &DeviceId) -> bool {
        self.manifest().is_some_and(|m| m.is_admin(device))
    }
    /// The manifest in force for roster `seq`: the newest one written while
    /// the roster before `seq` was current.
    pub fn governing(&self, roster_seq: u32) -> Option<&Manifest> {
        self.manifests
            .values()
            .rev()
            .find(|m| m.roster_seq < roster_seq)
    }
    /// Whether `device` may issue roster `seq` (or a log entry written
    /// while roster `seq - 1` was current).
    pub fn governs_admin(&self, device: &DeviceId, roster_seq: u32) -> bool {
        self.governing(roster_seq)
            .is_some_and(|m| m.is_admin(device))
    }
    /// Admin of any manifest so far.
    pub fn ever_admin(&self, device: &DeviceId) -> bool {
        self.manifests.values().any(|m| m.is_admin(device))
    }
    pub fn policy(&self) -> OrgPolicy {
        self.roster
            .as_ref()
            .map(|r| r.policy.clone())
            .unwrap_or_default()
    }
    pub fn roster_seq(&self) -> u32 {
        self.roster.as_ref().map(|r| r.seq).unwrap_or(0)
    }
    /// Whether the roster lists the device (admins are listed too).
    pub fn lists(&self, device: &DeviceId) -> bool {
        self.roster
            .as_ref()
            .is_some_and(|r| r.member(device).is_some())
    }
    pub fn user_of(&self, device: &DeviceId) -> Option<String> {
        self.roster
            .as_ref()
            .and_then(|r| r.member(device).map(|m| m.user.clone()))
    }
    /// Every accepted log entry, oldest first.
    pub fn entries(&self) -> Vec<LogEntry> {
        let mut all: Vec<LogEntry> = self
            .log
            .values()
            .flat_map(|m| m.values().cloned())
            .collect();
        all.sort_by(|a, b| (a.utc, &a.issuer, a.seq).cmp(&(b.utc, &b.issuer, b.seq)));
        all
    }
}

// ----- request and approval -------------------------------------------------------

/// The local file of a device waiting for approval: its key-exchange key and
/// the signing key it will join with (both made here, so the device id in
/// the request code is the id the device gets). It is secret until the
/// device joins and is kept owner-readable only.
#[derive(Serialize, Deserialize)]
pub struct OrgRequest {
    pub kem_alg: String,
    pub kem_secret_hex: String,
    pub signer_hex: String,
    #[serde(default)]
    pub name: String,
}

/// A parsed request code.
pub struct RequestInfo {
    pub key: EncapsKey,
    pub device: DeviceId,
    pub name: String,
    pub fingerprint: String,
}

impl OrgRequest {
    fn path(home: &Path) -> std::path::PathBuf {
        home.join(REQUEST_FILE)
    }
    /// Load or create the request of `home`; `name` (the device name) is
    /// bound to the code and so to the fingerprint.
    pub fn code_for(home: &Path, name: Option<&str>) -> Result<String> {
        std::fs::create_dir_all(home)?;
        let path = Self::path(home);
        let mut r: OrgRequest = if path.exists() {
            serde_json::from_slice(&std::fs::read(&path)?)?
        } else {
            OrgRequest {
                kem_alg: crate::kem::KEM_ALG.to_string(),
                kem_secret_hex: hex::encode(DecapsKey::generate().to_bytes()),
                signer_hex: hex::encode(SigningKey::generate().to_bytes()),
                name: String::new(),
            }
        };
        if let Some(n) = name {
            let n = n.trim();
            if n.contains(['\n', '\r', '.']) {
                bail!("the device name must be on one line and must not contain a dot");
            }
            r.name = n.to_string();
        }
        // Holds the device's signing key until the approval arrives: owner
        // readable only, from the first byte.
        let tmp = path.with_extension("json.tmp");
        {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            use std::io::Write as _;
            let mut f = opts.open(&tmp)?;
            f.write_all(&serde_json::to_vec_pretty(&r)?)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        r.code()
    }
    fn code(&self) -> Result<String> {
        let dk = DecapsKey::from_bytes(&hex::decode(&self.kem_secret_hex)?)?;
        let signer = SigningKey::from_bytes(&hex::decode(&self.signer_hex)?)?;
        let device = crate::ledger::device_id_for(&signer.public());
        let mut code = format!(
            "{REQUEST_PREFIX}{}.{}",
            hex::encode(dk.public().to_bytes()),
            device
        );
        if !self.name.is_empty() {
            code.push('.');
            code.push_str(&self.name);
        }
        Ok(code)
    }
    fn load(home: &Path) -> Result<OrgRequest> {
        let path = Self::path(home);
        if !path.exists() {
            bail!(
                "no organization request in {}: run `varsto org request` there first and give its code to an administrator",
                home.display()
            );
        }
        Ok(serde_json::from_slice(&std::fs::read(&path)?)?)
    }
    /// The six words both sides compare.
    pub fn fingerprint_for(home: &Path) -> Result<String> {
        let r = Self::load(home)?;
        Ok(Self::parse(&r.code()?)?.fingerprint)
    }
    /// Key, device id, bound name and fingerprint of a request code.
    pub fn parse(code: &str) -> Result<RequestInfo> {
        let rest = code.trim().strip_prefix(REQUEST_PREFIX).ok_or_else(|| {
            anyhow!("not an organization request code (expected the vor1. prefix)")
        })?;
        let mut parts = rest.splitn(3, '.');
        let key_hex = parts.next().unwrap_or("");
        let dev = parts
            .next()
            .ok_or_else(|| anyhow!("request code has the wrong shape"))?;
        let name = parts.next().unwrap_or("").trim().to_string();
        let key = EncapsKey::from_bytes(&hex::decode(key_hex)?)?;
        let device = DeviceId::from_hex(dev)?;
        let fingerprint = crate::share::fingerprint(&key, &format!("{device} {name}"));
        Ok(RequestInfo {
            key,
            device,
            name,
            fingerprint,
        })
    }
    /// The keys of the pending request: (KEM private key, signing key).
    pub fn keys(home: &Path) -> Result<(DecapsKey, SigningKey, String)> {
        let r = Self::load(home)?;
        Ok((
            DecapsKey::from_bytes(&hex::decode(&r.kem_secret_hex)?)?,
            SigningKey::from_bytes(&hex::decode(&r.signer_hex)?)?,
            r.name,
        ))
    }
    pub fn clear(home: &Path) {
        let _ = std::fs::remove_file(Self::path(home));
    }
}

/// What an approval carries to the new device: everything a pairing bundle
/// carries, plus the organization.
#[derive(Clone, Serialize, Deserialize)]
pub struct Approval {
    pub bundle: crate::pair::Bundle,
    pub org_id: String,
    /// The root public key (hex): the joining device pins it before its
    /// first sync, so a replaced manifest chain on the storage is refused.
    #[serde(default)]
    pub root_pubkey_hex: String,
    pub org_name: String,
    pub user: String,
    pub approver: DeviceId,
    /// The fingerprint the admin confirmed; the device checks it against its own.
    pub fingerprint: String,
}

/// An approval sealed to a request code: `vot1.<vault id>.<kem ct hex>.<sealed hex>`.
#[derive(Clone, Serialize, Deserialize)]
pub struct SealedApproval {
    pub vault_id: VaultId,
    pub kem_ct_hex: String,
    pub sealed_hex: String,
}

impl SealedApproval {
    fn aad(vault: &VaultId, kem_ct_hex: &str) -> Vec<u8> {
        crypto::aad(
            "org-approval",
            &[vault.as_str().as_bytes(), kem_ct_hex.as_bytes()],
        )
    }
    pub fn seal(a: &Approval, to: &EncapsKey) -> Result<Self> {
        let vault = VaultId::from_hex(&a.bundle.vault_id)?;
        let (ct, shared) = to.encapsulate()?;
        let kem_ct_hex = hex::encode(ct);
        let sealed = crypto::encrypt(
            &shared,
            &Self::aad(&vault, &kem_ct_hex),
            &Zeroizing::new(serde_json::to_vec(a)?),
        )?;
        Ok(SealedApproval {
            vault_id: vault,
            kem_ct_hex,
            sealed_hex: hex::encode(sealed),
        })
    }
    pub fn encode(&self) -> String {
        format!(
            "{TOKEN_PREFIX}{}.{}.{}",
            self.vault_id, self.kem_ct_hex, self.sealed_hex
        )
    }
    pub fn is_token(s: &str) -> bool {
        s.trim().starts_with(TOKEN_PREFIX)
    }
    pub fn decode(s: &str) -> Result<Self> {
        let rest = s.trim().strip_prefix(TOKEN_PREFIX).ok_or_else(|| {
            anyhow!("not an organization approval token (expected the vot1. prefix)")
        })?;
        let parts: Vec<&str> = rest.splitn(3, '.').collect();
        if parts.len() != 3 {
            bail!("approval token has the wrong shape");
        }
        Ok(SealedApproval {
            vault_id: VaultId::from_hex(parts[0])?,
            kem_ct_hex: parts[1].to_string(),
            sealed_hex: parts[2].to_string(),
        })
    }
    pub fn open(&self, dk: &DecapsKey) -> Result<Approval> {
        let shared = dk.decapsulate(&hex::decode(&self.kem_ct_hex)?)?;
        let plain = Zeroizing::new(
            crypto::decrypt(
                &shared,
                &Self::aad(&self.vault_id, &self.kem_ct_hex),
                &hex::decode(&self.sealed_hex)?,
            )
            .map_err(|_| anyhow!("the approval token does not open with this device's request key: it was made for another request"))?,
        );
        let a: Approval = serde_json::from_slice(&plain)?;
        if a.bundle.vault_id != self.vault_id.to_string() {
            bail!("approval token names another vault than its envelope");
        }
        Ok(a)
    }
}

/// Open an approval token with the request kept in `home`, checking the
/// fingerprint the admin confirmed against this device's own.
pub fn open_approval(home: &Path, token: &str) -> Result<(Approval, SigningKey)> {
    let (dk, signer, name) = OrgRequest::keys(home)?;
    let a = SealedApproval::decode(token)?.open(&dk)?;
    let device = crate::ledger::device_id_for(&signer.public());
    let mine = crate::share::fingerprint(&dk.public(), &format!("{device} {name}"));
    if !a.fingerprint.is_empty() && !crate::share::fingerprint_matches(&mine, &a.fingerprint) {
        bail!(
            "the administrator confirmed the fingerprint \"{}\" but this device's request has \"{mine}\": the request code was changed on its way; ask for a new approval",
            a.fingerprint
        );
    }
    Ok((a, signer))
}

/// The printable root kit of an organization.
pub fn root_kit_text(org_name: &str, org_id: &str, root_hex: &str) -> Result<String> {
    let words = crate::recovery::words_from_key(root_hex)?;
    let numbered: Vec<String> = words
        .split(' ')
        .enumerate()
        .map(|(i, w)| format!("{:>2}. {w}", i + 1))
        .collect();
    let mut t = String::new();
    t.push_str("VARSTO ORGANIZATION ROOT KEY\n");
    t.push_str(&format!("Organization {org_name} ({org_id})\n"));
    t.push_str(
        "These 24 words are the root key of the organization. Whoever has them can appoint and remove administrators.\n",
    );
    t.push_str(
        "They are not stored on any device. Keep them on paper or metal, in more than one place, away from the vault's own recovery kit.\n",
    );
    t.push_str(
        "They are needed only for `varsto org admin add` and `varsto org admin remove`.\n\n",
    );
    for row in numbered.chunks(4) {
        t.push_str(&row.join("   "));
        t.push('\n');
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_key_is_deterministic_and_ids_follow_it() {
        let root = SecretKey::random();
        let a = root_signer(&root);
        let b = root_signer(&root);
        assert_eq!(a.public().to_bytes(), b.public().to_bytes());
        assert!(a.is_hybrid());
        let words = crate::recovery::words_from_key(&root.to_hex()).unwrap();
        let (_, c) = root_from_words(&words).unwrap();
        assert_eq!(c.public().to_bytes(), a.public().to_bytes());
        assert_eq!(org_id_for(&a.public()).len(), 32);
    }

    #[test]
    fn manifest_needs_the_root_signature_and_pins_it() {
        let vault = VaultId::random();
        let key = SecretKey::random();
        let root = root_signer(&SecretKey::random());
        let other = root_signer(&SecretKey::random());
        let m = Manifest {
            org_id: org_id_for(&root.public()),
            name: "Acme".into(),
            seq: 1,
            previous_hash: String::new(),
            issued_utc: 1,
            root_pubkey_hex: hex::encode(root.public().to_bytes()),
            admins: vec![Admin {
                device: DeviceId::random(),
                name: "hq".into(),
            }],
            roster_seq: 0,
        };
        let s = SignedManifest::seal(&m, &vault, 0, &key, &root).unwrap();
        assert_eq!(s.open(&vault, &key, None).unwrap(), m);
        assert_eq!(s.open(&vault, &key, Some(&root.public())).unwrap(), m);
        assert!(s.open(&vault, &key, Some(&other.public())).is_err());
        assert!(s.open(&vault, &SecretKey::random(), None).is_err());
        // A manifest sealed by another root for the same org id is refused.
        assert!(SignedManifest::seal(&m, &vault, 0, &key, &other).is_err());
        let mut t = s.clone();
        t.seq = 2;
        assert!(t.open(&vault, &key, None).is_err());
    }

    #[test]
    fn roster_and_log_verify_their_issuer() {
        let vault = VaultId::random();
        let key = SecretKey::random();
        let admin = SigningKey::generate();
        let me = crate::ledger::device_id_for(&admin.public());
        let r = Roster {
            org_id: "a".repeat(32),
            seq: 1,
            previous_hash: String::new(),
            manifest_seq: 1,
            issuer: me.clone(),
            issued_utc: 1,
            members: vec![],
            removed: vec![],
            policy: OrgPolicy::default(),
        };
        let s = SignedRoster::seal(&r, &vault, 0, &key, &admin).unwrap();
        assert_eq!(s.open(&vault, &key, &admin.public()).unwrap(), r);
        assert!(s
            .open(&vault, &key, &SigningKey::generate().public())
            .is_err());
        let e = LogEntry {
            org_id: r.org_id.clone(),
            issuer: me,
            seq: 1,
            previous_hash: String::new(),
            utc: 2,
            event: OrgEvent::PolicyChanged {
                policy: OrgPolicy::default(),
            },
            roster_seq: 1,
        };
        let s = SignedLogEntry::seal(&e, &vault, 0, &key, &admin).unwrap();
        assert_eq!(s.open(&vault, &key, &admin.public()).unwrap(), e);
        let mut t = s.clone();
        t.key_epoch = 1;
        assert!(t.open(&vault, &key, &admin.public()).is_err());
    }

    #[test]
    fn object_names_carry_the_sequence_number() {
        assert_eq!(seq_from_name("00000007-001.json"), Some(7));
        assert_eq!(seq_from_name("00000007.json"), Some(7));
        assert_eq!(seq_from_name("7.json"), None);
        assert_eq!(seq_from_name("junk"), None);
        assert_eq!(
            SignedRoster::storage_key(3, 2),
            "org/roster/00000003-002.json"
        );
        let d = DeviceId::random();
        assert_eq!(
            SignedLogEntry::storage_key(&d, 12, 1),
            format!("org/log/{d}/00000012-001.json")
        );
    }

    #[test]
    fn request_code_and_approval_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("new");
        let code = OrgRequest::code_for(&home, Some("phone")).unwrap();
        let info = OrgRequest::parse(&code).unwrap();
        assert_eq!(info.name, "phone");
        assert_eq!(info.fingerprint.split(' ').count(), 6);
        assert_eq!(
            OrgRequest::fingerprint_for(&home).unwrap(),
            info.fingerprint
        );
        // The same request, renamed: same device id, other fingerprint.
        let code2 = OrgRequest::code_for(&home, Some("tablet")).unwrap();
        let info2 = OrgRequest::parse(&code2).unwrap();
        assert_eq!(info2.device, info.device);
        assert_ne!(info2.fingerprint, info.fingerprint);
        let a = Approval {
            bundle: crate::pair::Bundle {
                vault_id: VaultId::random().to_string(),
                vault_key: SecretKey::random().to_hex(),
                from: "hq".into(),
                storages: vec![],
            },
            org_id: "b".repeat(32),
            root_pubkey_hex: String::new(),
            org_name: "Acme".into(),
            user: "dana".into(),
            approver: DeviceId::random(),
            fingerprint: info2.fingerprint.clone(),
        };
        let token = SealedApproval::seal(&a, &info2.key).unwrap().encode();
        assert!(SealedApproval::is_token(&token));
        let (opened, signer) = open_approval(&home, &token).unwrap();
        assert_eq!(opened.user, "dana");
        assert_eq!(crate::ledger::device_id_for(&signer.public()), info.device);
        // A token for another request does not open here.
        let other = tempfile::tempdir().unwrap();
        OrgRequest::code_for(other.path(), Some("x")).unwrap();
        assert!(open_approval(other.path(), &token).is_err());
        // A token whose fingerprint names another request is refused.
        let mut b = a.clone();
        b.fingerprint = info.fingerprint.clone();
        let t2 = SealedApproval::seal(&b, &info2.key).unwrap().encode();
        assert!(open_approval(&home, &t2).is_err());
    }
}
