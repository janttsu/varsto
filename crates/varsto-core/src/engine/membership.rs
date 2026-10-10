// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Device revocation, vault key epochs and remote wipe
//! (`docs/spec/alpha-0-format.md` section 20).
//!
//! Every full device holds the vault key, and every shared vault key
//! (ledger, registry, folder records, peer authentication) is derived from
//! it. Removing a device therefore starts a new *vault key epoch*:
//!
//! 1. the revoking device signs a revocation record for the device (with a
//!    ledger cut-off and an optional wipe order) and publishes it under the
//!    epoch-0 registry key, so the revoked device can still read it;
//! 2. it creates a random vault key for the new epoch, publishes an epoch
//!    record encrypted under that key (the previous key, the devices that
//!    stay, the folders that keep their key) and adopts it;
//! 3. it seals the new key to each remaining device's published hybrid KEM
//!    key (X25519 + ML-KEM-768), signed with its device key ("grant").
//!
//! Other devices pick the grant up on their next sync, check the issuer's
//! signature and the chain back to the key they hold, and adopt it. Every
//! later write (ledger batches, records, manifests, chunks of folders that
//! are re-keyed) uses keys the revoked device never had. What it already
//! held stays readable to it: nothing can recall a key.

use super::*;
use crate::crypto::{SigningKey, VerifyingKey};
use crate::kem::{DecapsKey, EncapsKey};
use zeroize::Zeroizing;

/// `vault/kem/<device>.json`: a device's KEM public key, signed by the device.
pub const KEM_PREFIX: &str = "vault/kem/";
/// `vault/revocations/<revoked device>/<issuer>.json`.
pub const REVOCATION_PREFIX: &str = "vault/revocations/";
/// `vault/epochs/<epoch, 8 digits>.enc`, encrypted under that epoch's key.
pub const EPOCH_PREFIX: &str = "vault/epochs/";
/// `vault/grants/<epoch>/<device>/<issuer>.json`: an epoch key sealed to one device.
pub const GRANT_PREFIX: &str = "vault/grants/";

const VAULT_KEYS_FILE: &str = "vault-keys.enc";
const REMOVED_FILE: &str = "removed.json";
const WIPED_FILE: &str = "wiped.json";

// ----- local key epochs ----------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
struct EpochFile {
    keys: BTreeMap<u32, String>,
    #[serde(default)]
    kem_hex: String,
    #[serde(default)]
    members: BTreeSet<DeviceId>,
    #[serde(default)]
    frozen: BTreeSet<FolderId>,
}

/// The vault keys of every epoch this device knows, its KEM key pair, and
/// what the newest epoch record said. Stored in `vault-keys.enc` under a key
/// derived from the device's own root key (like the local keyring).
pub(crate) struct VaultEpochs {
    pub(crate) keys: BTreeMap<u32, SecretKey>,
    pub(crate) kem: Option<DecapsKey>,
    /// Full devices the newest epoch record kept (empty at epoch 0).
    pub(crate) members: BTreeSet<DeviceId>,
    /// Folders that keep writing under their epoch-0 key (shared with other
    /// users, or Strongroom).
    pub(crate) frozen: BTreeSet<FolderId>,
    /// Whether this process already made sure the KEM record is published.
    kem_published: bool,
}

impl VaultEpochs {
    /// A vault that was never re-keyed: epoch 0 is the vault key itself.
    pub(crate) fn genesis(vault_key: &SecretKey) -> Self {
        VaultEpochs {
            keys: BTreeMap::from([(0, vault_key.clone())]),
            kem: Some(DecapsKey::generate()),
            members: BTreeSet::new(),
            frozen: BTreeSet::new(),
            kem_published: false,
        }
    }

    pub(crate) fn current(&self) -> u32 {
        self.keys.keys().next_back().copied().unwrap_or(0)
    }

    fn file_key(keys: &Keys) -> SecretKey {
        keys.master.derive("local-vault-keys", &[])
    }

    fn aad(vault: &VaultId, device: &DeviceId) -> Vec<u8> {
        crypto::aad(
            "local-vault-keys",
            &[vault.as_str().as_bytes(), device.as_str().as_bytes()],
        )
    }

    /// Devices from before key epochs existed have no file: their vault key
    /// is the epoch-0 key, and a KEM key is created on first use.
    pub(crate) fn load(
        home: &Path,
        keys: &Keys,
        vault: &VaultId,
        device: &DeviceId,
    ) -> Result<Self> {
        let p = home.join(VAULT_KEYS_FILE);
        if !p.exists() {
            let mut e = Self::genesis(&keys.master);
            e.kem = None;
            return Ok(e);
        }
        let plain = Zeroizing::new(
            crypto::decrypt(
                &Self::file_key(keys),
                &Self::aad(vault, device),
                &fs::read(&p)?,
            )
            .context("open vault-keys.enc")?,
        );
        let f: EpochFile = serde_json::from_slice(&plain)?;
        let mut keys_out = BTreeMap::new();
        for (e, hex) in &f.keys {
            keys_out.insert(*e, SecretKey::from_hex(hex)?);
        }
        if keys_out.is_empty() {
            keys_out.insert(0, keys.master.clone());
        }
        Ok(VaultEpochs {
            keys: keys_out,
            kem: if f.kem_hex.is_empty() {
                None
            } else {
                Some(DecapsKey::from_bytes(&hex::decode(&f.kem_hex)?)?)
            },
            members: f.members,
            frozen: f.frozen,
            kem_published: false,
        })
    }

    pub(crate) fn save(
        &self,
        home: &Path,
        keys: &Keys,
        vault: &VaultId,
        device: &DeviceId,
    ) -> Result<()> {
        let f = EpochFile {
            keys: self.keys.iter().map(|(e, k)| (*e, k.to_hex())).collect(),
            kem_hex: self
                .kem
                .as_ref()
                .map(|k| hex::encode(k.to_bytes()))
                .unwrap_or_default(),
            members: self.members.clone(),
            frozen: self.frozen.clone(),
        };
        let plain = Zeroizing::new(serde_json::to_vec(&f)?);
        let blob = crypto::encrypt(&Self::file_key(keys), &Self::aad(vault, device), &plain)?;
        util::write_atomic(&home.join(VAULT_KEYS_FILE), &blob)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                home.join(VAULT_KEYS_FILE),
                fs::Permissions::from_mode(0o600),
            )?;
        }
        Ok(())
    }
}

// ----- published objects ----------------------------------------------------

fn sig_message(kind: &str, fields: &[&[u8]]) -> Vec<u8> {
    crypto::aad(kind, fields)
}

/// A device's hybrid KEM public key, signed with its device key so that no
/// one else (not even a holder of the vault key) can substitute it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KemRecord {
    pub format_version: u16,
    pub device: DeviceId,
    pub kem_alg: String,
    pub public_hex: String,
    pub sig_alg: String,
    pub sig_hex: String,
}

impl KemRecord {
    pub fn storage_key(device: &DeviceId) -> String {
        format!("{KEM_PREFIX}{device}.json")
    }
    fn message(vault: &VaultId, device: &DeviceId, alg: &str, public_hex: &str) -> Vec<u8> {
        sig_message(
            "kem-record",
            &[
                vault.as_str().as_bytes(),
                device.as_str().as_bytes(),
                alg.as_bytes(),
                public_hex.as_bytes(),
            ],
        )
    }
    pub fn sign(vault: &VaultId, device: &DeviceId, ek: &EncapsKey, signer: &SigningKey) -> Self {
        let public_hex = hex::encode(ek.to_bytes());
        let sig = signer.sign(&Self::message(
            vault,
            device,
            crate::kem::KEM_ALG,
            &public_hex,
        ));
        KemRecord {
            format_version: crate::FORMAT_VERSION,
            device: device.clone(),
            kem_alg: crate::kem::KEM_ALG.to_string(),
            public_hex,
            sig_alg: signer.alg().to_string(),
            sig_hex: hex::encode(sig),
        }
    }
    pub fn verify(&self, vault: &VaultId, pk: &VerifyingKey) -> Result<EncapsKey> {
        if self.kem_alg != crate::kem::KEM_ALG {
            bail!("unsupported key encapsulation algorithm {}", self.kem_alg);
        }
        pk.verify(
            &self.sig_alg,
            &Self::message(vault, &self.device, &self.kem_alg, &self.public_hex),
            &hex::decode(&self.sig_hex)?,
        )?;
        EncapsKey::from_bytes(&hex::decode(&self.public_hex)?)
    }
}

/// What a revocation says (encrypted inside `SignedRevocation`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Revocation {
    /// The device that is removed.
    pub device: DeviceId,
    pub device_name: String,
    /// The device that removed it.
    pub issuer: DeviceId,
    pub issued_utc: i64,
    /// Highest ledger batch of the removed device that stays valid.
    pub cutoff_seq: u64,
    /// Remote wipe: the removed device deletes its keys, state and folder
    /// contents when it next reaches a storage.
    pub wipe: bool,
    /// The vault key epoch this revocation started.
    pub new_epoch: u32,
}

/// A revocation as stored: the body is encrypted under the registry key of
/// `key_epoch` (always 0 when written by this version, so every device that
/// ever belonged to the vault can read it, the removed one included), and
/// the issuer signs the device ids, the epoch and the ciphertext hash.
/// Storage cannot forge, alter or move one: the AEAD and the signature fail.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedRevocation {
    pub format_version: u16,
    pub device: DeviceId,
    pub issuer: DeviceId,
    pub key_epoch: u32,
    pub body_hex: String,
    pub sig_alg: String,
    pub sig_hex: String,
}

impl SignedRevocation {
    pub fn storage_key(device: &DeviceId, issuer: &DeviceId) -> String {
        format!("{REVOCATION_PREFIX}{device}/{issuer}.json")
    }
    fn aad(vault: &VaultId, device: &DeviceId, issuer: &DeviceId) -> Vec<u8> {
        crypto::aad(
            "revocation",
            &[
                vault.as_str().as_bytes(),
                device.as_str().as_bytes(),
                issuer.as_str().as_bytes(),
            ],
        )
    }
    fn message(
        vault: &VaultId,
        device: &DeviceId,
        issuer: &DeviceId,
        key_epoch: u32,
        body_hash: &[u8],
    ) -> Vec<u8> {
        sig_message(
            "revocation-signature",
            &[
                vault.as_str().as_bytes(),
                device.as_str().as_bytes(),
                issuer.as_str().as_bytes(),
                &key_epoch.to_le_bytes(),
                body_hash,
            ],
        )
    }
    /// Seal and sign. `registry_key` is the device-registry key of `key_epoch`.
    pub fn seal(
        rev: &Revocation,
        vault: &VaultId,
        key_epoch: u32,
        registry_key: &SecretKey,
        signer: &SigningKey,
    ) -> Result<Self> {
        let ct = crypto::encrypt(
            registry_key,
            &Self::aad(vault, &rev.device, &rev.issuer),
            &serde_json::to_vec(rev)?,
        )?;
        let sig = signer.sign(&Self::message(
            vault,
            &rev.device,
            &rev.issuer,
            key_epoch,
            &crypto::hash(&ct),
        ));
        Ok(SignedRevocation {
            format_version: crate::FORMAT_VERSION,
            device: rev.device.clone(),
            issuer: rev.issuer.clone(),
            key_epoch,
            body_hex: hex::encode(ct),
            sig_alg: signer.alg().to_string(),
            sig_hex: hex::encode(sig),
        })
    }
    /// Verify the issuer's signature, then decrypt.
    pub fn open(
        &self,
        vault: &VaultId,
        registry_key: &SecretKey,
        issuer_key: &VerifyingKey,
    ) -> Result<Revocation> {
        let ct = hex::decode(&self.body_hex)?;
        issuer_key.verify(
            &self.sig_alg,
            &Self::message(
                vault,
                &self.device,
                &self.issuer,
                self.key_epoch,
                &crypto::hash(&ct),
            ),
            &hex::decode(&self.sig_hex)?,
        )?;
        let plain = crypto::decrypt(
            registry_key,
            &Self::aad(vault, &self.device, &self.issuer),
            &ct,
        )?;
        let rev: Revocation = serde_json::from_slice(&plain)?;
        if rev.device != self.device || rev.issuer != self.issuer {
            bail!("revocation body does not match its envelope");
        }
        Ok(rev)
    }
}

/// The record of one vault key epoch, encrypted under a key derived from
/// that epoch's vault key: only holders of the new key can write or read it.
/// It links back to the previous key, so the current key opens the whole
/// history (a device joining later reads old data with it).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EpochRecord {
    pub epoch: u32,
    pub previous_hex: String,
    pub issuer: DeviceId,
    pub issued_utc: i64,
    /// Full devices that stay in the vault (they get the new key).
    pub members: Vec<DeviceId>,
    /// Devices removed when this epoch began.
    pub revoked: Vec<DeviceId>,
    /// Folders that keep their epoch-0 key (shared folders, Strongroom).
    pub frozen: Vec<FolderId>,
}

impl EpochRecord {
    pub fn storage_key(epoch: u32) -> String {
        format!("{EPOCH_PREFIX}{epoch:08}.enc")
    }
    fn key(vault_key: &SecretKey) -> SecretKey {
        vault_key.derive("epoch-record", &[])
    }
    fn aad(vault: &VaultId, epoch: u32) -> Vec<u8> {
        crypto::aad(
            "epoch-record",
            &[vault.as_str().as_bytes(), &epoch.to_le_bytes()],
        )
    }
    pub fn seal(&self, vault: &VaultId, vault_key: &SecretKey) -> Result<Vec<u8>> {
        crypto::encrypt(
            &Self::key(vault_key),
            &Self::aad(vault, self.epoch),
            &Zeroizing::new(serde_json::to_vec(self)?),
        )
    }
    pub fn open(blob: &[u8], vault: &VaultId, epoch: u32, vault_key: &SecretKey) -> Result<Self> {
        let plain = Zeroizing::new(crypto::decrypt(
            &Self::key(vault_key),
            &Self::aad(vault, epoch),
            blob,
        )?);
        let rec: EpochRecord = serde_json::from_slice(&plain)?;
        if rec.epoch != epoch {
            bail!("epoch record does not match its name");
        }
        Ok(rec)
    }
}

/// A vault key of one epoch sealed to one device's KEM key and signed by
/// the device that sealed it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub format_version: u16,
    pub epoch: u32,
    pub device: DeviceId,
    pub issuer: DeviceId,
    pub kem_alg: String,
    pub kem_ct_hex: String,
    pub sealed_hex: String,
    pub sig_alg: String,
    pub sig_hex: String,
}

impl Grant {
    pub fn storage_key(epoch: u32, device: &DeviceId, issuer: &DeviceId) -> String {
        format!("{GRANT_PREFIX}{epoch:08}/{device}/{issuer}.json")
    }
    fn aad(vault: &VaultId, epoch: u32, device: &DeviceId, issuer: &DeviceId) -> Vec<u8> {
        crypto::aad(
            "epoch-grant",
            &[
                vault.as_str().as_bytes(),
                &epoch.to_le_bytes(),
                device.as_str().as_bytes(),
                issuer.as_str().as_bytes(),
            ],
        )
    }
    fn message(&self, vault: &VaultId) -> Vec<u8> {
        sig_message(
            "epoch-grant-signature",
            &[
                vault.as_str().as_bytes(),
                &self.epoch.to_le_bytes(),
                self.device.as_str().as_bytes(),
                self.issuer.as_str().as_bytes(),
                self.kem_alg.as_bytes(),
                self.kem_ct_hex.as_bytes(),
                self.sealed_hex.as_bytes(),
            ],
        )
    }
    pub fn seal(
        vault: &VaultId,
        epoch: u32,
        device: &DeviceId,
        to: &EncapsKey,
        key: &SecretKey,
        issuer: &DeviceId,
        signer: &SigningKey,
    ) -> Result<Self> {
        let (kem_ct, shared) = to.encapsulate()?;
        let sealed = crypto::encrypt(&shared, &Self::aad(vault, epoch, device, issuer), &key.0)?;
        let mut g = Grant {
            format_version: crate::FORMAT_VERSION,
            epoch,
            device: device.clone(),
            issuer: issuer.clone(),
            kem_alg: crate::kem::KEM_ALG.to_string(),
            kem_ct_hex: hex::encode(kem_ct),
            sealed_hex: hex::encode(sealed),
            sig_alg: signer.alg().to_string(),
            sig_hex: String::new(),
        };
        g.sig_hex = hex::encode(signer.sign(&g.message(vault)));
        Ok(g)
    }
    pub fn verify(&self, vault: &VaultId, issuer_key: &VerifyingKey) -> Result<()> {
        if self.kem_alg != crate::kem::KEM_ALG {
            bail!("unsupported key encapsulation algorithm {}", self.kem_alg);
        }
        issuer_key.verify(
            &self.sig_alg,
            &self.message(vault),
            &hex::decode(&self.sig_hex)?,
        )
    }
    /// Check the issuer's signature and open with this device's KEM key.
    pub fn open(
        &self,
        vault: &VaultId,
        issuer_key: &VerifyingKey,
        dk: &DecapsKey,
    ) -> Result<SecretKey> {
        self.verify(vault, issuer_key)?;
        let shared = dk.decapsulate(&hex::decode(&self.kem_ct_hex)?)?;
        let key = Zeroizing::new(crypto::decrypt(
            &shared,
            &Self::aad(vault, self.epoch, &self.device, &self.issuer),
            &hex::decode(&self.sealed_hex)?,
        )?);
        SecretKey::from_bytes(&key)
    }
}

// ----- results and local markers ---------------------------------------------

/// A revocation this device accepted (kept in `devices.json`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Revoked {
    pub by: DeviceId,
    pub issued_utc: i64,
    pub cutoff_seq: u64,
    pub wipe: bool,
}

/// This device was removed from the vault (`removed.json`, or `wiped.json`
/// after a wipe; neither holds anything secret).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Removal {
    pub by: DeviceId,
    pub by_name: String,
    pub issued_utc: i64,
    pub wipe: bool,
    pub noticed_utc: i64,
}

/// Why this device no longer syncs. Returned (inside `anyhow::Error`) by
/// sync, pull and push once the device has seen its own revocation; the
/// service drops its engine when `wiped` is set.
#[derive(Clone, Debug)]
pub struct DeviceRemoved {
    pub by_name: String,
    pub issued_utc: i64,
    pub wiped: bool,
}

impl std::fmt::Display for DeviceRemoved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "this device was removed from the vault by {} on {}",
            self.by_name,
            util::format_date(self.issued_utc)
        )?;
        if self.wiped {
            write!(f, "; its keys, sync state and folder contents were wiped")?;
        } else {
            write!(f, "; it no longer syncs (reset it to start over)")?;
        }
        Ok(())
    }
}

impl std::error::Error for DeviceRemoved {}

/// The removal of this device, if one was recorded in `home` (also after a
/// wipe, when nothing else of the vault is left).
pub fn removal_notice(home: &Path) -> Option<Removal> {
    [WIPED_FILE, REMOVED_FILE]
        .iter()
        .find_map(|f| util::read_json(&home.join(f)).ok())
}

/// One device of the vault as the device list shows it.
#[derive(Clone, Debug, Serialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub name: String,
    pub enrolled_utc: i64,
    pub this_device: bool,
    pub revoked: bool,
    pub revoked_utc: Option<i64>,
    pub revoked_by: Option<String>,
    pub wipe_ordered: bool,
    /// System, model and Varsto version the device last published.
    #[serde(default)]
    pub details: Option<super::devinfo::DeviceDetails>,
    /// In an organization: the person the device belongs to, and whether
    /// it is an administrator. Absent without an organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
}

/// What `revoke_device` did.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeReport {
    pub device_id: String,
    pub name: String,
    /// Every device removed in this epoch (one, or a user's devices).
    #[serde(default)]
    pub devices: Vec<String>,
    pub key_epoch: u32,
    pub cutoff_seq: u64,
    pub wipe: bool,
    /// Devices the new vault key was sealed to.
    pub keys_sent_to: Vec<String>,
    /// Devices that have not published a key-exchange key yet: they get the
    /// new vault key from any device on its next sync after they do.
    pub keys_pending_for: Vec<String>,
    /// Folders whose new content uses new keys.
    pub folders_rekeyed: Vec<String>,
    /// Folders that keep their key (shared with other users, Strongroom).
    pub folders_not_rekeyed: Vec<String>,
}

fn epoch_from_name(name: &str) -> Option<u32> {
    name.strip_suffix(".enc").and_then(|n| n.parse().ok())
}

/// Read the record of `epoch` from the first storage where `key` opens it.
fn fetch_epoch_record(
    storages: &[&dyn Storage],
    vault: &VaultId,
    epoch: u32,
    key: &SecretKey,
) -> Result<EpochRecord> {
    for b in storages {
        if let Some(blob) = b.get(&EpochRecord::storage_key(epoch))? {
            if let Ok(rec) = EpochRecord::open(&blob, vault, epoch, key) {
                return Ok(rec);
            }
        }
    }
    bail!("the record of key epoch {epoch} is missing or does not open with its key")
}

/// From the key of `top`, walk the epoch records down to `stop` (exclusive):
/// returns the keys of epochs `stop..=top` (the key of `stop` included, from
/// the record above it), the newest record and every frozen folder.
fn walk_chain(
    storages: &[&dyn Storage],
    vault: &VaultId,
    top: u32,
    top_key: SecretKey,
    stop: u32,
) -> Result<(BTreeMap<u32, SecretKey>, EpochRecord, BTreeSet<FolderId>)> {
    let newest = fetch_epoch_record(storages, vault, top, &top_key)?;
    let mut frozen: BTreeSet<FolderId> = newest.frozen.iter().cloned().collect();
    let mut keys = BTreeMap::from([(top, top_key)]);
    let mut prev = SecretKey::from_hex(&newest.previous_hex)?;
    for e in (stop + 1..top).rev() {
        let r = fetch_epoch_record(storages, vault, e, &prev)?;
        frozen.extend(r.frozen.iter().cloned());
        keys.insert(e, prev);
        prev = SecretKey::from_hex(&r.previous_hex)?;
    }
    keys.insert(stop, prev);
    Ok((keys, newest, frozen))
}

/// The key epochs a device joining with `vault_key` gets. The key must be
/// the current one: a key from before a device was removed (an old recovery
/// kit, or the removed device's own copy) is refused.
pub(super) fn discover_epochs(
    backend: &dyn Storage,
    vault: &VaultId,
    vault_key: &SecretKey,
) -> Result<VaultEpochs> {
    let mut epochs: Vec<u32> = backend
        .list(EPOCH_PREFIX)?
        .iter()
        .filter_map(|k| k.strip_prefix(EPOCH_PREFIX).and_then(epoch_from_name))
        .collect();
    epochs.sort_unstable();
    let Some(&top) = epochs.last() else {
        return Ok(VaultEpochs::genesis(vault_key));
    };
    let storages = [backend];
    match walk_chain(&storages, vault, top, vault_key.clone(), 0) {
        Ok((keys, newest, frozen)) => {
            let mut e = VaultEpochs::genesis(vault_key);
            e.keys = keys;
            e.members = newest.members.into_iter().collect();
            e.frozen = frozen;
            Ok(e)
        }
        Err(_) => bail!(
            "this vault key does not open the vault's current keys: it is wrong, or it is from before a device was removed (the keys changed then; epoch {top}). Use the current vault key: pair from one of your devices, or print a new recovery kit there"
        ),
    }
}

/// Remove what a wipe removes inside one folder root. A root that is the
/// file system root, the user's home directory or a directory that contains
/// the device directory is too wide to empty blindly: there only the files
/// the folder state names are removed. Links are removed, never followed.
fn wipe_root(root: &Path, home: &Path, tracked: &[String]) -> u64 {
    let mut removed = 0u64;
    let user_home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    let wide = root.parent().is_none()
        || user_home.as_deref() == Some(root)
        || home.starts_with(root)
        || !root.is_absolute();
    if !wide {
        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .contents_first(true)
            .min_depth(1)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            if entry.file_type().is_dir() {
                let _ = fs::remove_dir(p);
            } else if fs::remove_file(p).is_ok() {
                removed += 1;
            }
        }
        return removed;
    }
    for rel in tracked {
        if Path::new(rel)
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            continue;
        }
        let disk = root.join(rel);
        for p in [placeholder_path(&disk), disk] {
            if fs::symlink_metadata(&p).is_ok() && fs::remove_file(&p).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

impl Engine {
    // ----- keys per epoch ---------------------------------------------------------

    /// The newest vault key epoch this device holds (0 until a device is removed).
    pub fn key_epoch(&self) -> u32 {
        self.epochs.current()
    }

    /// Epoch-0 vault key: the root of everything that must stay the same
    /// across epochs (disk pool ids, replica key, LAN beacon tag).
    pub(super) fn root_key(&self) -> &SecretKey {
        self.epochs.keys.get(&0).unwrap_or(&self.keys.master)
    }

    pub(super) fn current_vault_key(&self) -> &SecretKey {
        self.epochs
            .keys
            .values()
            .next_back()
            .unwrap_or(&self.keys.master)
    }

    /// Device-registry keys of every epoch, newest first (with the epoch).
    pub(super) fn registry_keys(&self) -> Vec<(u32, SecretKey)> {
        self.epochs
            .keys
            .iter()
            .rev()
            .map(|(e, k)| (*e, k.derive("device-registry", &[])))
            .collect()
    }

    pub(super) fn registry_key_now(&self) -> SecretKey {
        self.current_vault_key().derive("device-registry", &[])
    }

    /// Folder-record keys of every epoch, newest first.
    pub(super) fn folder_record_keys(&self) -> Vec<SecretKey> {
        self.epochs
            .keys
            .values()
            .rev()
            .map(|k| k.derive("folder-record", &[]))
            .collect()
    }

    pub(super) fn folder_record_key_now(&self) -> SecretKey {
        self.current_vault_key().derive("folder-record", &[])
    }

    /// Ledger key for a batch key id `ledger` (epoch 0) or `ledger@<epoch>`.
    pub(super) fn ledger_key_for(&self, id: &str) -> Option<SecretKey> {
        let epoch = if id == KEY_LEDGER {
            0
        } else {
            id.strip_prefix(ledger::KEY_LEDGER_EPOCH_PREFIX)?
                .parse()
                .ok()?
        };
        Some(self.epochs.keys.get(&epoch)?.derive("ledger", &[]))
    }

    /// Key id and key new batches are sealed with.
    pub(super) fn ledger_key_now(&self) -> (String, SecretKey) {
        let e = self.key_epoch();
        let id = if e == 0 {
            KEY_LEDGER.to_string()
        } else {
            format!("{}{e}", ledger::KEY_LEDGER_EPOCH_PREFIX)
        };
        (id, self.current_vault_key().derive("ledger", &[]))
    }

    /// Folders that keep writing under their epoch-0 key: shared with other
    /// users (members only hold that key), or Strongroom (its key is never
    /// derived from the vault key).
    pub(super) fn is_frozen(&self, rec: &FolderRecord) -> bool {
        rec.is_strongroom() || rec.shared || self.epochs.frozen.contains(&rec.folder_id)
    }

    /// The keys of a folder for every epoch this device knows. Frozen folders
    /// still read later vault epochs (a device that did not know the folder
    /// was shared may have used one) but write under epoch 0, or under the
    /// folder's newest share epoch once a member was removed (`share_ops`).
    pub(super) fn folder_keys(&self, rec: &FolderRecord) -> Result<FolderKeys> {
        let fk = rec.keys()?;
        let mut later: BTreeMap<u32, SecretKey> = BTreeMap::new();
        if !self.vault.member {
            let scope: [&[u8]; 2] = [
                self.vault.vault_id.as_str().as_bytes(),
                rec.folder_id.as_str().as_bytes(),
            ];
            later.extend(
                self.epochs
                    .keys
                    .iter()
                    .filter(|(e, _)| **e > 0)
                    .map(|(e, k)| (*e, k.derive("folder-epoch", &scope))),
            );
        }
        for (e, k) in &rec.epoch_keys {
            later.insert(*e, SecretKey::from_hex(k)?);
        }
        let share_epoch = rec
            .epoch_keys
            .keys()
            .copied()
            .filter(|e| *e >= crate::share::SHARE_EPOCH_BASE)
            .max();
        let fk = fk.with_epochs(later);
        Ok(match share_epoch {
            Some(e) => fk.write_at(e),
            None if self.vault.member || self.is_frozen(rec) => fk.write_at_base(),
            None => fk,
        })
    }

    // ----- who belongs ------------------------------------------------------------

    pub fn is_revoked(&self, device: &DeviceId) -> bool {
        self.devices.revoked.contains_key(device)
    }

    /// Whether a revocation or a new key epoch from `issuer` counts: anyone
    /// in a plain vault, administrators only in an organization.
    fn org_may_revoke(&self, issuer: &DeviceId) -> bool {
        match &self.org {
            Some(o) => o.is_admin(issuer),
            None => true,
        }
    }

    /// Whether a policy or placement record written by `device` is adopted.
    pub(super) fn org_accepts_policy_from(&self, device: &DeviceId) -> bool {
        match &self.org {
            Some(o) => o.is_admin(device) || o.policy().members_may_set_policies,
            None => true,
        }
    }

    fn org_role(&self, device: &DeviceId) -> Option<String> {
        let o = self.org.as_ref()?;
        if o.is_admin(device) {
            Some("admin".into())
        } else if o.lists(device) {
            Some("member".into())
        } else {
            None
        }
    }

    /// Devices whose revocations and grants this device acts on: known full
    /// devices that are not revoked and that the newest key epoch kept (or
    /// whose record was written under the current key). A device enrolled
    /// with an out-of-date vault key is not trusted.
    pub(super) fn trusted(&self, device: &DeviceId) -> bool {
        if device == &self.vault.device_id {
            return self.removal.is_none();
        }
        if self.is_revoked(device) || !self.devices.devices.contains_key(device) {
            return false;
        }
        // In an organization, only devices the roster lists belong.
        if let Some(o) = &self.org {
            if o.roster.is_some() && !o.lists(device) {
                return false;
            }
        }
        let cur = self.key_epoch();
        cur == 0
            || self.epochs.members.contains(device)
            || self.devices.record_epochs.get(device).copied().unwrap_or(0) >= cur
    }

    /// Whether a ledger batch counts: a revoked device's batches after its
    /// cut-off never do.
    pub(super) fn batch_accepted(&self, device: &DeviceId, seq: u64) -> bool {
        self.devices
            .revoked
            .get(device)
            .is_none_or(|r| seq <= r.cutoff_seq)
    }

    pub(super) fn device_name(&self, device: &DeviceId) -> String {
        if device == &self.vault.device_id {
            return self.vault.device_name.clone();
        }
        self.devices
            .devices
            .get(device)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| device.short().to_string())
    }

    pub(super) fn device_key(&self, device: &DeviceId) -> Option<VerifyingKey> {
        if device == &self.vault.device_id {
            return Some(self.keys.signer.public());
        }
        self.devices.devices.get(device)?.pubkey().ok()
    }

    /// The removal of this device, once it has seen it.
    pub fn removal(&self) -> Option<&Removal> {
        self.removal.as_ref()
    }

    pub(super) fn ensure_active(&self) -> Result<()> {
        match &self.removal {
            Some(r) => Err(anyhow::Error::new(DeviceRemoved {
                by_name: r.by_name.clone(),
                issued_utc: r.issued_utc,
                wiped: r.wipe,
            })),
            None => Ok(()),
        }
    }

    pub(super) fn save_epochs(&self) -> Result<()> {
        self.epochs.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )
    }

    /// Every full device of the vault this device knows, revoked ones marked.
    pub fn devices_list(&self) -> Vec<DeviceInfo> {
        let me = &self.vault.device_id;
        let mut out = vec![DeviceInfo {
            device_id: me.to_string(),
            name: self.vault.device_name.clone(),
            enrolled_utc: self
                .devices
                .devices
                .get(me)
                .map(|r| r.enrolled_utc)
                .unwrap_or(self.vault.created_utc),
            this_device: true,
            revoked: false,
            revoked_utc: None,
            revoked_by: None,
            wipe_ordered: false,
            details: self.devices.details.get(me).cloned(),
            user: self.org.as_ref().and_then(|o| o.user_of(me)),
            role: self.org_role(me),
        }];
        for (id, rec) in &self.devices.devices {
            if id == me || !(self.trusted(id) || self.is_revoked(id)) {
                continue;
            }
            let r = self.devices.revoked.get(id);
            out.push(DeviceInfo {
                device_id: id.to_string(),
                name: rec.name.clone(),
                enrolled_utc: rec.enrolled_utc,
                this_device: false,
                revoked: r.is_some(),
                revoked_utc: r.map(|r| r.issued_utc),
                revoked_by: r.map(|r| self.device_name(&r.by)),
                wipe_ordered: r.is_some_and(|r| r.wipe),
                details: self.devices.details.get(id).cloned(),
                user: self.org.as_ref().and_then(|o| o.user_of(id)),
                role: self.org_role(id),
            });
        }
        out
    }

    // ----- revoking ---------------------------------------------------------------

    /// Remove another full device from the vault: publish a signed revocation
    /// (optionally with a wipe order), start a new vault key epoch and seal the
    /// new key to every remaining device. See the module documentation for
    /// what the removed device can and cannot read afterwards.
    pub fn revoke_device(&mut self, name_or_id: &str, wipe: bool) -> Result<RevokeReport> {
        if self.vault.member {
            bail!("a member device cannot remove devices from the owner's vault");
        }
        self.ensure_active()?;
        self.pull_ledger()?;
        let me = self.vault.device_id.clone();
        let wanted = name_or_id.trim();
        if let Some(o) = &self.org {
            if !o.is_admin(&me) {
                bail!(
                    "in the organization {}, only an administrator can remove devices",
                    o.name
                );
            }
        }
        let matches: Vec<DeviceId> = self
            .devices
            .devices
            .iter()
            .chain(std::iter::once((&me, &self.own_record())))
            .filter(|(id, rec)| {
                rec.name == wanted
                    || id.as_str() == wanted
                    || (wanted.len() >= 8 && id.as_str().starts_with(wanted))
            })
            .map(|(id, _)| id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let target = match matches.as_slice() {
            [] => bail!("no device named {wanted} in this vault (see `varsto device list`)"),
            [one] => one.clone(),
            _ => bail!("several devices are named {wanted}: use the device id instead"),
        };
        if target == me {
            bail!("a device cannot remove itself: remove it from another device, or reset this one (Settings, or `varsto reset --yes`) to start over");
        }
        if self.is_revoked(&target) {
            bail!("{wanted} was already removed");
        }
        if !self.trusted(&target) {
            bail!("{wanted} is not a current device of this vault");
        }
        let report = self.revoke_many(std::slice::from_ref(&target), wipe)?;
        self.org_after_revoke(&target, wipe, report.key_epoch)?;
        Ok(report)
    }

    /// Remove several current devices in one key epoch (a user's devices).
    /// The caller has checked that they are current and not this device.
    pub(super) fn revoke_many(&mut self, targets: &[DeviceId], wipe: bool) -> Result<RevokeReport> {
        let me = self.vault.device_id.clone();
        if targets.is_empty() {
            bail!("no current device to remove");
        }
        if targets.contains(&me) {
            bail!("a device cannot remove itself");
        }
        let targets: BTreeSet<DeviceId> = targets.iter().cloned().collect();
        let remaining: Vec<DeviceId> = self
            .devices
            .devices
            .keys()
            .chain(std::iter::once(&me))
            .filter(|d| !targets.contains(d) && self.trusted(d))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if remaining.is_empty() {
            bail!("cannot remove the last full device of the vault");
        }
        // Another device may have started a newer epoch that has not reached us.
        let old = self.key_epoch();
        for (_, b) in self.metadata_storages(false)? {
            let newer = b
                .list(EPOCH_PREFIX)?
                .iter()
                .filter_map(|k| k.strip_prefix(EPOCH_PREFIX).and_then(epoch_from_name))
                .any(|e| e > old);
            if newer {
                bail!("another device changed the vault keys and this device has not received them yet; sync, then try again");
            }
        }
        let target_names: Vec<String> = targets.iter().map(|t| self.device_name(t)).collect();
        let target = targets.iter().next().cloned().expect("checked non-empty");
        let target_name = target_names[0].clone();
        let new = old + 1;
        let new_key = SecretKey::random();
        // Folders that keep their key: Strongroom, and anything shared with
        // other users (by the local flag or by member records in storage).
        let mut shared_on_storage: BTreeSet<FolderId> = BTreeSet::new();
        for (_, b) in self.metadata_storages(false)? {
            for k in b.list(SHARE_PREFIX)? {
                if let Some(f) = k
                    .strip_prefix(SHARE_PREFIX)
                    .and_then(|r| r.split('/').next())
                    .and_then(|f| FolderId::from_hex(f).ok())
                {
                    shared_on_storage.insert(f);
                }
            }
        }
        let mut frozen = self.epochs.frozen.clone();
        let (mut rekeyed, mut kept) = (Vec::new(), Vec::new());
        for rec in self.keyring.folders.values() {
            if self.is_frozen(rec) || shared_on_storage.contains(&rec.folder_id) {
                frozen.insert(rec.folder_id.clone());
                kept.push(rec.name.clone());
            } else {
                rekeyed.push(rec.name.clone());
            }
        }
        let record = EpochRecord {
            epoch: new,
            previous_hex: self.current_vault_key().to_hex(),
            issuer: me.clone(),
            issued_utc: util::now_utc(),
            members: remaining.clone(),
            revoked: targets.iter().cloned().collect(),
            frozen: frozen.iter().cloned().collect(),
        };
        let revs: Vec<Revocation> = targets
            .iter()
            .map(|t| Revocation {
                device: t.clone(),
                device_name: self.device_name(t),
                issuer: me.clone(),
                issued_utc: record.issued_utc,
                cutoff_seq: self.ledger.head(t).seq,
                wipe,
                new_epoch: new,
            })
            .collect();
        let cutoff_seq = revs[0].cutoff_seq;
        let storages = self.metadata_storages(true)?;
        if storages.is_empty() {
            bail!("this device has no storage to publish the removal to");
        }
        // The epoch record first: put-if-absent makes two concurrent
        // rotations collide here instead of splitting the vault.
        let blob = record.seal(&self.vault.vault_id, &new_key)?;
        for (i, (_, b)) in storages.iter().enumerate() {
            if !b.put_if_absent(&EpochRecord::storage_key(new), &blob)? && i == 0 {
                bail!(
                    "another device changed the vault keys at the same time; sync, then try again"
                );
            }
        }
        let epoch0 = self.root_key().derive("device-registry", &[]);
        for rev in &revs {
            let signed =
                SignedRevocation::seal(rev, &self.vault.vault_id, 0, &epoch0, &self.keys.signer)?;
            let bytes = serde_json::to_vec(&signed)?;
            for (_, b) in &storages {
                b.put_if_absent(&SignedRevocation::storage_key(&rev.device, &me), &bytes)?;
            }
            self.devices.revoked.insert(
                rev.device.clone(),
                Revoked {
                    by: me.clone(),
                    issued_utc: rev.issued_utc,
                    cutoff_seq: rev.cutoff_seq,
                    wipe,
                },
            );
        }
        self.save_devices()?;
        self.epochs.keys.insert(new, new_key);
        self.epochs.members = remaining.iter().cloned().collect();
        self.epochs.frozen = frozen;
        self.save_epochs()?;
        let (sent, pending) = self.issue_grants()?;
        self.reseal_own_peer_record();
        Ok(RevokeReport {
            device_id: target.to_string(),
            name: target_name,
            devices: target_names,
            key_epoch: new,
            cutoff_seq,
            wipe,
            keys_sent_to: sent,
            keys_pending_for: pending,
            folders_rekeyed: rekeyed,
            folders_not_rekeyed: kept,
        })
    }

    // ----- picking up changes on sync -------------------------------------------

    /// Run on every pull, before ledger batches are ingested: publish our KEM
    /// key, act on revocations (our own included), adopt new key epochs and
    /// hand the current key to devices that still lack it.
    pub(super) fn sync_membership(&mut self) -> Result<()> {
        if self.vault.member {
            return Ok(());
        }
        self.ensure_active()?;
        self.ensure_kem_record()?;
        self.sync_org()?;
        if let Some(gone) = self.pull_revocations()? {
            return Err(anyhow::Error::new(gone));
        }
        self.adopt_epochs()?;
        // Objects an admin wrote right after a rotation are sealed under
        // the epoch just adopted: read the organization once more.
        self.sync_org()?;
        self.issue_grants()?;
        Ok(())
    }

    fn kem_record(&mut self) -> Result<KemRecord> {
        if self.epochs.kem.is_none() {
            self.epochs.kem = Some(DecapsKey::generate());
            self.save_epochs()?;
        }
        let ek = self.epochs.kem.as_ref().expect("just created").public();
        Ok(KemRecord::sign(
            &self.vault.vault_id,
            &self.vault.device_id,
            &ek,
            &self.keys.signer,
        ))
    }

    /// Publish this device's KEM record where it is missing (once per process
    /// unless a storage is added).
    pub(super) fn ensure_kem_record(&mut self) -> Result<()> {
        if self.vault.member || self.removal.is_some() || self.epochs.kem_published {
            return Ok(());
        }
        let rec = self.kem_record()?;
        let key = KemRecord::storage_key(&self.vault.device_id);
        let bytes = serde_json::to_vec(&rec)?;
        for (_, b) in self.metadata_storages(true)? {
            if !b.exists(&key)? {
                b.put_if_absent(&key, &bytes)?;
            }
        }
        self.epochs.kem_published = true;
        Ok(())
    }

    pub(super) fn kem_record_stale(&mut self) {
        self.epochs.kem_published = false;
    }

    /// Accept new revocations. Returns the removal when one names this device.
    fn pull_revocations(&mut self) -> Result<Option<DeviceRemoved>> {
        let me = self.vault.device_id.clone();
        let mut seen = HashSet::new();
        let mut found: Vec<Revocation> = Vec::new();
        for (_, b) in self.metadata_storages(false)? {
            for key in b.list(REVOCATION_PREFIX)? {
                let Some((dev, issuer)) = key
                    .strip_prefix(REVOCATION_PREFIX)
                    .and_then(|r| r.strip_suffix(".json"))
                    .and_then(|r| r.split_once('/'))
                else {
                    continue;
                };
                let (Ok(dev), Ok(issuer)) = (DeviceId::from_hex(dev), DeviceId::from_hex(issuer))
                else {
                    continue;
                };
                if self.is_revoked(&dev) || !seen.insert(key.clone()) {
                    continue;
                }
                let Some(blob) = b.get(&key)? else { continue };
                let Ok(signed) = serde_json::from_slice::<SignedRevocation>(&blob) else {
                    continue;
                };
                if signed.device != dev || signed.issuer != issuer {
                    continue;
                }
                let (Some(pk), Some(k)) = (
                    self.device_key(&issuer),
                    self.epochs.keys.get(&signed.key_epoch),
                ) else {
                    continue;
                };
                let reg = k.derive("device-registry", &[]);
                if let Ok(rev) = signed.open(&self.vault.vault_id, &reg, &pk) {
                    found.push(rev);
                }
            }
        }
        // Oldest first: a device revoked earlier cannot revoke anyone later.
        found.sort_by(|a, b| (a.issued_utc, &a.issuer).cmp(&(b.issued_utc, &b.issuer)));
        let mut changed = false;
        let mut gone = None;
        for rev in found {
            if rev.issuer == rev.device
                || !self.trusted(&rev.issuer)
                || self.is_revoked(&rev.device)
                || !self.org_may_revoke(&rev.issuer)
            {
                continue;
            }
            if rev.device == me {
                let removal = Removal {
                    by: rev.issuer.clone(),
                    by_name: self.device_name(&rev.issuer),
                    issued_utc: rev.issued_utc,
                    wipe: rev.wipe,
                    noticed_utc: util::now_utc(),
                };
                util::write_json(&self.home.join(REMOVED_FILE), &removal)?;
                self.removal = Some(removal.clone());
                if rev.wipe {
                    self.wipe_this_device(&removal)?;
                }
                gone = Some(DeviceRemoved {
                    by_name: removal.by_name,
                    issued_utc: removal.issued_utc,
                    wiped: rev.wipe,
                });
                break;
            }
            self.devices.revoked.insert(
                rev.device.clone(),
                Revoked {
                    by: rev.issuer.clone(),
                    issued_utc: rev.issued_utc,
                    cutoff_seq: rev.cutoff_seq,
                    wipe: rev.wipe,
                },
            );
            changed = true;
        }
        if changed && gone.is_none() {
            self.save_devices()?;
        }
        Ok(gone)
    }

    /// Adopt the newest key epoch sealed to this device by a trusted device,
    /// after checking that its chain of epoch records leads back to the key
    /// this device holds and that the epoch keeps this device.
    fn adopt_epochs(&mut self) -> Result<()> {
        if self.epochs.kem.is_none() {
            return Ok(());
        }
        let me = self.vault.device_id.clone();
        let cur = self.key_epoch();
        let open = self.metadata_storages(false)?;
        let storages: Vec<&dyn Storage> = open.iter().map(|(_, b)| b.as_ref()).collect();
        let mut grants: BTreeMap<u32, Vec<Grant>> = BTreeMap::new();
        for b in &storages {
            for key in b.list(GRANT_PREFIX)? {
                let parts: Vec<&str> = key
                    .strip_prefix(GRANT_PREFIX)
                    .unwrap_or("")
                    .splitn(3, '/')
                    .collect();
                let [epoch, dev, _issuer] = parts.as_slice() else {
                    continue;
                };
                let Ok(epoch) = epoch.parse::<u32>() else {
                    continue;
                };
                if epoch <= cur || *dev != me.as_str() {
                    continue;
                }
                if let Some(blob) = b.get(&key)? {
                    if let Ok(g) = serde_json::from_slice::<Grant>(&blob) {
                        grants.entry(epoch).or_default().push(g);
                    }
                }
            }
        }
        let dk = self.epochs.kem.as_ref().expect("checked above");
        let mut adopted = None;
        'epochs: for (epoch, list) in grants.iter().rev() {
            for g in list {
                if g.epoch != *epoch || g.device != me || !self.trusted(&g.issuer) {
                    continue;
                }
                let Some(pk) = self.device_key(&g.issuer) else {
                    continue;
                };
                let Ok(key) = g.open(&self.vault.vault_id, &pk, dk) else {
                    continue;
                };
                let Ok((keys, newest, frozen)) =
                    walk_chain(&storages, &self.vault.vault_id, *epoch, key, cur)
                else {
                    continue;
                };
                // The chain must end at the key we hold, and the epoch must keep us.
                if keys.get(&cur).map(|k| k.0) != Some(self.current_vault_key().0)
                    || !newest.members.contains(&me)
                    || !self.org_may_revoke(&newest.issuer)
                {
                    continue;
                }
                adopted = Some((keys, newest, frozen));
                break 'epochs;
            }
        }
        drop(open);
        if let Some((keys, newest, frozen)) = adopted {
            for r in &newest.revoked {
                // The epoch record names who was removed; the signed revocation
                // (read above) carries the cut-off. Without it, cut at what we hold.
                if !self.is_revoked(r) {
                    self.devices.revoked.insert(
                        r.clone(),
                        Revoked {
                            by: newest.issuer.clone(),
                            issued_utc: newest.issued_utc,
                            cutoff_seq: self.ledger.head(r).seq,
                            wipe: false,
                        },
                    );
                    self.save_devices()?;
                }
            }
            self.epochs.keys.extend(keys);
            self.epochs.members = newest.members.into_iter().collect();
            self.epochs.frozen.extend(frozen);
            self.save_epochs()?;
            self.reseal_own_peer_record();
        }
        Ok(())
    }

    /// Seal the current vault key to every device the current epoch keeps
    /// that has no valid grant yet. Returns (sent to, still waiting for).
    fn issue_grants(&mut self) -> Result<(Vec<String>, Vec<String>)> {
        let epoch = self.key_epoch();
        let (mut sent, mut pending) = (Vec::new(), Vec::new());
        if epoch == 0 || self.removal.is_some() {
            return Ok((sent, pending));
        }
        let me = self.vault.device_id.clone();
        let prefix = format!("{GRANT_PREFIX}{epoch:08}/");
        let mut have: BTreeSet<DeviceId> = BTreeSet::new();
        let readable = self.metadata_storages(false)?;
        for (_, b) in &readable {
            for key in b.list(&prefix)? {
                let Some((dev, issuer)) = key
                    .strip_prefix(&prefix)
                    .and_then(|r| r.strip_suffix(".json"))
                    .and_then(|r| r.split_once('/'))
                else {
                    continue;
                };
                let (Ok(dev), Ok(issuer)) = (DeviceId::from_hex(dev), DeviceId::from_hex(issuer))
                else {
                    continue;
                };
                if have.contains(&dev) || !self.trusted(&issuer) {
                    continue;
                }
                // Count only grants a trusted device really signed.
                let valid = b
                    .get(&key)?
                    .and_then(|blob| serde_json::from_slice::<Grant>(&blob).ok())
                    .zip(self.device_key(&issuer))
                    .is_some_and(|(g, pk)| {
                        g.epoch == epoch
                            && g.device == dev
                            && g.verify(&self.vault.vault_id, &pk).is_ok()
                    });
                if valid {
                    have.insert(dev);
                }
            }
        }
        let key = self.current_vault_key().clone();
        let targets: Vec<DeviceId> = self
            .epochs
            .members
            .iter()
            .filter(|d| **d != me && !have.contains(*d) && self.trusted(d))
            .cloned()
            .collect();
        let storages = self.metadata_storages(true)?;
        for d in targets {
            let Some(pk) = self.device_key(&d) else {
                continue;
            };
            let mut ek = None;
            for (_, b) in &readable {
                if let Some(blob) = b.get(&KemRecord::storage_key(&d))? {
                    if let Ok(rec) = serde_json::from_slice::<KemRecord>(&blob) {
                        if rec.device == d {
                            if let Ok(k) = rec.verify(&self.vault.vault_id, &pk) {
                                ek = Some(k);
                                break;
                            }
                        }
                    }
                }
            }
            let Some(ek) = ek else {
                pending.push(self.device_name(&d));
                continue;
            };
            let g = Grant::seal(
                &self.vault.vault_id,
                epoch,
                &d,
                &ek,
                &key,
                &me,
                &self.keys.signer,
            )?;
            let bytes = serde_json::to_vec(&g)?;
            for (_, b) in &storages {
                b.put_if_absent(&Grant::storage_key(epoch, &d, &me), &bytes)?;
            }
            sent.push(self.device_name(&d));
        }
        Ok((sent, pending))
    }

    /// Re-seal our rendezvous record under the current registry key, so a
    /// removed device stops learning our addresses at once rather than at
    /// the next periodic republish.
    fn reseal_own_peer_record(&self) {
        let key = crate::p2p::PeerRecord::storage_key(&self.vault.device_id);
        let Ok(storages) = self.metadata_storages(false) else {
            return;
        };
        for (_, b) in &storages {
            let Ok(Some(blob)) = b.get(&key) else {
                continue;
            };
            for (_, k) in self.registry_keys().iter().skip(1) {
                if let Ok(rec) = crate::p2p::PeerRecord::open(
                    &blob,
                    &self.vault.vault_id,
                    &self.vault.device_id,
                    k,
                ) {
                    let _ = self.publish_peer_record(&rec);
                    return;
                }
            }
        }
    }

    // ----- remote wipe ------------------------------------------------------------

    /// Carry out a wipe order addressed to this device: empty every attached
    /// folder (see `wipe_root`), then remove the keys, keyring, secrets,
    /// ledger, sync state, trash, configuration and peer identity from the
    /// device directory. Nothing outside the folder roots and the device
    /// directory is touched, and storages are left alone. Unsynced changes
    /// on this device are lost: that is the point of wiping a lost device.
    fn wipe_this_device(&mut self, removal: &Removal) -> Result<()> {
        for m in self.config.folders.clone() {
            let tracked: Vec<String> = self
                .load_state(&m.folder_id)
                .map(|s| {
                    s.files
                        .keys()
                        .chain(s.pending_remote.keys())
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            wipe_root(&m.path, &self.home, &tracked);
        }
        reset_device(&self.home)?;
        let mut extra: Vec<PathBuf> = [
            crate::p2p::quic::CERT_FILE,
            crate::p2p::quic::KEY_FILE,
            "replica.json",
        ]
        .iter()
        .map(|f| self.home.join(f))
        .collect();
        if let Ok(rd) = fs::read_dir(&self.home) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if n.starts_with("pool-") && n.ends_with(".json") {
                    extra.push(e.path());
                }
            }
        }
        for p in extra {
            let _ = fs::remove_file(p);
        }
        util::write_json(&self.home.join(WIPED_FILE), removal)?;
        self.keyring = Keyring::default();
        self.config = Config::default();
        self.unlocked.clear();
        Ok(())
    }
}

/// Files `reset_device` removes in addition to the alpha-0 set.
pub(super) const RESET_EXTRA: [&str; 3] = [VAULT_KEYS_FILE, REMOVED_FILE, WIPED_FILE];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revocation_needs_the_issuer_signature() {
        let vault = VaultId::random();
        let key = SecretKey::random();
        let issuer = SigningKey::generate();
        let other = SigningKey::generate();
        let rev = Revocation {
            device: DeviceId::random(),
            device_name: "laptop".into(),
            issuer: ledger::device_id_for(&issuer.public()),
            issued_utc: 1,
            cutoff_seq: 3,
            wipe: true,
            new_epoch: 1,
        };
        let s = SignedRevocation::seal(&rev, &vault, 0, &key, &issuer).unwrap();
        assert_eq!(s.open(&vault, &key, &issuer.public()).unwrap(), rev);
        assert!(s.open(&vault, &key, &other.public()).is_err());
        let mut t = s.clone();
        t.key_epoch = 1;
        assert!(t.open(&vault, &key, &issuer.public()).is_err());
    }

    #[test]
    fn grant_opens_only_for_its_device_and_issuer() {
        let vault = VaultId::random();
        let issuer = SigningKey::generate();
        let dk = DecapsKey::generate();
        let dev = DeviceId::random();
        let key = SecretKey::random();
        let g = Grant::seal(
            &vault,
            2,
            &dev,
            &dk.public(),
            &key,
            &ledger::device_id_for(&issuer.public()),
            &issuer,
        )
        .unwrap();
        assert_eq!(g.open(&vault, &issuer.public(), &dk).unwrap().0, key.0);
        assert!(g
            .open(&vault, &SigningKey::generate().public(), &dk)
            .is_err());
        assert!(g
            .open(&vault, &issuer.public(), &DecapsKey::generate())
            .is_err());
        let mut moved = g.clone();
        moved.device = DeviceId::random();
        assert!(moved.open(&vault, &issuer.public(), &dk).is_err());
    }
}
