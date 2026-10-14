// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Shared folders (F-047) beyond the token: confirming who asked for a
//! share, removing members, and the per-folder key epochs that make a
//! removal stick (`docs/spec/alpha-0-format.md` section 23).
//!
//! - **Fingerprint.** A request code carries the requester's hybrid KEM key
//!   and, optionally, a name. Both sides derive six words from the two; the
//!   owner compares them with the requester over another channel (a call,
//!   in person) before the token is sealed, so a code swapped on the way is
//!   noticed. The sealed token carries the words the owner confirmed, and the
//!   recipient's device checks them against its own request.
//! - **Share epochs.** Removing a member (or revoking a token that was not
//!   accepted yet) gives the folder a new random key, a *share epoch*. New
//!   chunks, manifests, member records and member ledger batches use it. The
//!   owner's devices receive it under the folder-record key, members that
//!   stay through a grant sealed to their KEM key. The epoch record, readable
//!   with the new key only, links back to every older key of the folder and
//!   lists who keeps access and the ledger cut-off of who left.
//!
//! Share epoch numbers start at [`SHARE_EPOCH_BASE`], far above the vault key
//! epochs of section 21, so the two never collide in a chunk reference.

use crate::crypto::{self, SecretKey, SigningKey, VerifyingKey};
use crate::ids::{DeviceId, FolderId, VaultId};
use crate::kem::{DecapsKey, EncapsKey};
use crate::record::{self, RecordKind, SignedRecord};
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// First share epoch of a folder; later ones count up from here.
pub const SHARE_EPOCH_BASE: u32 = 1 << 20;

/// `vault/share-epochs/<folder>/<epoch>.enc`: the epoch record, under the new key.
pub const EPOCH_PREFIX: &str = "vault/share-epochs/";
/// `vault/share-keys/<folder>/<epoch>.enc`: the epoch key for the owner's devices.
pub const KEY_PREFIX: &str = "vault/share-keys/";
/// `vault/share-grants/<folder>/<epoch>/<recipient>/<issuer>.json`: the epoch
/// key for one member, sealed by one of the owner's devices.
pub const GRANT_PREFIX: &str = "vault/share-grants/";
/// `vault/share-members/<folder>/<epoch>/<device>.enc`: member records written
/// under a share epoch's registry key (epoch-0 records stay in `vault/shares/`).
pub const MEMBER_PREFIX: &str = "vault/share-members/";
/// `vault/share-kem/<folder>/<device>.json`: a member's KEM key, signed by it.
pub const KEM_PREFIX: &str = "vault/share-kem/";
/// `vault/share-invites/<folder>/<invite>.enc`: a token the owner issued.
pub const INVITE_PREFIX: &str = "vault/share-invites/";

/// Number of words in a request fingerprint (11 bits each, 66 bits).
pub const FINGERPRINT_WORDS: usize = 6;

/// Six BIP-39 English words derived from a request's KEM key and the name
/// bound to it. Independent of the format version, so two users on
/// different versions see the same words.
pub fn fingerprint(ek: &EncapsKey, name: &str) -> String {
    let mut ikm = Vec::new();
    for part in [ek.to_bytes().as_slice(), name.trim().as_bytes()] {
        ikm.extend_from_slice(&(part.len() as u32).to_le_bytes());
        ikm.extend_from_slice(part);
    }
    let h = blake3::derive_key("varsto share-request fingerprint v1", &ikm);
    let words = bip39::Language::English.word_list();
    let mut bits: u128 = 0;
    for b in &h[..9] {
        bits = (bits << 8) | *b as u128;
    }
    // 72 bits read; use the top 66.
    (0..FINGERPRINT_WORDS)
        .map(|i| {
            let idx = (bits >> (72 - 11 * (i + 1))) & 0x7ff;
            words[idx as usize]
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Compare a fingerprint typed or pasted by a person with the expected one
/// (case, spacing and punctuation do not matter).
pub fn fingerprint_matches(expected: &str, given: &str) -> bool {
    let norm = |s: &str| {
        s.split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(|w| w.to_ascii_lowercase())
            .collect::<Vec<_>>()
    };
    let (a, b) = (norm(expected), norm(given));
    !a.is_empty() && a == b
}

/// Identity of a request key: used to tie a member device (whose KEM key is
/// its request key) to the invitation the owner issued for it.
pub fn invite_id(ek: &EncapsKey) -> String {
    hex::encode(&crypto::hash(&ek.to_bytes())[..16])
}

/// A token the owner issued, so that the owner's devices can list
/// invitations that were not accepted yet and revoke them. Sealed under the
/// folder-record key (owner devices only).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteRecord {
    pub folder: FolderId,
    /// `invite_id` of the request key, or a random id for a plain token.
    pub invite: String,
    /// The request code's KEM key (hex); empty for a plain token.
    #[serde(default)]
    pub request_hex: String,
    /// Name the requester bound to the code, if any.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub fingerprint: String,
    pub issuer: DeviceId,
    pub issued_utc: i64,
    /// The role the token gives (editor for tokens issued before roles).
    #[serde(default)]
    pub role: ShareRole,
    /// The secret inside the sealed token from which the member derives
    /// its join proof (hex; empty for a plain token).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub join_secret_hex: String,
}

impl InviteRecord {
    pub fn storage_key(folder: &FolderId, invite: &str) -> String {
        format!("{INVITE_PREFIX}{folder}/{invite}.enc")
    }
    fn aad(vault: &VaultId, folder: &FolderId, invite: &str) -> Vec<u8> {
        crypto::aad(
            "share-invite",
            &[
                vault.as_str().as_bytes(),
                folder.as_str().as_bytes(),
                invite.as_bytes(),
            ],
        )
    }
    pub fn seal(&self, vault: &VaultId, key: &SecretKey) -> Result<Vec<u8>> {
        crypto::encrypt(
            key,
            &Self::aad(vault, &self.folder, &self.invite),
            &serde_json::to_vec(self)?,
        )
    }
    pub fn open(
        blob: &[u8],
        vault: &VaultId,
        folder: &FolderId,
        invite: &str,
        key: &SecretKey,
    ) -> Result<Self> {
        let plain = crypto::decrypt(key, &Self::aad(vault, folder, invite), blob)?;
        let r: InviteRecord = serde_json::from_slice(&plain)?;
        if &r.folder != folder || r.invite != invite {
            bail!("invite record does not match its name");
        }
        Ok(r)
    }
    pub fn request_key(&self) -> Option<EncapsKey> {
        EncapsKey::from_bytes(&hex::decode(&self.request_hex).ok()?).ok()
    }
}

/// A member removed when a share epoch began.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemovedMember {
    pub device: DeviceId,
    pub name: String,
    /// Highest ledger batch of the member that stays valid.
    pub cutoff_seq: u64,
}

/// The record of one share epoch of a folder, encrypted under a key derived
/// from that epoch's folder key: only holders of the new key read it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareEpochRecord {
    pub folder: FolderId,
    pub epoch: u32,
    pub issuer: DeviceId,
    pub issued_utc: i64,
    /// Every earlier folder key except the epoch-0 key (hex by epoch): the
    /// share epochs before this one and, for a folder that was re-keyed with
    /// the vault key, its vault-epoch keys.
    pub older: BTreeMap<u32, String>,
    /// Devices that keep access: the owner's full devices and the members
    /// that stay.
    pub participants: Vec<DeviceId>,
    /// The owner's devices among them: members accept grants of later
    /// epochs only from these.
    #[serde(default)]
    pub owners: Vec<DeviceId>,
    pub removed: Vec<RemovedMember>,
    /// Invitations (tokens not accepted yet) that this epoch revoked.
    #[serde(default)]
    pub revoked_invites: Vec<String>,
    /// Invitations still open: they get a grant addressed to the invitation.
    #[serde(default)]
    pub kept_invites: Vec<String>,
}

impl ShareEpochRecord {
    pub fn storage_key(folder: &FolderId, epoch: u32) -> String {
        format!("{EPOCH_PREFIX}{folder}/{epoch:010}.enc")
    }
    fn key(epoch_key: &SecretKey, folder: &FolderId) -> SecretKey {
        epoch_key.derive("share-epoch-record", &[folder.as_str().as_bytes()])
    }
    fn key_id(epoch: u32) -> String {
        format!("share@{epoch}")
    }
    /// Seal under the epoch's key and sign by the issuer: a signed record
    /// of kind `share-epoch` (format 2), scope the folder, sequence number
    /// the epoch. Grants of the epoch pin its `body_hash`.
    pub fn seal(
        &self,
        vault: &VaultId,
        epoch_key: &SecretKey,
        signer: &SigningKey,
    ) -> Result<SignedRecord> {
        let key_id = Self::key_id(self.epoch);
        record::Header {
            kind: RecordKind::ShareEpoch,
            vault,
            scope: self.folder.as_str(),
            device: &self.issuer,
            seq: self.epoch as u64,
            key_id: &key_id,
        }
        .seal(
            &Self::key(epoch_key, &self.folder),
            &Zeroizing::new(serde_json::to_vec(self)?),
            signer,
        )
    }
    /// Open a stored share epoch record with the epoch's key. The caller
    /// checks the issuer's signature (`SignedRecord::verify`) with the key
    /// of a device it knows to be one of the owner's, and the record's
    /// `body_hash` against the grant that brought the key.
    pub fn open(
        blob: &[u8],
        vault: &VaultId,
        folder: &FolderId,
        epoch: u32,
        epoch_key: &SecretKey,
    ) -> Result<(Self, SignedRecord)> {
        let env = SignedRecord::parse(blob)?;
        env.expect(
            &record::Expect::new(RecordKind::ShareEpoch, vault)
                .scope(folder.as_str())
                .seq(epoch as u64),
        )?;
        if env.key_id != Self::key_id(epoch) {
            bail!("share epoch record names another key");
        }
        let plain = Zeroizing::new(env.open(&Self::key(epoch_key, folder))?);
        let r: ShareEpochRecord = serde_json::from_slice(&plain)?;
        if &r.folder != folder || r.epoch != epoch || r.issuer != env.device {
            bail!("share epoch record does not match its name");
        }
        Ok((r, env))
    }
}

/// A share epoch key for the owner's own devices, sealed under the
/// folder-record key of the vault.
pub struct ShareKeyRecord;

impl ShareKeyRecord {
    pub fn storage_key(folder: &FolderId, epoch: u32) -> String {
        format!("{KEY_PREFIX}{folder}/{epoch:010}.enc")
    }
    fn aad(vault: &VaultId, folder: &FolderId, epoch: u32) -> Vec<u8> {
        crypto::aad(
            "share-key",
            &[
                vault.as_str().as_bytes(),
                folder.as_str().as_bytes(),
                &epoch.to_le_bytes(),
            ],
        )
    }
    pub fn seal(
        vault: &VaultId,
        folder: &FolderId,
        epoch: u32,
        epoch_key: &SecretKey,
        record_key: &SecretKey,
    ) -> Result<Vec<u8>> {
        crypto::encrypt(
            record_key,
            &Self::aad(vault, folder, epoch),
            epoch_key.as_bytes(),
        )
    }
    pub fn open(
        blob: &[u8],
        vault: &VaultId,
        folder: &FolderId,
        epoch: u32,
        record_key: &SecretKey,
    ) -> Result<SecretKey> {
        let k = Zeroizing::new(crypto::decrypt(
            record_key,
            &Self::aad(vault, folder, epoch),
            blob,
        )?);
        SecretKey::from_bytes(&k)
    }
}

/// Parse `<epoch, 10 digits>.enc` or `<epoch>/...` names.
pub fn epoch_from_name(name: &str) -> Option<u32> {
    let head = name.split('/').next()?;
    head.strip_suffix(".enc").unwrap_or(head).parse().ok()
}

/// A share epoch key sealed to one member's KEM key (or to the request key of
/// an invitation not accepted yet), signed by the owner device that sealed
/// it: a signed record of kind `grant` (format 2), scope the folder, writer
/// the issuer, sequence number the epoch, key id `kem:<recipient>`. The
/// body carries the key and the `body_hash` of the epoch's record, which
/// the recipient requires the record it adopts to have.
#[derive(Clone, Debug)]
pub struct ShareGrant {
    pub folder: FolderId,
    pub epoch: u32,
    /// A device id, or `inv-<invite id>`.
    pub recipient: String,
    pub issuer: DeviceId,
    pub record: SignedRecord,
}

/// What a share grant's sealed body holds.
#[derive(Serialize, Deserialize)]
struct GrantBody {
    key_hex: String,
    /// `body_hash` of the epoch's signed record.
    epoch_record_hash: String,
}

impl Drop for GrantBody {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key_hex.zeroize();
    }
}

impl Serialize for ShareGrant {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        self.record.serialize(s)
    }
}

impl<'de> Deserialize<'de> for ShareGrant {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let record = SignedRecord::deserialize(d)?;
        ShareGrant::from_record(record).map_err(serde::de::Error::custom)
    }
}

impl ShareGrant {
    pub fn storage_key(
        folder: &FolderId,
        epoch: u32,
        recipient: &str,
        issuer: &DeviceId,
    ) -> String {
        format!("{GRANT_PREFIX}{folder}/{epoch:010}/{recipient}/{issuer}.json")
    }
    fn from_record(record: SignedRecord) -> Result<Self> {
        if record.kind != RecordKind::Grant || record.scope.is_empty() {
            bail!("not a share grant");
        }
        let recipient = record
            .key_id
            .strip_prefix(record::KEM_KEY_PREFIX)
            .ok_or_else(|| anyhow!("grant is not sealed to a key-exchange key"))?
            .to_string();
        Ok(ShareGrant {
            folder: FolderId::from_hex(&record.scope)?,
            epoch: u32::try_from(record.seq)?,
            recipient,
            issuer: record.device.clone(),
            record,
        })
    }
    /// Check the issuer's signature only.
    pub fn verify(&self, vault: &VaultId, issuer_key: &VerifyingKey) -> Result<()> {
        if &self.record.vault != vault {
            bail!("grant of another vault");
        }
        self.record.verify(issuer_key)
    }
    pub fn invite_recipient(invite: &str) -> String {
        format!("inv-{invite}")
    }
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        vault: &VaultId,
        folder: &FolderId,
        epoch: u32,
        recipient: &str,
        to: &EncapsKey,
        key: &SecretKey,
        epoch_record_hash: &str,
        issuer: &DeviceId,
        signer: &SigningKey,
    ) -> Result<Self> {
        let key_id = record::kem_key_id(recipient);
        let body = GrantBody {
            key_hex: key.to_hex(),
            epoch_record_hash: epoch_record_hash.to_string(),
        };
        let record = record::Header {
            kind: RecordKind::Grant,
            vault,
            scope: folder.as_str(),
            device: issuer,
            seq: epoch as u64,
            key_id: &key_id,
        }
        .seal_to(to, &Zeroizing::new(serde_json::to_vec(&body)?), signer)?;
        Self::from_record(record)
    }
    /// Check the issuer's signature and open with the recipient's KEM key:
    /// the key and the hash of the epoch record it belongs to.
    pub fn open(
        &self,
        vault: &VaultId,
        issuer_key: &VerifyingKey,
        dk: &DecapsKey,
    ) -> Result<(SecretKey, String)> {
        self.verify(vault, issuer_key)?;
        let plain = Zeroizing::new(
            self.record
                .open_sealed(dk)
                .map_err(|_| anyhow!("share grant does not open with this device's key"))?,
        );
        let body: GrantBody = serde_json::from_slice(&plain)?;
        Ok((
            SecretKey::from_hex(&body.key_hex)?,
            body.epoch_record_hash.clone(),
        ))
    }
}

/// `vault/share-roles/<folder>/<seq, 10 digits>-<issuer>.json`: who of a
/// shared folder's members may write, signed by one of the owner's devices.
pub const ROLE_PREFIX: &str = "vault/share-roles/";
/// `vault/share-join/<folder>/<device>.json`: a member's proof that it opened
/// the token of one invitation (so the owner knows which role it was given).
pub const JOIN_PREFIX: &str = "vault/share-join/";

/// What a member of a shared folder may do. The owner's devices always write.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ShareRole {
    /// Reads and writes (every member before roles existed).
    #[default]
    Editor,
    /// Reads only: nothing it publishes for the folder is accepted.
    Viewer,
}

impl ShareRole {
    pub fn parse(s: &str) -> Result<ShareRole> {
        match s.trim().to_ascii_lowercase().as_str() {
            "editor" | "write" | "read-write" | "rw" => Ok(ShareRole::Editor),
            "viewer" | "read" | "read-only" | "ro" => Ok(ShareRole::Viewer),
            other => bail!("unknown role {other}: use viewer or editor"),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            ShareRole::Editor => "editor",
            ShareRole::Viewer => "viewer",
        }
    }
    pub fn is_editor(&self) -> bool {
        *self == ShareRole::Editor
    }
}

/// The role of one member device in a role record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleEntry {
    pub role: ShareRole,
    /// The member's name when the entry was written (shown only).
    #[serde(default)]
    pub name: String,
    /// When this role was given.
    pub since_utc: i64,
    /// A viewer that was an editor before: its changes up to this Lamport
    /// clock (as named in file versions) were accepted then and stay so.
    #[serde(default)]
    pub editor_until_clock: u64,
    /// Likewise its ledger batches up to this sequence number.
    #[serde(default)]
    pub editor_until_seq: u64,
}

/// Every member's role in a shared folder: a snapshot, not a delta. The
/// valid record with the highest sequence number is the truth (ties: the
/// later `issued_utc`, then the larger issuer id). Once a folder has one,
/// a member it does not list is a viewer: the owner's devices list a new
/// member under the role of its invitation once they see its join proof.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShareRoles {
    pub folder: FolderId,
    pub seq: u64,
    pub issuer: DeviceId,
    pub issued_utc: i64,
    /// The newest share epoch when the record was written.
    #[serde(default)]
    pub share_epoch: u32,
    /// By member device id.
    pub roles: BTreeMap<DeviceId, RoleEntry>,
}

impl ShareRoles {
    /// Ordering of two valid records of a folder: larger wins.
    pub fn rank(&self) -> (u64, i64, DeviceId) {
        (self.seq, self.issued_utc, self.issuer.clone())
    }
}

/// A role record as stored: the body encrypted under a key derived from the
/// folder key of share epoch `epoch` (0: the folder key), signed by the
/// issuing owner device over its place and the ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedShareRoles {
    pub format_version: u16,
    pub folder: FolderId,
    pub seq: u64,
    pub issuer: DeviceId,
    pub epoch: u32,
    pub body_hex: String,
    pub sig_alg: String,
    pub sig_hex: String,
}

impl SignedShareRoles {
    pub fn storage_key(folder: &FolderId, seq: u64, issuer: &DeviceId) -> String {
        format!("{ROLE_PREFIX}{folder}/{seq:010}-{issuer}.json")
    }
    /// (seq, issuer) of a name under `vault/share-roles/<folder>/`.
    pub fn parse_name(name: &str) -> Option<(u64, DeviceId)> {
        let stem = name.strip_suffix(".json")?;
        let (seq, issuer) = stem.split_once('-')?;
        Some((seq.parse().ok()?, DeviceId::from_hex(issuer).ok()?))
    }
    fn key(epoch_key: &SecretKey, folder: &FolderId) -> SecretKey {
        epoch_key.derive("share-roles", &[folder.as_str().as_bytes()])
    }
    fn aad(vault: &VaultId, folder: &FolderId, seq: u64, issuer: &DeviceId, epoch: u32) -> Vec<u8> {
        crypto::aad(
            "share-roles",
            &[
                vault.as_str().as_bytes(),
                folder.as_str().as_bytes(),
                &seq.to_le_bytes(),
                issuer.as_str().as_bytes(),
                &epoch.to_le_bytes(),
            ],
        )
    }
    fn message(&self, vault: &VaultId) -> Result<Vec<u8>> {
        let body = hex::decode(&self.body_hex)?;
        Ok(crypto::aad(
            "share-roles-signature",
            &[
                vault.as_str().as_bytes(),
                self.folder.as_str().as_bytes(),
                &self.seq.to_le_bytes(),
                self.issuer.as_str().as_bytes(),
                &self.epoch.to_le_bytes(),
                &crypto::hash(&body),
            ],
        ))
    }
    pub fn seal(
        roles: &ShareRoles,
        vault: &VaultId,
        epoch: u32,
        epoch_key: &SecretKey,
        signer: &SigningKey,
    ) -> Result<Self> {
        let body = crypto::encrypt(
            &Self::key(epoch_key, &roles.folder),
            &Self::aad(vault, &roles.folder, roles.seq, &roles.issuer, epoch),
            &serde_json::to_vec(roles)?,
        )?;
        let mut s = SignedShareRoles {
            format_version: crate::FORMAT_VERSION,
            folder: roles.folder.clone(),
            seq: roles.seq,
            issuer: roles.issuer.clone(),
            epoch,
            body_hex: hex::encode(body),
            sig_alg: signer.alg().to_string(),
            sig_hex: String::new(),
        };
        s.sig_hex = hex::encode(signer.sign(&s.message(vault)?));
        Ok(s)
    }
    /// Check the issuer's signature, then open with the folder key of the
    /// envelope's epoch. The body must agree with the envelope.
    pub fn open(
        &self,
        vault: &VaultId,
        issuer_key: &VerifyingKey,
        epoch_key: &SecretKey,
    ) -> Result<ShareRoles> {
        issuer_key.verify(
            &self.sig_alg,
            &self.message(vault)?,
            &hex::decode(&self.sig_hex)?,
        )?;
        let plain = crypto::decrypt(
            &Self::key(epoch_key, &self.folder),
            &Self::aad(vault, &self.folder, self.seq, &self.issuer, self.epoch),
            &hex::decode(&self.body_hex)?,
        )?;
        let r: ShareRoles = serde_json::from_slice(&plain)?;
        if r.folder != self.folder || r.seq != self.seq || r.issuer != self.issuer {
            bail!("share role record does not match its envelope");
        }
        Ok(r)
    }
}

/// A member's proof that it holds the token of invitation `invite`:
/// `derive(join secret, "share-join-proof", folder, device)`. The join secret
/// travels only inside the sealed token and in the owner's invitation
/// record, so nobody else can tie a device to an invitation (and its role).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinProof {
    pub folder: FolderId,
    pub device: DeviceId,
    pub invite: String,
    pub proof_hex: String,
}

impl JoinProof {
    pub fn storage_key(folder: &FolderId, device: &DeviceId) -> String {
        format!("{JOIN_PREFIX}{folder}/{device}.json")
    }
    pub fn proof(secret: &SecretKey, folder: &FolderId, device: &DeviceId) -> String {
        secret
            .derive(
                "share-join-proof",
                &[folder.as_str().as_bytes(), device.as_str().as_bytes()],
            )
            .to_hex()
    }
    pub fn make(secret: &SecretKey, folder: &FolderId, device: &DeviceId, invite: &str) -> Self {
        JoinProof {
            folder: folder.clone(),
            device: device.clone(),
            invite: invite.to_string(),
            proof_hex: Self::proof(secret, folder, device),
        }
    }
    pub fn verify(&self, secret: &SecretKey) -> bool {
        crypto::ct_eq(
            Self::proof(secret, &self.folder, &self.device).as_bytes(),
            self.proof_hex.as_bytes(),
        )
    }
}

/// The ledger key id of a member's batches for a folder: `share:<folder>`
/// under the epoch-0 key, `share:<folder>@<epoch>` under a share epoch.
pub fn ledger_key_id(folder: &FolderId, epoch: u32) -> String {
    if epoch == 0 {
        crate::vault::share_key_id(folder)
    } else {
        format!("share:{folder}@{epoch}")
    }
}

/// Inverse of [`ledger_key_id`].
pub fn parse_ledger_key_id(id: &str) -> Option<(FolderId, u32)> {
    let rest = id.strip_prefix("share:")?;
    let (fid, epoch) = match rest.split_once('@') {
        Some((f, e)) => (f, e.parse().ok()?),
        None => (rest, 0),
    };
    Some((FolderId::from_hex(fid).ok()?, epoch))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_binds_key_and_name() {
        let dk = DecapsKey::generate();
        let ek = dk.public();
        let a = fingerprint(&ek, "Alice");
        assert_eq!(a.split(' ').count(), FINGERPRINT_WORDS);
        assert_eq!(a, fingerprint(&ek, " Alice "));
        assert_ne!(a, fingerprint(&ek, "Mallory"));
        assert_ne!(a, fingerprint(&DecapsKey::generate().public(), "Alice"));
        assert!(fingerprint_matches(&a, &a.to_uppercase().replace(' ', "-")));
        assert!(!fingerprint_matches(&a, ""));
    }

    #[test]
    fn grant_opens_only_for_its_recipient_and_issuer() {
        let vault = VaultId::random();
        let folder = FolderId::random();
        let signer = SigningKey::generate();
        let issuer = crate::ledger::device_id_for(&signer.public());
        let dk = DecapsKey::generate();
        let key = SecretKey::random();
        let g = ShareGrant::seal(
            &vault,
            &folder,
            SHARE_EPOCH_BASE,
            "abc",
            &dk.public(),
            &key,
            "record-hash",
            &issuer,
            &signer,
        )
        .unwrap();
        let (k, h) = g.open(&vault, &signer.public(), &dk).unwrap();
        assert_eq!(k.to_hex(), key.to_hex());
        assert_eq!(h, "record-hash");
        assert!(g
            .open(&vault, &SigningKey::generate().public(), &dk)
            .is_err());
        assert!(g
            .open(&vault, &signer.public(), &DecapsKey::generate())
            .is_err());
        // Relabelled for another recipient: the signature no longer holds.
        let mut moved = g.clone();
        moved.record.key_id = crate::record::kem_key_id("other");
        let moved: ShareGrant =
            serde_json::from_slice(&serde_json::to_vec(&moved).unwrap()).unwrap();
        assert_eq!(moved.recipient, "other");
        assert!(moved.open(&vault, &signer.public(), &dk).is_err());
    }

    #[test]
    fn share_epoch_records_are_signed_by_their_issuer() {
        let vault = VaultId::random();
        let folder = FolderId::random();
        let owner = SigningKey::generate();
        let key = SecretKey::random();
        let r = ShareEpochRecord {
            folder: folder.clone(),
            epoch: SHARE_EPOCH_BASE,
            issuer: crate::ledger::device_id_for(&owner.public()),
            issued_utc: 1,
            older: BTreeMap::new(),
            participants: vec![],
            owners: vec![],
            removed: vec![],
            revoked_invites: vec![],
            kept_invites: vec![],
        };
        let blob = r.seal(&vault, &key, &owner).unwrap().to_bytes();
        let (back, env) =
            ShareEpochRecord::open(&blob, &vault, &folder, SHARE_EPOCH_BASE, &key).unwrap();
        env.verify(&owner.public()).unwrap();
        assert_eq!(back.issuer, r.issuer);
        // A member holding the key writes its own record under the same
        // name: it opens, but it is signed by the member, not an owner.
        let member = SigningKey::generate();
        let mut forged = r.clone();
        forged.issuer = crate::ledger::device_id_for(&member.public());
        forged.owners = vec![forged.issuer.clone()];
        let blob = forged.seal(&vault, &key, &member).unwrap().to_bytes();
        let (_, env) =
            ShareEpochRecord::open(&blob, &vault, &folder, SHARE_EPOCH_BASE, &key).unwrap();
        assert!(env.verify(&owner.public()).is_err());
        assert_ne!(env.device, r.issuer);
    }

    #[test]
    fn ledger_key_ids_round_trip() {
        let f = FolderId::random();
        assert_eq!(
            parse_ledger_key_id(&ledger_key_id(&f, 0)),
            Some((f.clone(), 0))
        );
        assert_eq!(
            parse_ledger_key_id(&ledger_key_id(&f, SHARE_EPOCH_BASE + 2)),
            Some((f, SHARE_EPOCH_BASE + 2))
        );
        assert_eq!(parse_ledger_key_id("ledger"), None);
    }
}
