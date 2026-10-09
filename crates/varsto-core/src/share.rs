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
    fn aad(vault: &VaultId, folder: &FolderId, epoch: u32) -> Vec<u8> {
        crypto::aad(
            "share-epoch-record",
            &[
                vault.as_str().as_bytes(),
                folder.as_str().as_bytes(),
                &epoch.to_le_bytes(),
            ],
        )
    }
    pub fn seal(&self, vault: &VaultId, epoch_key: &SecretKey) -> Result<Vec<u8>> {
        crypto::encrypt(
            &Self::key(epoch_key, &self.folder),
            &Self::aad(vault, &self.folder, self.epoch),
            &Zeroizing::new(serde_json::to_vec(self)?),
        )
    }
    pub fn open(
        blob: &[u8],
        vault: &VaultId,
        folder: &FolderId,
        epoch: u32,
        epoch_key: &SecretKey,
    ) -> Result<Self> {
        let plain = Zeroizing::new(crypto::decrypt(
            &Self::key(epoch_key, folder),
            &Self::aad(vault, folder, epoch),
            blob,
        )?);
        let r: ShareEpochRecord = serde_json::from_slice(&plain)?;
        if &r.folder != folder || r.epoch != epoch {
            bail!("share epoch record does not match its name");
        }
        Ok(r)
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
/// an invitation not accepted yet), signed by the owner device that sealed it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareGrant {
    pub format_version: u16,
    pub folder: FolderId,
    pub epoch: u32,
    /// A device id, or `inv-<invite id>`.
    pub recipient: String,
    pub issuer: DeviceId,
    pub kem_alg: String,
    pub kem_ct_hex: String,
    pub sealed_hex: String,
    pub sig_alg: String,
    pub sig_hex: String,
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
    /// Check the issuer's signature only.
    pub fn verify(&self, vault: &VaultId, issuer_key: &VerifyingKey) -> Result<()> {
        issuer_key.verify(
            &self.sig_alg,
            &self.message(vault),
            &hex::decode(&self.sig_hex)?,
        )
    }
    pub fn invite_recipient(invite: &str) -> String {
        format!("inv-{invite}")
    }
    fn aad(&self, vault: &VaultId) -> Vec<u8> {
        crypto::aad(
            "share-grant",
            &[
                vault.as_str().as_bytes(),
                self.folder.as_str().as_bytes(),
                &self.epoch.to_le_bytes(),
                self.recipient.as_bytes(),
                self.issuer.as_str().as_bytes(),
            ],
        )
    }
    fn message(&self, vault: &VaultId) -> Vec<u8> {
        crypto::aad(
            "share-grant-signature",
            &[
                vault.as_str().as_bytes(),
                self.folder.as_str().as_bytes(),
                &self.epoch.to_le_bytes(),
                self.recipient.as_bytes(),
                self.issuer.as_str().as_bytes(),
                self.kem_alg.as_bytes(),
                self.kem_ct_hex.as_bytes(),
                self.sealed_hex.as_bytes(),
            ],
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        vault: &VaultId,
        folder: &FolderId,
        epoch: u32,
        recipient: &str,
        to: &EncapsKey,
        key: &SecretKey,
        issuer: &DeviceId,
        signer: &SigningKey,
    ) -> Result<Self> {
        let (kem_ct, shared) = to.encapsulate()?;
        let mut g = ShareGrant {
            format_version: crate::FORMAT_VERSION,
            folder: folder.clone(),
            epoch,
            recipient: recipient.to_string(),
            issuer: issuer.clone(),
            kem_alg: crate::kem::KEM_ALG.to_string(),
            kem_ct_hex: hex::encode(kem_ct),
            sealed_hex: String::new(),
            sig_alg: signer.alg().to_string(),
            sig_hex: String::new(),
        };
        g.sealed_hex = hex::encode(crypto::encrypt(&shared, &g.aad(vault), &key.0)?);
        g.sig_hex = hex::encode(signer.sign(&g.message(vault)));
        Ok(g)
    }
    /// Check the issuer's signature and open with the recipient's KEM key.
    pub fn open(
        &self,
        vault: &VaultId,
        issuer_key: &VerifyingKey,
        dk: &DecapsKey,
    ) -> Result<SecretKey> {
        if self.kem_alg != crate::kem::KEM_ALG {
            bail!("unsupported key encapsulation algorithm {}", self.kem_alg);
        }
        issuer_key.verify(
            &self.sig_alg,
            &self.message(vault),
            &hex::decode(&self.sig_hex)?,
        )?;
        let shared = dk.decapsulate(&hex::decode(&self.kem_ct_hex)?)?;
        let key = Zeroizing::new(
            crypto::decrypt(&shared, &self.aad(vault), &hex::decode(&self.sealed_hex)?)
                .map_err(|_| anyhow!("share grant does not open with this device's key"))?,
        );
        SecretKey::from_bytes(&key)
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
        let issuer = DeviceId::random();
        let signer = SigningKey::generate();
        let dk = DecapsKey::generate();
        let key = SecretKey::random();
        let g = ShareGrant::seal(
            &vault,
            &folder,
            SHARE_EPOCH_BASE,
            "abc",
            &dk.public(),
            &key,
            &issuer,
            &signer,
        )
        .unwrap();
        assert_eq!(
            g.open(&vault, &signer.public(), &dk).unwrap().to_hex(),
            key.to_hex()
        );
        assert!(g
            .open(&vault, &SigningKey::generate().public(), &dk)
            .is_err());
        assert!(g
            .open(&vault, &signer.public(), &DecapsKey::generate())
            .is_err());
        let mut moved = g.clone();
        moved.recipient = "other".into();
        assert!(moved.open(&vault, &signer.public(), &dk).is_err());
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
