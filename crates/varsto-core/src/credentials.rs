// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The reminder to change a storage key after a device is removed.
//!
//! Varsto does not call the provider. Removing a device still leaves the
//! old key able to delete ciphertext until the user creates a new key,
//! enters it on every remaining device, and only then disables the old one.
//! What each device publishes is a statement: a hash of the S3 secret it
//! holds (never the secret) and, separately, that someone disabled the old
//! key. An rclone remote has no hash here, because its credential stays in
//! rclone's configuration. A local directory or a disk pool has no key to
//! change. A network share is named once in the removal report.
//!
//! The record is kind 29 (`vault/credentials/<device>/`). A client that
//! does not know the kind never lists that prefix, so it ignores the
//! record. A removed device cannot write one.

use crate::crypto;
use crate::record::{Id16, Kind, RecordBody, RecordMeta, StreamRef};
use serde::{Deserialize, Serialize};

/// `kind` of an S3 storage in a credential record.
pub const KIND_S3: u8 = 1;
/// `kind` of an rclone remote. Its hash is always zeros.
pub const KIND_RCLONE: u8 = 2;

const MAX_NAME: usize = 256;
const MAX_DETAIL: usize = 1024;
const MAX_ENTRIES: usize = 64;
const ZERO_HASH: [u8; 32] = [0; 32];

/// The key that was stored here when a device was removed. The highest
/// `epoch` for one `storage_id` is the one that counts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    pub storage_id: String,
    pub kind: u8,
    pub name: String,
    pub detail: String,
    pub old_hash: [u8; 32],
    pub epoch: u32,
}

/// What one device says it holds now. `retired` means that device has
/// confirmed the old key is disabled at the provider. A new secret clears it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Current {
    pub storage_id: String,
    pub kind: u8,
    pub name: String,
    pub detail: String,
    pub secret_hash: [u8; 32],
    pub retired: bool,
}

/// One device's credential statement. Newest seq of the stream wins.
/// `baselines` are copied forward so a removal survives after the remover's
/// own record is no longer the only copy. `current` is only this device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialBody {
    pub device: Id16,
    pub seq: u64,
    pub epoch: u32,
    pub baselines: Vec<Baseline>,
    pub current: Vec<Current>,
}

impl RecordBody for CredentialBody {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if self.device != meta.device {
            return Err("its device is not the record's writer".into());
        }
        if self.seq != meta.seq || self.seq == 0 {
            return Err("its seq is not the record's".into());
        }
        if meta.scope != [0; 16] {
            return Err("credential records are vault-wide".into());
        }
        check_entries(&self.baselines, &self.current)?;
        Ok(())
    }
}

fn check_entries(baselines: &[Baseline], current: &[Current]) -> Result<(), String> {
    if baselines.len() > MAX_ENTRIES || current.len() > MAX_ENTRIES {
        return Err("too many storages in a credential record".into());
    }
    let mut prev = "";
    for b in baselines {
        check_row(b.kind, &b.storage_id, &b.name, &b.detail, &b.old_hash)?;
        if b.storage_id.as_str() <= prev {
            return Err("baselines are not sorted and unique".into());
        }
        prev = &b.storage_id;
    }
    prev = "";
    for c in current {
        check_row(c.kind, &c.storage_id, &c.name, &c.detail, &c.secret_hash)?;
        if c.storage_id.as_str() <= prev {
            return Err("current entries are not sorted and unique".into());
        }
        prev = &c.storage_id;
    }
    Ok(())
}

fn check_row(
    kind: u8,
    storage_id: &str,
    name: &str,
    detail: &str,
    hash: &[u8; 32],
) -> Result<(), String> {
    if storage_id.is_empty() || storage_id.len() > MAX_DETAIL {
        return Err("a storage id is empty or too long".into());
    }
    if name.len() > MAX_NAME || detail.len() > MAX_DETAIL {
        return Err("a storage name or detail is too long".into());
    }
    match kind {
        KIND_S3 => Ok(()),
        KIND_RCLONE if *hash == ZERO_HASH => Ok(()),
        KIND_RCLONE => Err("an rclone credential has no hash".into()),
        _ => Err("unknown storage kind".into()),
    }
}

/// The stream of `device`'s credential statements.
pub fn credential_stream(device: Id16) -> StreamRef {
    StreamRef::new(Kind::Credential, [0; 16], device)
}

/// BLAKE3 over a fixed label, the storage id and the secret. The secret is
/// not recoverable from the hash, and the same secret on another storage
/// hashes differently.
pub fn secret_hash(storage_id: &str, secret: &str) -> [u8; 32] {
    let mut buf = Vec::with_capacity(24 + storage_id.len() + secret.len() + 2);
    buf.extend_from_slice(b"varsto-storage-secret-v1");
    buf.push(0);
    buf.extend_from_slice(storage_id.as_bytes());
    buf.push(0);
    buf.extend_from_slice(secret.as_bytes());
    let out = crypto::hash(&buf);
    buf.fill(0);
    out
}

/// Keep the highest removal epoch for each storage. The same epoch with two
/// hashes keeps the smaller hash, so every device merges the same way.
pub fn merge_baselines(all: impl IntoIterator<Item = Baseline>) -> Vec<Baseline> {
    let mut best: Vec<Baseline> = Vec::new();
    for b in all {
        if let Some(old) = best.iter_mut().find(|o| o.storage_id == b.storage_id) {
            let replace =
                b.epoch > old.epoch || (b.epoch == old.epoch && b.old_hash < old.old_hash);
            if replace {
                *old = b;
            }
        } else {
            best.push(b);
        }
    }
    best.sort_by(|a, b| a.storage_id.cmp(&b.storage_id));
    best
}

/// Sort and drop duplicate storage ids (the later one wins). Records must
/// already be unique; this is for the cache before it is sealed.
pub fn normalize_current(mut all: Vec<Current>) -> Vec<Current> {
    // Stable sort keeps the first of a pair. Reversing first makes that the
    // later statement, which is the one a device published last.
    all.reverse();
    all.sort_by(|a, b| a.storage_id.cmp(&b.storage_id));
    all.dedup_by(|a, b| a.storage_id == b.storage_id);
    all
}

/// One remaining device's published statement.
#[derive(Clone, Debug)]
pub struct DeviceStatement {
    pub device: Id16,
    pub name: String,
    pub current: Vec<Current>,
}

/// The secret this device actually holds. `None` means nothing is stored
/// for that storage (an env key counts as stored). Other devices are not
/// judged from this.
#[derive(Clone, Debug)]
pub struct LiveSecret {
    pub storage_id: String,
    pub has_storage: bool,
    pub secret_hash: Option<[u8; 32]>,
}

/// One storage the overview, `varsto status` and the removal report name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialWarning {
    pub storage_id: String,
    pub name: String,
    pub kind: String,
    pub text: String,
    pub needs_secret: bool,
    pub needs_confirm: bool,
    pub devices_old: Vec<String>,
}

/// Warnings for the baselines still open. A zero S3 hash means the remover
/// had no stored key, so it matches nobody. This device is judged by `live`,
/// not by the hash it published. The warning stays until nobody still has
/// the old S3 key and some remaining device has confirmed the old key is
/// disabled. An rclone warning ends at that confirmation alone.
pub fn warnings(
    baselines: &[Baseline],
    devices: &[DeviceStatement],
    me: &Id16,
    live: &[LiveSecret],
) -> Vec<CredentialWarning> {
    let baselines = merge_baselines(baselines.iter().cloned());
    let mut out = Vec::new();
    for b in baselines {
        let live_here = live.iter().find(|l| l.storage_id == b.storage_id);
        let mut accused = Vec::new();
        let mut any_retired = false;
        for d in devices {
            let statement = d.current.iter().find(|c| c.storage_id == b.storage_id);
            let (retired, holds_old) = if d.device == *me {
                let mut retired = statement.is_some_and(|c| c.retired);
                let published = statement.map(|c| c.secret_hash);
                if let Some(h) = live_here.and_then(|l| l.secret_hash) {
                    if published != Some(h) {
                        retired = false;
                    }
                }
                let holds_old = b.kind == KIND_S3
                    && b.old_hash != ZERO_HASH
                    && live_here.and_then(|l| l.secret_hash) == Some(b.old_hash);
                (retired, holds_old)
            } else {
                let holds_old = b.kind == KIND_S3
                    && b.old_hash != ZERO_HASH
                    && statement.is_some_and(|c| c.secret_hash == b.old_hash);
                (statement.is_some_and(|c| c.retired), holds_old)
            };
            if retired {
                any_retired = true;
            }
            if holds_old {
                let name = if d.device == *me {
                    "this device".to_string()
                } else {
                    d.name.clone()
                };
                accused.push(name);
            }
        }
        accused.sort();
        accused.dedup();
        // rclone never has a hash to compare, so the confirmation is the
        // whole check. S3 also needs every known remaining key to have changed.
        if any_retired && accused.is_empty() {
            continue;
        }
        let kind = if b.kind == KIND_RCLONE {
            "rclone"
        } else {
            "s3"
        };
        let place = label(&b.name, &b.detail);
        let text = if b.kind == KIND_RCLONE {
            format!(
                "{place}: the removed device can still delete encrypted files here until you disable the old key at the provider. Update rclone's configuration on every remaining computer that uses this remote, and only then confirm that you disabled the old key. Varsto never sees the rclone credential."
            )
        } else if accused.is_empty() {
            format!(
                "{place}: no remaining device reports the key from before the removal, but Varsto cannot see whether you disabled it at the provider. Confirm that only after every remaining device that uses this storage has the new key. Until then the removed device can still delete encrypted files."
            )
        } else {
            format!(
                "{place}: {} still has the key from before a device was removed. The removed device can still delete encrypted files until you disable that key at the provider. Create a new key there, enter it on every remaining device, and only then disable the old one.",
                accused.join(", ")
            )
        };
        out.push(CredentialWarning {
            storage_id: b.storage_id,
            name: b.name,
            kind: kind.to_string(),
            text,
            needs_secret: b.kind == KIND_S3 && accused.iter().any(|n| n == "this device"),
            needs_confirm: !any_retired,
            devices_old: accused,
        });
    }
    out
}

fn label(name: &str, detail: &str) -> String {
    if detail.is_empty() {
        name.to_string()
    } else {
        format!("{name} ({detail})")
    }
}

/// A cloud storage named in the removal report.
#[derive(Clone, Debug)]
pub struct CloudNote {
    pub kind: u8,
    pub name: String,
    pub detail: String,
    /// An S3 secret was stored on this device. False for rclone, and for an
    /// S3 storage whose key lives nowhere Varsto can read.
    pub has_secret: bool,
}

/// Sentences for the removal report. `network_paths` are local storages on
/// a network share; the caller decides that, so a temp directory does not
/// have to be one. No sentence for an ordinary directory or a disk pool.
pub fn removal_notes(cloud: &[CloudNote], network_paths: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for c in cloud {
        let place = label(&c.name, &c.detail);
        let text = if c.kind == KIND_RCLONE {
            format!(
                "{place}: the removed device can still delete encrypted files here until you disable the old key at the provider. Update rclone's configuration on every remaining computer, then confirm that you did and that the old key is disabled."
            )
        } else if c.has_secret {
            format!(
                "{place}: the removed device can still delete encrypted files here until you disable the old key at the provider. Create a new key there first, enter it on every remaining device, and only then disable the old key."
            )
        } else {
            format!(
                "{place}: Varsto has no stored key for this storage on this device. The removed device can still delete encrypted files until you disable the old key at the provider. Create a new key, enter it on every remaining device that uses this storage, and only then disable the old key."
            )
        };
        out.push(text);
    }
    if network_paths.len() == 1 {
        out.push(format!(
            "{} is on a network share. Change that share's password: the removed device can still use the old one, and Varsto does not store it.",
            network_paths[0]
        ));
    } else if network_paths.len() > 1 {
        out.push(format!(
            "These storages are on a network share: {}. Change those share passwords: the removed device can still use the old ones, and Varsto does not store them.",
            network_paths.join(", ")
        ));
    }
    out
}

/// Shorten to `max` bytes without splitting a character.
pub fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(id: &str, kind: u8, hash: [u8; 32], epoch: u32) -> Baseline {
        Baseline {
            storage_id: id.into(),
            kind,
            name: "photos".into(),
            detail: "bucket".into(),
            old_hash: hash,
            epoch,
        }
    }

    fn cur(id: &str, kind: u8, hash: [u8; 32], retired: bool) -> Current {
        Current {
            storage_id: id.into(),
            kind,
            name: "photos".into(),
            detail: "bucket".into(),
            secret_hash: hash,
            retired,
        }
    }

    fn dev(n: u8, name: &str, current: Vec<Current>) -> DeviceStatement {
        DeviceStatement {
            device: [n; 16],
            name: name.into(),
            current,
        }
    }

    fn live(id: &str, hash: Option<[u8; 32]>) -> LiveSecret {
        LiveSecret {
            storage_id: id.into(),
            has_storage: true,
            secret_hash: hash,
        }
    }

    fn me() -> Id16 {
        [1; 16]
    }

    #[test]
    fn secret_hash_is_bound_to_the_storage() {
        let a = secret_hash("s3:one", "secret");
        let b = secret_hash("s3:two", "secret");
        assert_ne!(a, b);
        assert_ne!(a, crypto::hash(b"secret"));
        assert_eq!(a, secret_hash("s3:one", "secret"));
    }

    #[test]
    fn higher_epoch_wins_and_a_tie_keeps_one_hash() {
        let low = base("s3:a", KIND_S3, [1; 32], 1);
        let high = base("s3:a", KIND_S3, [2; 32], 4);
        let merged = merge_baselines([low, high.clone()]);
        assert_eq!(merged, vec![high]);
        let a = base("s3:a", KIND_S3, [9; 32], 3);
        let b = base("s3:a", KIND_S3, [2; 32], 3);
        let merged = merge_baselines([a, b.clone()]);
        assert_eq!(merged[0].old_hash, b.old_hash);
    }

    #[test]
    fn old_s3_key_warns_until_it_changes_and_someone_confirms() {
        let old = [4; 32];
        let baselines = [base("s3:a", KIND_S3, old, 2)];
        let mine = dev(1, "laptop", vec![cur("s3:a", KIND_S3, old, false)]);
        let w = warnings(
            &baselines,
            &[mine.clone()],
            &me(),
            &[live("s3:a", Some(old))],
        );
        assert_eq!(w.len(), 1);
        assert!(w[0].needs_secret);
        assert!(w[0].needs_confirm);
        assert_eq!(w[0].devices_old, vec!["this device".to_string()]);
        assert!(w[0].text.contains("bucket"));

        // The published hash changed, but the secret on this device did not.
        let published_new = dev(1, "laptop", vec![cur("s3:a", KIND_S3, [8; 32], true)]);
        let w = warnings(
            &baselines,
            &[published_new],
            &me(),
            &[live("s3:a", Some(old))],
        );
        assert!(w[0].needs_secret);
        assert!(w[0].text.contains("this device"));

        // The key changed here. The warning stays until the old key is disabled.
        let changed = dev(1, "laptop", vec![cur("s3:a", KIND_S3, [8; 32], false)]);
        let w = warnings(
            &baselines,
            &[changed.clone()],
            &me(),
            &[live("s3:a", Some([8; 32]))],
        );
        assert!(!w[0].needs_secret);
        assert!(w[0].needs_confirm);

        let retired = dev(1, "laptop", vec![cur("s3:a", KIND_S3, [8; 32], true)]);
        let w = warnings(
            &baselines,
            &[retired],
            &me(),
            &[live("s3:a", Some([8; 32]))],
        );
        assert!(w.is_empty());
    }

    #[test]
    fn another_device_still_on_the_old_key_keeps_the_warning() {
        let old = [4; 32];
        let baselines = [base("s3:a", KIND_S3, old, 2)];
        let mine = dev(1, "laptop", vec![cur("s3:a", KIND_S3, [8; 32], true)]);
        let other = dev(2, "phone", vec![cur("s3:a", KIND_S3, old, false)]);
        let w = warnings(
            &baselines,
            &[mine, other],
            &me(),
            &[live("s3:a", Some([8; 32]))],
        );
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].devices_old, vec!["phone".to_string()]);
        assert!(!w[0].needs_confirm);
        assert!(!w[0].needs_secret);

        // A later statement of the old hash reopens a warning that had cleared.
        let again = dev(2, "phone", vec![cur("s3:a", KIND_S3, old, false)]);
        let only_me = dev(1, "laptop", vec![cur("s3:a", KIND_S3, [8; 32], true)]);
        let w = warnings(
            &baselines,
            &[only_me, again],
            &me(),
            &[live("s3:a", Some([8; 32]))],
        );
        assert_eq!(w[0].devices_old, vec!["phone".to_string()]);
    }

    #[test]
    fn a_device_that_never_published_is_not_accused() {
        let old = [4; 32];
        let baselines = [base("s3:a", KIND_S3, old, 1)];
        let mine = dev(1, "laptop", vec![]);
        let quiet = dev(2, "phone", vec![]);
        let w = warnings(&baselines, &[mine, quiet], &me(), &[]);
        assert_eq!(w.len(), 1);
        assert!(w[0].devices_old.is_empty());
        assert!(w[0].needs_confirm);
        assert!(!w[0].needs_secret);
        assert!(w[0].text.contains("cannot see"));
    }

    #[test]
    fn a_zero_hash_baseline_matches_nobody() {
        let baselines = [base("s3:a", KIND_S3, ZERO_HASH, 1)];
        let mine = dev(1, "laptop", vec![cur("s3:a", KIND_S3, ZERO_HASH, false)]);
        let w = warnings(&baselines, &[mine], &me(), &[live("s3:a", None)]);
        assert!(w[0].devices_old.is_empty());
        assert!(w[0].needs_confirm);
    }

    #[test]
    fn rclone_clears_only_when_someone_confirms() {
        let baselines = [base("rclone:box:", KIND_RCLONE, ZERO_HASH, 2)];
        let mine = dev(
            1,
            "laptop",
            vec![cur("rclone:box:", KIND_RCLONE, ZERO_HASH, false)],
        );
        let w = warnings(&baselines, &[mine.clone()], &me(), &[]);
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].kind, "rclone");
        assert!(!w[0].needs_secret);
        assert!(w[0].needs_confirm);
        assert!(w[0].text.contains("rclone"));

        let done = dev(
            1,
            "laptop",
            vec![cur("rclone:box:", KIND_RCLONE, ZERO_HASH, true)],
        );
        assert!(warnings(&baselines, &[done], &me(), &[]).is_empty());
    }

    #[test]
    fn removal_notes_skip_local_disks_and_name_a_share() {
        assert!(removal_notes(&[], &[]).is_empty());
        let share = removal_notes(&[], &["/mnt/nas/vault".into()]);
        assert_eq!(share.len(), 1);
        assert!(share[0].contains("network share"));
        assert!(share[0].contains("/mnt/nas/vault"));
        let s3 = CloudNote {
            kind: KIND_S3,
            name: "photos".into(),
            detail: "bucket".into(),
            has_secret: true,
        };
        let note = removal_notes(&[s3], &[]);
        assert!(note[0].contains("photos (bucket)"));
        assert!(!note[0].contains("no stored key"));
        let missing = CloudNote {
            kind: KIND_S3,
            name: "photos".into(),
            detail: "bucket".into(),
            has_secret: false,
        };
        assert!(removal_notes(&[missing], &[])[0].contains("no stored key"));
        let rclone = CloudNote {
            kind: KIND_RCLONE,
            name: "b2".into(),
            detail: "b2:bucket".into(),
            has_secret: false,
        };
        assert!(removal_notes(&[rclone], &[])[0].contains("rclone"));
    }

    #[test]
    fn a_credential_body_rejects_a_bad_row() {
        let device = [3; 16];
        let meta = RecordMeta {
            kind: Kind::Credential,
            vault: [0; 16],
            scope: [0; 16],
            device,
            seq: 1,
            parts: 1,
            key_id: crate::record::KeyId::Registry(0),
            body_hash: [0; 32],
            epoch: None,
            recipient: None,
            size: 0,
        };
        let mut body = CredentialBody {
            device,
            seq: 1,
            epoch: 1,
            baselines: vec![base("s3:a", KIND_S3, [1; 32], 1)],
            current: vec![cur("s3:a", KIND_S3, [1; 32], false)],
        };
        assert!(body.check(&meta).is_ok());
        body.baselines[0].kind = 9;
        assert!(body.check(&meta).is_err());
        body.baselines[0].kind = KIND_RCLONE;
        body.baselines[0].old_hash = [1; 32];
        assert!(body.check(&meta).is_err());
        body.baselines[0].old_hash = ZERO_HASH;
        body.current.reverse();
        body.baselines.push(base("s3:a", KIND_S3, [1; 32], 1));
        assert!(body.check(&meta).is_err());
    }
}
