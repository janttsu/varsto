// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Folder manifests: the per-device view of a folder's files, encrypted under
//! the folder metadata key and published to storage. Devices merge each
//! other's manifests with version vectors; concurrent edits produce a
//! deterministic winner and a conflict copy, never silent data loss (F-003).

use crate::crypto::{self, SecretKey};
use crate::ids::{ChunkId, DeviceId, FolderId, ObjectName, VaultId};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Largest chunk any device writes (`ChunkerParams::DEFAULT.max` is 1 MiB);
/// a manifest that claims more is refused before anything is allocated.
pub const MAX_CHUNK_SIZE: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkRef {
    pub chunk: ChunkId,
    pub object: ObjectName,
    pub size: u64,
    /// Folder key epoch the chunk is encrypted under (0 = the folder record's
    /// key; later epochs follow device revocations). Omitted when 0, so
    /// manifests written before rotation existed are unchanged.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub epoch: u32,
}

fn is_zero(e: &u32) -> bool {
    *e == 0
}

/// Version vector: device -> logical clock of that device's last change.
pub type VersionVector = BTreeMap<DeviceId, u64>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileState {
    pub path: String,
    pub version: VersionVector,
    pub deleted: bool,
    pub size: u64,
    /// Modification time in nanoseconds since the Unix epoch (change detection only).
    pub mtime: i64,
    /// Keyed hash of the whole content (folder hash key); empty when deleted.
    pub content_hash: String,
    pub chunks: Vec<ChunkRef>,
    pub modified_by: DeviceId,
    pub modified_clock: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u16,
    pub folder: FolderId,
    pub device: DeviceId,
    pub seq: u64,
    pub lamport: u64,
    pub created_utc: i64,
    pub files: BTreeMap<String, FileState>,
}

impl Manifest {
    pub fn storage_key(folder: &FolderId, device: &DeviceId, seq: u64) -> String {
        format!("manifests/{}/{}/{:016}.enc", folder, device, seq)
    }

    pub fn storage_prefix(folder: &FolderId, device: &DeviceId) -> String {
        format!("manifests/{}/{}/", folder, device)
    }

    fn aad(vault: &VaultId, folder: &FolderId, device: &DeviceId, seq: u64) -> Vec<u8> {
        crypto::aad(
            "manifest",
            &[
                vault.as_str().as_bytes(),
                folder.as_str().as_bytes(),
                device.as_str().as_bytes(),
                &seq.to_le_bytes(),
            ],
        )
    }

    pub fn seal(&self, vault: &VaultId, meta_key: &SecretKey) -> Result<Vec<u8>> {
        let plain = serde_json::to_vec(self)?;
        crypto::encrypt(
            meta_key,
            &Self::aad(vault, &self.folder, &self.device, self.seq),
            &plain,
        )
    }

    pub fn open(
        blob: &[u8],
        vault: &VaultId,
        folder: &FolderId,
        device: &DeviceId,
        seq: u64,
        meta_key: &SecretKey,
    ) -> Result<Manifest> {
        let plain = crypto::decrypt(meta_key, &Self::aad(vault, folder, device, seq), blob)?;
        let m: Manifest = serde_json::from_slice(&plain)?;
        if &m.folder != folder || &m.device != device || m.seq != seq {
            bail!("manifest body does not match its name");
        }
        m.validate()?;
        Ok(m)
    }

    /// Refuse a manifest whose entries could not have come from an honest
    /// device: a path that leaves the folder (it would be written there),
    /// a key that is not the entry's path, a chunk larger than any chunker
    /// makes, or a size that is not the sum of its chunks.
    pub fn validate(&self) -> Result<()> {
        for (key, f) in &self.files {
            if key != &f.path {
                bail!("manifest entry {key:?} names another path {:?}", f.path);
            }
            crate::util::check_rel_path(&f.path)?;
            if f.deleted {
                continue;
            }
            let mut total: u64 = 0;
            for c in &f.chunks {
                if c.size == 0 || c.size > MAX_CHUNK_SIZE {
                    bail!("manifest entry {key:?} has a chunk of {} bytes", c.size);
                }
                total = total
                    .checked_add(c.size)
                    .ok_or_else(|| anyhow::anyhow!("manifest entry {key:?} overflows"))?;
            }
            if total != f.size {
                bail!(
                    "manifest entry {key:?} says {} bytes but its chunks hold {total}",
                    f.size
                );
            }
        }
        Ok(())
    }

    /// Stable hash of the file map, used to detect whether a new manifest is needed.
    pub fn files_hash(files: &BTreeMap<String, FileState>) -> String {
        let bytes = serde_json::to_vec(files).unwrap_or_default();
        hex::encode(crypto::hash(&bytes))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Order {
    Equal,
    LocalNewer,
    RemoteNewer,
    Concurrent,
}

pub fn compare(local: &VersionVector, remote: &VersionVector) -> Order {
    let le = |a: &VersionVector, b: &VersionVector| {
        a.iter().all(|(k, v)| b.get(k).copied().unwrap_or(0) >= *v)
    };
    match (le(local, remote), le(remote, local)) {
        (true, true) => Order::Equal,
        (true, false) => Order::RemoteNewer,
        (false, true) => Order::LocalNewer,
        (false, false) => Order::Concurrent,
    }
}

pub fn vv_max(a: &VersionVector, b: &VersionVector) -> VersionVector {
    let mut out = a.clone();
    for (k, v) in b {
        let e = out.entry(k.clone()).or_insert(0);
        *e = (*e).max(*v);
    }
    out
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Merge {
    KeepLocal,
    TakeRemote,
    /// Both sides changed. `winner` becomes the file; `loser` is kept as a
    /// conflict copy (None when the loser is a deletion or identical content).
    Conflict {
        winner: FileState,
        loser: Option<FileState>,
    },
}

/// Decide how a remote state combines with the local state of the same path.
pub fn merge(local: Option<&FileState>, remote: &FileState) -> Merge {
    let Some(local) = local else {
        return Merge::TakeRemote;
    };
    match compare(&local.version, &remote.version) {
        Order::Equal | Order::LocalNewer => Merge::KeepLocal,
        Order::RemoteNewer => Merge::TakeRemote,
        Order::Concurrent => {
            let merged_version = vv_max(&local.version, &remote.version);
            let same_content =
                local.deleted == remote.deleted && local.content_hash == remote.content_hash;
            if same_content {
                let mut w = local.clone();
                w.version = merged_version;
                return Merge::Conflict {
                    winner: w,
                    loser: None,
                };
            }
            // A deletion never wins against a concurrent modification.
            if local.deleted != remote.deleted {
                let (mut w, _) = if local.deleted {
                    (remote.clone(), local)
                } else {
                    (local.clone(), remote)
                };
                w.version = merged_version;
                return Merge::Conflict {
                    winner: w,
                    loser: None,
                };
            }
            let local_wins = (local.modified_clock, &local.modified_by)
                > (remote.modified_clock, &remote.modified_by);
            let (mut w, l) = if local_wins {
                (local.clone(), remote.clone())
            } else {
                (remote.clone(), local.clone())
            };
            w.version = merged_version;
            Merge::Conflict {
                winner: w,
                loser: Some(l),
            }
        }
    }
}

/// Name of a conflict copy: `report.txt` -> `report.conflict-<device>-<clock>.txt`.
pub fn conflict_path(path: &str, loser: &FileState) -> String {
    let (dir, name) = match path.rfind('/') {
        Some(i) => (&path[..=i], &path[i + 1..]),
        None => ("", path),
    };
    let tag = format!(
        "conflict-{}-{}",
        loser.modified_by.short(),
        loser.modified_clock
    );
    let new_name = match name.rfind('.') {
        Some(i) if i > 0 => format!("{}.{}{}", &name[..i], tag, &name[i..]),
        _ => format!("{name}.{tag}"),
    };
    format!("{dir}{new_name}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, chunks: &[u64]) -> FileState {
        FileState {
            path: path.to_string(),
            version: VersionVector::default(),
            deleted: false,
            size: chunks.iter().sum(),
            mtime: 0,
            content_hash: String::new(),
            chunks: chunks
                .iter()
                .map(|s| ChunkRef {
                    chunk: ChunkId::from_bytes(&[1; 16]),
                    object: ObjectName::from_bytes(&[2; 32]),
                    size: *s,
                    epoch: 0,
                })
                .collect(),
            modified_by: DeviceId::from_bytes(&[3; 16]),
            modified_clock: 1,
        }
    }

    fn manifest_with(files: Vec<FileState>) -> Manifest {
        Manifest {
            format_version: crate::FORMAT_VERSION,
            folder: FolderId::from_bytes(&[4; 16]),
            device: DeviceId::from_bytes(&[3; 16]),
            seq: 1,
            lamport: 1,
            created_utc: 0,
            files: files.into_iter().map(|f| (f.path.clone(), f)).collect(),
        }
    }

    #[test]
    fn manifests_from_other_devices_are_validated_before_use() {
        assert!(manifest_with(vec![entry("docs/a.txt", &[10, 20])])
            .validate()
            .is_ok());
        // A path that leaves the folder is refused when the manifest is opened.
        let vault = VaultId::from_bytes(&[5; 16]);
        let key = SecretKey::random();
        let bad = manifest_with(vec![entry("../../.ssh/authorized_keys", &[10])]);
        let blob = bad.seal(&vault, &key).unwrap();
        assert!(Manifest::open(&blob, &vault, &bad.folder, &bad.device, 1, &key).is_err());
        let abs = manifest_with(vec![entry("/etc/passwd", &[10])]);
        assert!(abs.validate().is_err());
        // The map key must be the entry's path.
        let mut mismatch = manifest_with(vec![entry("a.txt", &[10])]);
        let f = mismatch.files.remove("a.txt").unwrap();
        mismatch.files.insert("other.txt".into(), f);
        assert!(mismatch.validate().is_err());
        // Sizes must add up and chunks must be of a size a chunker makes.
        let mut wrong = manifest_with(vec![entry("a.txt", &[10])]);
        wrong.files.get_mut("a.txt").unwrap().size = 11;
        assert!(wrong.validate().is_err());
        assert!(manifest_with(vec![entry("a.txt", &[1 << 40])])
            .validate()
            .is_err());
        assert!(manifest_with(vec![entry("a.txt", &[0])])
            .validate()
            .is_err());
        // A deleted entry carries no chunks and passes.
        let mut gone = entry("a.txt", &[]);
        gone.deleted = true;
        assert!(manifest_with(vec![gone]).validate().is_ok());
    }

    fn st(dev: &str, clock: u64, hash: &str, vv: &[(&str, u64)]) -> FileState {
        FileState {
            path: "a.txt".into(),
            version: vv
                .iter()
                .map(|(d, c)| (DeviceId::from_bytes(d.as_bytes()), *c))
                .collect(),
            deleted: false,
            size: 1,
            mtime: 0,
            content_hash: hash.into(),
            chunks: vec![],
            modified_by: DeviceId::from_bytes(dev.as_bytes()),
            modified_clock: clock,
        }
    }

    #[test]
    fn version_vector_orders() {
        let a = st("A", 1, "h1", &[("A", 1)]);
        let b = st("B", 2, "h2", &[("A", 1), ("B", 2)]);
        assert!(matches!(merge(Some(&a), &b), Merge::TakeRemote));
        assert!(matches!(merge(Some(&b), &a), Merge::KeepLocal));
        assert!(matches!(merge(None, &a), Merge::TakeRemote));
    }

    #[test]
    fn concurrent_edits_conflict_deterministically() {
        let a = st("A", 5, "ha", &[("A", 5)]);
        let b = st("B", 7, "hb", &[("B", 7)]);
        let Merge::Conflict {
            winner: w1,
            loser: l1,
        } = merge(Some(&a), &b)
        else {
            panic!()
        };
        let Merge::Conflict {
            winner: w2,
            loser: l2,
        } = merge(Some(&b), &a)
        else {
            panic!()
        };
        assert_eq!(w1, w2);
        assert_eq!(l1, l2);
        assert_eq!(w1.content_hash, "hb");
        assert_eq!(w1.version.len(), 2);
        assert_eq!(
            conflict_path("docs/report.txt", l1.as_ref().unwrap()),
            format!(
                "docs/report.conflict-{}-5.txt",
                DeviceId::from_bytes(b"A").short()
            )
        );
    }

    #[test]
    fn delete_loses_against_concurrent_edit() {
        let mut del = st("A", 5, "", &[("A", 5)]);
        del.deleted = true;
        let edit = st("B", 3, "hb", &[("B", 3)]);
        let Merge::Conflict { winner, loser } = merge(Some(&del), &edit) else {
            panic!()
        };
        assert!(!winner.deleted);
        assert!(loser.is_none());
    }
}
