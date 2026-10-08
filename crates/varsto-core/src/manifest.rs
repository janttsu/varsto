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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkRef {
    pub chunk: ChunkId,
    pub object: ObjectName,
    pub size: u64,
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
        Ok(m)
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
