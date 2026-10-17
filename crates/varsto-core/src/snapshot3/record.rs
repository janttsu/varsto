// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The body of a format-3 `snapshot` record (section 7).
//!
//! ```text
//! SnapshotBody { backup, device, seq, lamport, taken_utc, expires_utc,
//!                base,                        // == seq: a base (full listing)
//!                devices: Vec<[16]>,          // interned ids of version vectors and modified_by
//!                files: Vec<WireEntry>,       // base: every file; differential: entries that differ from the base
//!                removed: Vec<path bytes> }   // differential only: paths of the base that are gone
//! ```
//!
//! Entries are the manifests' wire entries (`crate::manifest3::record`)
//! with `held` always false: a backup is never on the vault's devices, so
//! no device holds it (section 31). A snapshot lists live files only.

use super::Id16;
use crate::manifest3::record::{Header, ManifestBody, WireEntry, MAX_ENTRIES, MAX_PATH, MAX_VV};
use crate::manifest3::FileEntry;
use crate::record::{RecordBody, RecordMeta};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The body of a `snapshot` record: a base or a differential against one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotBody {
    pub backup: Id16,
    pub device: Id16,
    pub seq: u64,
    pub lamport: u64,
    pub taken_utc: i64,
    /// Fixed when the snapshot is taken (section 31).
    pub expires_utc: i64,
    /// Seq of the base snapshot this one is a differential against;
    /// `== seq` for a base.
    pub base: u64,
    pub devices: Vec<Id16>,
    pub files: Vec<WireEntry>,
    pub removed: Vec<Vec<u8>>,
}

/// Header fields of a snapshot body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapHeader {
    pub backup: Id16,
    pub device: Id16,
    pub seq: u64,
    pub lamport: u64,
    pub taken_utc: i64,
    pub expires_utc: i64,
    pub base: u64,
}

impl SnapshotBody {
    /// Encode `files` (the whole listing for a base, the entries that
    /// differ from the base for a differential) and, for a differential,
    /// the `removed` paths.
    pub fn new<'a>(
        h: SnapHeader,
        files: impl IntoIterator<Item = &'a FileEntry>,
        removed: impl IntoIterator<Item = &'a str>,
    ) -> SnapshotBody {
        let mut m = ManifestBody::new(
            Header {
                folder: h.backup,
                device: h.device,
                seq: h.seq,
                lamport: h.lamport,
                created_utc: h.taken_utc,
                base: h.base,
                prev: [0; 32],
            },
            files,
            removed,
        );
        for f in &mut m.files {
            f.held = false;
        }
        SnapshotBody {
            backup: h.backup,
            device: h.device,
            seq: h.seq,
            lamport: h.lamport,
            taken_utc: h.taken_utc,
            expires_utc: h.expires_utc,
            base: h.base,
            devices: m.devices,
            files: m.files,
            removed: m.removed,
        }
    }

    pub fn is_base(&self) -> bool {
        self.base == self.seq
    }

    fn as_manifest(&self) -> ManifestBody {
        ManifestBody {
            folder: self.backup,
            device: self.device,
            seq: self.seq,
            lamport: self.lamport,
            created_utc: self.taken_utc,
            base: self.base,
            prev: [0; 32],
            devices: self.devices.clone(),
            files: self.files.clone(),
            removed: self.removed.clone(),
        }
    }

    /// Every check that does not need the envelope: the manifests' entry
    /// checks (section 28), live files only, `held` unset, limits, unique
    /// paths, a well-formed base or differential. Returns the entries and
    /// removed paths.
    pub fn validate(&self) -> Result<(BTreeMap<String, FileEntry>, Vec<String>), String> {
        if self.seq == 0 {
            return Err("seq 0".into());
        }
        if self.base > self.seq || self.base == 0 {
            return Err(format!("base {} for seq {}", self.base, self.seq));
        }
        if self.expires_utc < self.taken_utc {
            return Err("a snapshot that expires before it was taken".into());
        }
        if self.is_base() && !self.removed.is_empty() {
            return Err("a base removes paths".into());
        }
        if self.files.len() + self.removed.len() > MAX_ENTRIES {
            return Err(format!(
                "{} entries, more than {MAX_ENTRIES}",
                self.files.len() + self.removed.len()
            ));
        }
        if self.devices.len() > MAX_VV {
            return Err(format!("{} devices in the id table", self.devices.len()));
        }
        if self.files.iter().any(|f| f.held) {
            return Err("a snapshot entry that is held".into());
        }
        if self.files.iter().any(|f| f.deleted) {
            return Err("a snapshot lists a deleted file".into());
        }
        if self.removed.iter().any(|p| p.len() > MAX_PATH) {
            return Err("a removed path is too long".into());
        }
        // The manifest rules for ids, paths, chunks and uniqueness.
        let (entries, removed) = self.as_manifest().validate()?;
        let map = entries.into_iter().map(|e| (e.path.clone(), e)).collect();
        Ok((map, removed))
    }
}

impl RecordBody for SnapshotBody {
    fn base(&self) -> Option<u64> {
        Some(self.base)
    }
    // No `prev`: a differential names its base, not a predecessor, so
    // expiring any snapshot never breaks another.
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if self.backup != meta.scope {
            return Err("its backup is not the record's scope".into());
        }
        if self.device != meta.device {
            return Err("its device is not the record's writer".into());
        }
        if self.seq != meta.seq {
            return Err("its seq is not the record's".into());
        }
        self.validate().map(|_| ())
    }
}
