// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `fsck` on the pack-level format (`docs/spec/format-3-design.md`
//! sections 3, 4, 5, 12; work package 10b).
//!
//! The check is a function over what an engine already holds, so it has no
//! engine dependency: the ledger view, the opened storages, per folder the
//! map table and the manifests, and optionally a probe that reads the
//! announced records. It compares them:
//!
//! - every pack the view claims exists on the claimed storage at exactly
//!   its size class (one tiny ranged read, no download), and with
//!   `verify` its hash matches (through the `verify_pack` callback, which
//!   WP5 supplies; read in the media-aware lanes of section 39);
//! - every place in every map lies inside a known pack and class, and no
//!   two places of a pack overlap;
//! - every object a current manifest references has a live place on a
//!   storage that really holds the pack, else the file is damaged;
//! - every announced map or manifest record is on the metadata storages,
//!   complete and accepted (or waiting or refused, with the reason);
//! - packs on a storage that nobody claims are orphans (older than
//!   [`ORPHAN_DAYS`] they are due for garbage collection);
//! - forked streams, refused events and records are reported.
//!
//! [`fix`] makes the one repair the design allows without a folder key: a
//! pack missing on one storage is copied whole from another storage that
//! holds it intact (its hash is checked against its id); the claim is in
//! the ledger already, so nothing is announced. Corrupt and short packs
//! are handed to the optional `repair_pack` callback (WP5).
//!
//! # Report JSON (`varsto fsck --json`, format 3)
//!
//! `Fsck3Report` serialises as one object. Ids are lower-case hex, times
//! are UTC seconds, lists are in a stable order:
//!
//! ```text
//! { "verify": bool,
//!   "packs": n, "copies_claimed": n, "copies_present": n, "copies_verified_now": n,
//!   "missing_copies": [{pack, storage, detail}],
//!   "wrong_length": [{pack, storage, detail}],
//!   "corrupt_copies": [{pack, storage, detail}],
//!   "verify_errors": [{pack, storage, detail}],
//!   "orphans": [{storage, pack, kind, bytes, age_days, gc_due}],
//!   "maps": [{folder, places, packs, outside_pack: [..], unknown_pack: [..],
//!             class_mismatch: [..], overlapping: [..], unmapped_packs: [pack]}],
//!   "blocks": {referenced, live, only_marked, missing},
//!   "damaged_files": [{folder, writer, path, blocks, blocks_missing}],
//!   "records": {announced, checked, missing: [..], missing_on: [..], waiting: [..], refused: [..]},
//!   "forked_devices": [hex], "forked_streams": [text],
//!   "records_refused": {kind: n}, "events_refused": n, "events_unknown": n, "marks_refused": n,
//!   "unchecked_storages": [name], "storage_errors": [{storage, detail}],
//!   "fixed": [{pack, from, to, bytes}], "fix_failed": [{pack, storage, detail}],
//!   "handed_to_repair": [{pack, storage, detail}] }
//! ```
//!
//! Interpretations of the design (for review):
//! - The storage trait has no `stat`: a pack's length is probed with a
//!   ranged read of two bytes at `class - 1` (one byte back means exact),
//!   and its age comes from the caller's `modified_utc` hook. Without the
//!   hook an orphan's age is unknown and it is never reported as due.
//! - "Duplicate claims" cannot exist in the pack-level view (claims are a
//!   union of devices); the equivalent corruption is two places of a pack
//!   that overlap or name different objects, reported as `overlapping`.

mod check;
mod fix;
mod records;
mod report;

#[cfg(test)]
pub(crate) mod testkit;
#[cfg(test)]
mod tests;

pub use check::fsck;
pub use fix::{fix, FixOptions};
pub use records::{AcceptorProbe, RecordProbe, RecordRef, RecordState};
pub use report::{
    BlockCounts, DamagedFile, FixAction, Fsck3Report, MapFindings, Orphan, PackIssue,
    RecordFindings, RecordIssue, StorageError,
};

use crate::ledger3::{FolderBin, LedgerView, PackId};
use crate::manifest3::FolderManifests;
use crate::media::Media;
use crate::record::RecordsRefused;
use crate::storage::Storage;
use anyhow::Result;

/// An unclaimed pack older than this many days is due for garbage
/// collection (section 3, "Garbage collection": orphans go after 7 days).
pub const ORPHAN_DAYS: i64 = 7;

/// One opened storage.
pub struct StorageDesc<'a> {
    /// The name the ledger uses for it.
    pub name: String,
    pub storage: &'a dyn Storage,
    /// Cold storages hold the 256 MiB class too.
    pub cold: bool,
    /// Holds records (ledger, maps, manifests): records are probed here.
    pub meta: bool,
    /// How verification reads are laid out (section 39).
    pub media: Media,
}

impl<'a> StorageDesc<'a> {
    /// A hot metadata storage on an unknown medium.
    pub fn new(name: &str, storage: &'a dyn Storage) -> Self {
        StorageDesc {
            name: name.to_string(),
            storage,
            cold: false,
            meta: true,
            media: Media::Unknown,
        }
    }

    /// The largest class this storage may hold.
    pub fn max_class(&self) -> u8 {
        if self.cold {
            5
        } else {
            4
        }
    }
}

/// One folder this device holds the keys of.
pub struct FolderInput<'a> {
    pub id: FolderBin,
    pub name: String,
    pub map: &'a crate::blockmap::MapTable,
    pub manifests: &'a FolderManifests,
}

/// What a `verify_pack` callback is asked to check.
pub struct PackCheck<'a> {
    pub storage: &'a str,
    pub backend: &'a dyn Storage,
    pub pack: PackId,
    /// The exact length the pack must have.
    pub class_len: u64,
}

/// A `verify_pack` callback's answer (WP5's per-pack verification).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackVerdict {
    Ok,
    /// The bytes do not hash to the pack id (or are short).
    Corrupt(String),
    Missing,
    /// Could not be read now (the storage failed, not the pack).
    Unreadable(String),
}

/// Reads one whole pack and compares its hash with its id.
pub type VerifyPack<'a> = dyn Fn(&PackCheck) -> PackVerdict + Sync + 'a;
/// The modification time (UTC seconds) of a pack on a storage, if known.
pub type PackAge<'a> = dyn Fn(&str, &PackId) -> Option<i64> + 'a;
/// Hands a damaged pack copy to the repair of WP5; true when repaired.
pub type RepairPack<'a> = dyn Fn(&PackIssue) -> Result<bool> + 'a;

/// Everything `fsck` reads.
pub struct Fsck3Input<'a> {
    pub view: &'a LedgerView,
    pub storages: &'a [StorageDesc<'a>],
    pub folders: &'a [FolderInput<'a>],
    /// Probe of announced records; without it records are not checked.
    pub records: Option<&'a dyn RecordProbe>,
    /// Refusals counted while pulling records.
    pub refused: Option<&'a RecordsRefused>,
    pub modified_utc: Option<&'a PackAge<'a>>,
    pub verify_pack: Option<&'a VerifyPack<'a>>,
    pub now_utc: i64,
}

/// `fsck` options.
#[derive(Clone, Copy, Debug, Default)]
pub struct Fsck3Options {
    /// Read every claimed pack and compare its hash (`--verify`).
    pub verify: bool,
}

/// The packs a storage holds: id to key, from one listing of `packs/`.
pub fn list_packs(storage: &dyn Storage) -> Result<std::collections::BTreeMap<PackId, String>> {
    let mut out = std::collections::BTreeMap::new();
    for key in storage.list(crate::packs::PREFIX)? {
        if let Some(id) = crate::packs::pack_of_key(&key) {
            let mut bin = [0u8; 32];
            if hex::decode_to_slice(id, &mut bin).is_ok() {
                out.insert(bin, key);
            }
        }
    }
    Ok(out)
}

/// How a stored pack's length compares with the class it must have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LenProbe {
    Missing,
    Exact,
    Longer,
    Shorter,
}

/// Compare the length of a pack with `class_len` with one ranged read.
pub fn probe_len(storage: &dyn Storage, pack: &PackId, class_len: u64) -> Result<LenProbe> {
    let key = crate::packs::pack_key(&hex::encode(pack));
    Ok(
        match storage
            .get_range(&key, class_len.saturating_sub(1), 2)?
            .map(|b| b.len())
        {
            None => LenProbe::Missing,
            Some(1) => LenProbe::Exact,
            Some(0) => LenProbe::Shorter,
            Some(_) => LenProbe::Longer,
        },
    )
}

/// The size class length (bytes) of a pack on `storage`, found by probing
/// the classes in order; `None` when it is no size class or not there.
pub fn find_class_len(storage: &dyn Storage, pack: &PackId, max_class: u8) -> Result<Option<u64>> {
    for c in 0..=max_class {
        let len = crate::ledger3::events::class_bytes(c).unwrap_or(0);
        match probe_len(storage, pack, len)? {
            LenProbe::Missing | LenProbe::Shorter => return Ok(None),
            LenProbe::Exact => return Ok(Some(len)),
            LenProbe::Longer => {}
        }
    }
    Ok(None)
}
