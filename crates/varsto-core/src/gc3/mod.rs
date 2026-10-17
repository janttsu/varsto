// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Marks, garbage collection, verification and repair of storage format 3
//! (`docs/spec/format-3-design.md` section 3, "Dead marks, settling and
//! collection", "Who may mark", "Garbage collection", "Verification and
//! repair", "Pruning"; work package 5). Built behind the `format3`
//! feature; nothing in the format-2 code path calls it (the trash upkeep
//! calls these functions from WP12 on).
//!
//! Every function here works over what a device holds, without the
//! engine: the storages ([`Storages`]), the ledger view, the folder's map
//! table and map writer (`crate::blockmap`), a [`RecordWriter`] for map
//! records, and a [`Commit`] that seals a batch and pushes it.
//!
//! - [`marks`]: which places nothing references (`find_unreferenced`),
//!   which dead-marked places are referenced again (`find_revived`), and
//!   publishing `dead` / `undead` marks in the writer's next map delta.
//! - [`collect`]: the verdict of a place (live, referenced, waiting for
//!   whom, collectable), the plan of one run (drops, rewrites, compaction)
//!   and its execution; orphan packs.
//! - [`verify`]: the per-pack check (one GET, BLAKE3 against the id, no
//!   key), repair of a damaged pack, and copying a pack missing on one
//!   storage from another.
//! - [`prune`]: map records below the writer's newest base, once every
//!   reader acknowledged it.
//!
//! Interpretations of the design (for review):
//! - "G, having applied every writer's records announced up to the
//!   batches that settled m": the collector requires that it applied every
//!   reference record (manifests; trash, history and snapshots once WP7
//!   adds them through [`References`]) that its view shows announced, of
//!   every writer of the folder. That is at least what the batches that
//!   settled m announced (they are in the view, or settling would fail),
//!   so it is the design's condition or a stronger one; the view does not
//!   keep which batch of a writer first acknowledged the mark.
//! - Only marks whose marker is a current writer of the folder count for
//!   collection (marks of a device demoted or removed since are ignored
//!   and counted), on top of `record::accept` refusing the map records of
//!   viewers, K3-only devices and replicas outright.
//! - Undead marks are published by any writer that finds a reference to a
//!   place whose newest mark is dead, not only by the marker (a marker
//!   that is gone would otherwise leave the place marked).
//! - A `lost` mark goes on a corrupt place only when no other storage
//!   holding the same pack gives a good member at that place: a place is
//!   (pack id, offset) on every storage of the pack, so a lost mark for one
//!   damaged copy would wrongly mark the good copies elsewhere.
//! - A pack whose known members do not follow one another from offset 0
//!   holds a member this table does not list: it is neither dropped nor
//!   rewritten.
//! - Orphans: storages keep no write times this code can read, so a pack
//!   no claim and no map names is remembered when first seen
//!   ([`OrphanState`], kept by the caller) and deleted 7 days later if
//!   still unnamed. A pack the view shows deliberately dropped from a
//!   storage (a crash between the batch and the delete) is deleted at once.

pub mod collect;
pub mod marks;
pub mod prune;
pub mod verify;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::ledger3::events::Event;
use crate::ledger3::{DeviceBin, FolderBin, LedgerView, ObjectBin};
use crate::manifest3::FolderManifests;
use crate::membership3::{FolderRegistry, Role};
use crate::record::{Kind, RecordWriter};
use crate::storage::Storage;

pub use collect::{
    collect, collect_orphans, place_verdict, plan, GcOptions, GcPlan, GcReport, OrphanReport,
    OrphanState, PlaceVerdict,
};
pub use marks::{
    find_revived, find_unreferenced, mark_round, publish_dead_marks, publish_undead_marks,
    MarkReport,
};
pub use prune::{map_prune_floor, map_readers_waiting, prune_map, PruneReport};
pub use verify::{
    copy_missing_pack, other_places, repair_pack, verify_pack, PackCheck, RepairReport, Verified,
};

/// Seven days: an unclaimed pack no map lists goes after this long.
pub const ORPHAN_SECS: i64 = 7 * 86_400;
/// Hot packs smaller than this class are compacted once their live
/// members fill it.
pub const COMPACT_BYTES: u64 = crate::packs::HOT_TARGET as u64;

/// What kind of storage a pack is on (section 3: cold and pool packs are
/// never rewritten; cold ones keep the price model's minimum duration).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageClass {
    Hot,
    Cold,
    Pool,
}

/// One storage as garbage collection sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageInfo {
    pub class: StorageClass,
    /// The minimum storage duration of its price model (cold storages), in
    /// seconds; `None`: none known.
    pub minimum_secs: Option<i64>,
}

impl StorageInfo {
    pub const HOT: StorageInfo = StorageInfo {
        class: StorageClass::Hot,
        minimum_secs: None,
    };
    /// From the storage's price model (`price::StoragePrice`).
    pub fn cold(price: Option<&crate::price::StoragePrice>) -> StorageInfo {
        StorageInfo {
            class: StorageClass::Cold,
            minimum_secs: price
                .and_then(|p| p.minimum_storage_days)
                .map(|d| i64::from(d) * 86_400),
        }
    }
    /// The pack size limit of packs written there (`packs::HOT_TARGET`,
    /// `packs::COLD_TARGET`).
    pub fn target(&self) -> usize {
        match self.class {
            StorageClass::Cold => crate::packs::COLD_TARGET,
            _ => crate::packs::HOT_TARGET,
        }
    }
}

/// The storages this device can reach, by name.
pub trait Storages {
    /// The opened storage (`None`: not reachable from here now).
    fn open(&self, name: &str) -> Option<Arc<dyn Storage>>;
    /// Its class; unknown names count as hot.
    fn info(&self, name: &str) -> StorageInfo;
}

/// A fixed set of opened storages.
#[derive(Clone, Default)]
pub struct StorageSet {
    pub storages: BTreeMap<String, (Arc<dyn Storage>, StorageInfo)>,
}

impl StorageSet {
    pub fn add(&mut self, s: Arc<dyn Storage>, info: StorageInfo) {
        self.storages.insert(s.name().to_string(), (s, info));
    }
    pub fn names(&self) -> Vec<String> {
        self.storages.keys().cloned().collect()
    }
}

impl Storages for StorageSet {
    fn open(&self, name: &str) -> Option<Arc<dyn Storage>> {
        self.storages.get(name).map(|(s, _)| s.clone())
    }
    fn info(&self, name: &str) -> StorageInfo {
        self.storages
            .get(name)
            .map_or(StorageInfo::HOT, |(_, i)| *i)
    }
}

/// Seals this device's events as one action and pushes the batch(es) to
/// every metadata storage (`LedgerStore::append_action` and the push).
/// Nothing is deleted before `commit` returned `Ok`.
pub trait Commit {
    /// The Lamport time for a map record this device writes now.
    fn tick(&mut self) -> u64;
    /// Seal and push; `Ok` only once the batch is on the storages.
    fn commit(&mut self, events: Vec<Event>) -> Result<()>;
}

/// Where map records go: the writer and the hot metadata storages.
pub struct MapOut<'a> {
    pub writer: &'a RecordWriter<'a>,
    pub meta: &'a [&'a dyn Storage],
}

/// What references objects of a folder (section 3: current files in every
/// accepted writer's newest manifest, unexpired trash and history entries,
/// unexpired snapshots). WP6's `FolderManifests` is one; WP7 adds trash,
/// history and snapshots (pairs combine).
pub trait References {
    fn is_referenced(&self, object: &ObjectBin) -> bool;
    /// Writers of `writers` whose reference records the view shows
    /// announced past what this device applied: collection waits for them.
    fn behind(
        &self,
        view: &LedgerView,
        folder: &FolderBin,
        writers: &[DeviceBin],
    ) -> Vec<DeviceBin>;
}

/// Whether the view announces a record of `writer`'s stream of `kind` past
/// `applied` (forked streams included: they are never applied, so
/// collection waits until the fork is resolved).
pub fn stream_behind(
    view: &LedgerView,
    kind: Kind,
    folder: &FolderBin,
    writer: &DeviceBin,
    applied: u64,
) -> bool {
    view.stream(kind.code(), folder, writer)
        .and_then(|s| s.newest())
        .is_some_and(|n| n > applied)
}

impl References for FolderManifests {
    fn is_referenced(&self, object: &ObjectBin) -> bool {
        FolderManifests::is_referenced(self, object)
    }
    fn behind(
        &self,
        view: &LedgerView,
        folder: &FolderBin,
        writers: &[DeviceBin],
    ) -> Vec<DeviceBin> {
        writers
            .iter()
            .filter(|w| stream_behind(view, Kind::Manifest, folder, w, self.applied(w)))
            .copied()
            .collect()
    }
}

/// A set of referenced objects with what was applied per (kind, writer):
/// for callers that gather references from several record kinds.
#[derive(Clone, Debug, Default)]
pub struct ReferenceSet {
    pub objects: HashSet<ObjectBin>,
    pub applied: BTreeMap<(Kind, DeviceBin), u64>,
    /// The kinds whose streams carry references.
    pub kinds: BTreeSet<Kind>,
}

impl References for ReferenceSet {
    fn is_referenced(&self, object: &ObjectBin) -> bool {
        self.objects.contains(object)
    }
    fn behind(
        &self,
        view: &LedgerView,
        folder: &FolderBin,
        writers: &[DeviceBin],
    ) -> Vec<DeviceBin> {
        writers
            .iter()
            .filter(|w| {
                self.kinds.iter().any(|k| {
                    let applied = self.applied.get(&(*k, **w)).copied().unwrap_or(0);
                    stream_behind(view, *k, folder, w, applied)
                })
            })
            .copied()
            .collect()
    }
}

impl<A: References, B: References> References for (A, B) {
    fn is_referenced(&self, object: &ObjectBin) -> bool {
        self.0.is_referenced(object) || self.1.is_referenced(object)
    }
    fn behind(
        &self,
        view: &LedgerView,
        folder: &FolderBin,
        writers: &[DeviceBin],
    ) -> Vec<DeviceBin> {
        let mut out = self.0.behind(view, folder, writers);
        out.extend(self.1.behind(view, folder, writers));
        out.sort_unstable();
        out.dedup();
        out
    }
}

impl<T: References + ?Sized> References for &T {
    fn is_referenced(&self, object: &ObjectBin) -> bool {
        (**self).is_referenced(object)
    }
    fn behind(
        &self,
        view: &LedgerView,
        folder: &FolderBin,
        writers: &[DeviceBin],
    ) -> Vec<DeviceBin> {
        (**self).behind(view, folder, writers)
    }
}

/// WP7's references of a folder (`trash3::Refs`: manifests, unexpired
/// trash and history, unexpired snapshots) as [`References`]: the set is
/// computed once; a writer is behind while the view announces manifest or
/// trash records of it past what was applied, or unexpired snapshots of it
/// that are not loaded yet.
pub struct FolderReferences<'a> {
    pub refs: &'a crate::trash3::Refs<'a>,
    set: HashSet<ObjectBin>,
}

impl<'a> FolderReferences<'a> {
    pub fn new(refs: &'a crate::trash3::Refs<'a>) -> FolderReferences<'a> {
        FolderReferences {
            set: refs.set(),
            refs,
        }
    }
}

impl References for FolderReferences<'_> {
    fn is_referenced(&self, object: &ObjectBin) -> bool {
        self.set.contains(object)
    }
    fn behind(
        &self,
        view: &LedgerView,
        folder: &FolderBin,
        writers: &[DeviceBin],
    ) -> Vec<DeviceBin> {
        let r = self.refs;
        let snaps: BTreeSet<DeviceBin> = r
            .snapshots
            .map(|(s, v)| s.wanted(v, r.now).into_iter().map(|w| w.device).collect())
            .unwrap_or_default();
        writers
            .iter()
            .filter(|w| {
                r.manifests
                    .is_some_and(|m| stream_behind(view, Kind::Manifest, folder, w, m.applied(w)))
                    || r.trash.is_some_and(|(t, _, _)| {
                        stream_behind(view, Kind::Trash, folder, w, t.applied(w))
                    })
                    || snaps.contains(*w)
            })
            .copied()
            .collect()
    }
}

/// Everything is referenced: nothing is marked or collected (the stand-in
/// until every reference kind is wired).
#[derive(Clone, Copy, Debug, Default)]
pub struct Everything;

impl References for Everything {
    fn is_referenced(&self, _: &ObjectBin) -> bool {
        true
    }
    fn behind(&self, _: &LedgerView, _: &FolderBin, _: &[DeviceBin]) -> Vec<DeviceBin> {
        Vec::new()
    }
}

/// This device's standing in a folder: what section 3 lets it do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Standing {
    pub device: DeviceBin,
    /// Its role in the folder (`None`: no grant, K3 only, or removed).
    pub role: Option<Role>,
    /// A member device (another person's), not an own full device.
    pub member: bool,
    /// It holds the folder's K10 (can read maps and manifests).
    pub holds_k10: bool,
}

impl Standing {
    /// From the folder records at the folder's current epoch.
    pub fn of(
        registry: &FolderRegistry,
        folder: &FolderBin,
        epoch: u32,
        device: DeviceBin,
        member: bool,
        holds_k10: bool,
    ) -> Standing {
        Standing {
            device,
            role: registry.role(&device, folder, epoch),
            member,
            holds_k10,
        }
    }

    /// Owners and editors (own devices and members) mark places and write
    /// maps (marks, repairs).
    pub fn may_mark(&self) -> bool {
        self.holds_k10 && matches!(self.role, Some(Role::Owner | Role::Editor))
    }

    /// Garbage collection runs only on own full devices with write role
    /// that hold K10: members do not collect (they may not hold the
    /// owner's storages).
    pub fn may_collect(&self) -> bool {
        self.may_mark() && !self.member
    }

    /// Repairs write a new pack and a map delta: writers only. Every
    /// device may verify and copy whole packs.
    pub fn may_repair(&self) -> bool {
        self.may_mark()
    }
}

/// The current writers of a folder (owners and editors, own devices and
/// members, not revoked) at its epoch `epoch`: whose acknowledgements
/// settle a mark.
pub fn folder_writers(
    registry: &FolderRegistry,
    folder: &FolderBin,
    epoch: u32,
    revoked: &BTreeSet<DeviceBin>,
) -> Vec<DeviceBin> {
    participants(registry, folder, epoch, revoked, |r| {
        matches!(r, Role::Owner | Role::Editor)
    })
}

/// The readers of a folder (every participant holding K10: owners,
/// editors, viewers, own devices and members), not revoked: whose
/// acknowledgements let map records be pruned.
pub fn folder_readers(
    registry: &FolderRegistry,
    folder: &FolderBin,
    epoch: u32,
    revoked: &BTreeSet<DeviceBin>,
) -> Vec<DeviceBin> {
    participants(registry, folder, epoch, revoked, |_| true)
}

fn participants(
    registry: &FolderRegistry,
    folder: &FolderBin,
    epoch: u32,
    revoked: &BTreeSet<DeviceBin>,
    keep: impl Fn(Role) -> bool,
) -> Vec<DeviceBin> {
    let Some(st) = registry.get(folder) else {
        return Vec::new();
    };
    st.participants()
        .into_iter()
        .filter(|p| !revoked.contains(&p.device))
        .filter(|p| registry.role(&p.device, folder, epoch).is_some_and(&keep))
        .map(|p| p.device)
        .collect()
}

/// The folder's packs in the view a map row may name (marks on other
/// packs are refused by the table).
pub(crate) fn folder_pack(view: &LedgerView, folder: FolderBin) -> impl Fn(&[u8; 32]) -> bool + '_ {
    move |p| view.pack_folder(p).is_none_or(|f| f == folder)
}
