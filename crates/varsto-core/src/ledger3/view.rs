// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The pack-level location view (`docs/spec/format-3-design.md` section 4).
//!
//! The view holds one `PackRecord` per pack with one `PackPlace` per
//! storage that ever saw a claim, verification or drop of it; devices are
//! bits of interned device numbers, folders and storage names are interned
//! too, so the view grows with packs × storages and not with blocks.
//!
//! Application is order-independent: claims and verifications are unions,
//! times are maxima, a drop cancels the claims on that storage with a
//! smaller Lamport time (a place counts while its newest claim is newer
//! than its newest drop and than the storage's retirement), and the
//! folder, writer, class and map seq of a pack come from the claim with the
//! largest (Lamport, device, seq, position) stamp among full devices'
//! claims that name a folder. Interned numbers depend on arrival order, so
//! two views are compared through `canonical()`.
//!
//! A raw view (batches applied) becomes what callers query through
//! `finish()`, which decides members' conditional events (see
//! `super::scope`) and marks forked devices.

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::events::{Announcement, Batch, Event, PackOn, PackStored};
use super::scope::{folder_written, Allow, EventScope, FolderRoles, NoRoles};
use super::{DeviceBin, FolderBin, Hash32, ObjectBin, PackId, NO_FOLDER};

/// Which event set a value last, by the full device id: Lamport time,
/// device, batch seq, position in the batch. The largest wins.
pub type Stamp = (u64, DeviceBin, u64, u32);

/// A stamp with the device interned (`Tables::devices`). `seq == 0`: none.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct PackStamp {
    pub lamport: u64,
    pub seq: u64,
    pub pos: u32,
    pub dev: u16,
}

impl PackStamp {
    pub fn is_none(&self) -> bool {
        self.seq == 0
    }
}

/// "No folder known" in `PackRecord::folder`.
pub const NO_INDEX: u32 = u32::MAX;

/// One storage's view of one pack. Device sets are bitsets over interned
/// device numbers below 64; larger numbers are kept in `LedgerView::wide`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackPlace {
    pub claimed_by: u64,
    pub verified_by: u64,
    pub dropped_by: u64,
    /// Newest claim, verification and drop (Lamport time).
    pub stored_at: u64,
    pub verified_at: u64,
    pub dropped_at: u64,
    /// Newest claim and verification (batch creation time, UTC seconds).
    pub stored_utc: u32,
    pub verified_utc: u32,
}

/// A conditional event of a member device, decided in `finish`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct MemberEvent {
    /// The event code (3 stored, 4 verified, 5 dropped).
    pub code: u16,
    pub storage: u16,
    /// The member's folder (interned).
    pub folder: u32,
    pub class: u8,
    pub map_seq: u64,
    pub at: PackStamp,
    pub utc: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackRecord {
    /// Size class (0 = 1 MiB ... 4 = 256 MiB).
    pub class: u8,
    /// Interned folder (`NO_INDEX`: no full device or member named one).
    pub folder: u32,
    /// Interned writer device, valid when `at` is set.
    pub writer: u16,
    /// The writer's block-map record that lists the pack.
    pub map_seq: u64,
    /// The claim that set class, folder, writer and map seq.
    pub at: PackStamp,
    pub places: SmallVec<[(u16, PackPlace); 2]>,
    /// Members' conditional events (raw views only; empty after `finish`).
    pub member: Option<Box<Vec<MemberEvent>>>,
}

impl Default for PackRecord {
    fn default() -> Self {
        PackRecord {
            class: 0,
            folder: NO_INDEX,
            writer: 0,
            map_seq: 0,
            at: PackStamp::default(),
            places: SmallVec::new(),
            member: None,
        }
    }
}

impl PackRecord {
    fn place_mut(&mut self, storage: u16) -> &mut PackPlace {
        let i = match self.places.iter().position(|(s, _)| *s == storage) {
            Some(i) => i,
            None => {
                self.places.push((storage, PackPlace::default()));
                self.places.len() - 1
            }
        };
        &mut self.places[i].1
    }

    fn place(&self, storage: u16) -> Option<&PackPlace> {
        self.places
            .iter()
            .find(|(s, _)| *s == storage)
            .map(|(_, p)| p)
    }
}

/// Which device set of a place a `wide` entry extends.
pub const SET_CLAIMED: u8 = 0;
pub const SET_VERIFIED: u8 = 1;
pub const SET_DROPPED: u8 = 2;

/// (pack, storage, set): device numbers of 64 and above.
pub type WideKey = (PackId, u16, u8);

/// A place of another view with its storage and device sets renumbered
/// for this one (claimed, verified, dropped), while merging.
type TranslatedPlace = (u16, PackPlace, [Vec<u16>; 3]);

/// A stream of announced records: (kind, scope, device).
pub type StreamKey = (u8, FolderBin, DeviceBin);

/// What a batch announced about one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announced {
    pub base: u64,
    pub parts: u16,
    pub body_hash: Hash32,
    pub size: u64,
    /// The signer's batch that announced it (the smallest, if several).
    pub batch: u64,
}

/// The newest base of a stream and the records after it (snapshot
/// streams keep every record: a differential names an older base).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stream {
    pub records: BTreeMap<u64, Announced>,
    /// The largest seq any announcement named as a base: records below it
    /// are not kept (a maximum, so the same whatever the arrival order).
    pub floor: u64,
}

impl Stream {
    /// The newest base: (seq, body_hash, parts).
    pub fn base(&self) -> Option<(u64, Hash32, u16)> {
        self.records
            .iter()
            .rev()
            .find(|(seq, a)| a.base == **seq)
            .map(|(s, a)| (*s, a.body_hash, a.parts))
    }

    /// Records after the newest base, in order: (seq, body_hash, parts).
    pub fn deltas(&self) -> Vec<(u64, Hash32, u16)> {
        let from = self.base().map(|b| b.0).unwrap_or(0);
        self.records
            .range(from + 1..)
            .map(|(s, a)| (*s, a.body_hash, a.parts))
            .collect()
    }

    pub fn newest(&self) -> Option<u64> {
        self.records.keys().next_back().copied()
    }

    /// Add an announcement; returns whether it contradicts one already
    /// held at the same seq (the larger hash is kept, deterministically).
    fn insert(&mut self, seq: u64, a: Announced, keep_all: bool) -> bool {
        if !keep_all && a.base == seq && seq > self.floor {
            self.floor = seq;
            self.records = self.records.split_off(&seq);
        }
        if !keep_all && seq < self.floor {
            return false;
        }
        match self.records.get_mut(&seq) {
            Some(old) if old.body_hash == a.body_hash && old.parts == a.parts => {
                old.batch = old.batch.min(a.batch);
                false
            }
            Some(old) => {
                if (a.body_hash, a.parts, a.base) > (old.body_hash, old.parts, old.base) {
                    *old = a;
                }
                true
            }
            None => {
                self.records.insert(seq, a);
                false
            }
        }
    }
}

/// A backup snapshot as the ledger knows it (`snapshot_taken` carries no
/// hash any more: its `record_published` does).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRecord {
    pub taken: bool,
    pub taken_utc: i64,
    pub expires_utc: i64,
    pub files: u64,
    pub bytes: u64,
    pub expired: bool,
    pub taken_at: Option<Stamp>,
}

impl SnapshotRecord {
    fn take(&mut self, other: &SnapshotRecord) {
        if other.taken && other.taken_at > self.taken_at {
            self.taken = true;
            self.taken_utc = other.taken_utc;
            self.expires_utc = other.expires_utc;
            self.files = other.files;
            self.bytes = other.bytes;
            self.taken_at = other.taken_at;
        }
        self.expired |= other.expired;
    }

    pub fn is_live(&self) -> bool {
        self.taken && !self.expired
    }
}

#[derive(Clone, Debug, Default)]
struct Index {
    devices: HashMap<DeviceBin, u16>,
    folders: HashMap<FolderBin, u32>,
    storages: HashMap<String, u16>,
}

/// Interned ids. Numbers depend on the order things were first seen.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(from = "TablesWire", into = "TablesWire")]
pub struct Tables {
    devices: Vec<DeviceBin>,
    folders: Vec<FolderBin>,
    storages: Vec<String>,
    idx: Index,
}

impl PartialEq for Tables {
    fn eq(&self, o: &Self) -> bool {
        self.devices == o.devices && self.folders == o.folders && self.storages == o.storages
    }
}
impl Eq for Tables {}

#[derive(Serialize, Deserialize)]
struct TablesWire {
    devices: Vec<DeviceBin>,
    folders: Vec<FolderBin>,
    storages: Vec<String>,
}

impl From<TablesWire> for Tables {
    fn from(w: TablesWire) -> Self {
        let mut t = Tables {
            devices: w.devices,
            folders: w.folders,
            storages: w.storages,
            idx: Index::default(),
        };
        // An index past the number type is never handed out.
        t.devices.truncate(u16::MAX as usize);
        t.storages.truncate(u16::MAX as usize);
        t.folders.truncate(NO_INDEX as usize);
        for (i, d) in t.devices.iter().enumerate() {
            t.idx.devices.entry(*d).or_insert(i as u16);
        }
        for (i, f) in t.folders.iter().enumerate() {
            t.idx.folders.entry(*f).or_insert(i as u32);
        }
        for (i, s) in t.storages.iter().enumerate() {
            t.idx.storages.entry(s.clone()).or_insert(i as u16);
        }
        t
    }
}

impl From<Tables> for TablesWire {
    fn from(t: Tables) -> Self {
        TablesWire {
            devices: t.devices,
            folders: t.folders,
            storages: t.storages,
        }
    }
}

impl Tables {
    pub fn dev(&mut self, d: &DeviceBin) -> Option<u16> {
        if let Some(i) = self.idx.devices.get(d) {
            return Some(*i);
        }
        let i = u16::try_from(self.devices.len())
            .ok()
            .filter(|i| *i < u16::MAX)?;
        self.devices.push(*d);
        self.idx.devices.insert(*d, i);
        Some(i)
    }

    pub fn folder(&mut self, f: &FolderBin) -> Option<u32> {
        if let Some(i) = self.idx.folders.get(f) {
            return Some(*i);
        }
        let i = u32::try_from(self.folders.len())
            .ok()
            .filter(|i| *i < NO_INDEX)?;
        self.folders.push(*f);
        self.idx.folders.insert(*f, i);
        Some(i)
    }

    pub fn storage(&mut self, s: &str) -> Option<u16> {
        if let Some(i) = self.idx.storages.get(s) {
            return Some(*i);
        }
        let i = u16::try_from(self.storages.len())
            .ok()
            .filter(|i| *i < u16::MAX)?;
        self.storages.push(s.to_string());
        self.idx.storages.insert(s.to_string(), i);
        Some(i)
    }

    pub fn find_dev(&self, d: &DeviceBin) -> Option<u16> {
        self.idx.devices.get(d).copied()
    }
    pub fn find_folder(&self, f: &FolderBin) -> Option<u32> {
        self.idx.folders.get(f).copied()
    }
    pub fn find_storage(&self, s: &str) -> Option<u16> {
        self.idx.storages.get(s).copied()
    }
    pub fn device(&self, i: u16) -> Option<&DeviceBin> {
        self.devices.get(i as usize)
    }
    pub fn folder_id(&self, i: u32) -> Option<&FolderBin> {
        self.folders.get(i as usize)
    }
    pub fn storage_name(&self, i: u16) -> Option<&str> {
        self.storages.get(i as usize).map(|s| s.as_str())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerView {
    pub packs: HashMap<PackId, PackRecord>,
    pub streams: BTreeMap<StreamKey, Stream>,
    pub tables: Tables,
    /// Device numbers of 64 and above in a place's sets (vaults with that
    /// many writers are rare, so they are not in every place).
    pub wide: BTreeMap<WideKey, BTreeSet<u16>>,
    pub devices: BTreeMap<DeviceBin, String>,
    pub devices_at: BTreeMap<DeviceBin, Stamp>,
    pub folders: BTreeSet<FolderBin>,
    pub max_lamport: u64,
    /// Retired storages and when (Lamport time).
    pub retired: BTreeMap<String, u64>,
    pub batches: u64,
    /// Full devices: per device, the newest batch of each other device it
    /// said it held (vault ledger pruning and every settle question).
    pub acks: BTreeMap<DeviceBin, BTreeMap<DeviceBin, u64>>,
    /// Members: per (folder, member), what its folder-scoped batches said
    /// it held. Counts for settling marks and folder record pruning only.
    pub folder_acks: BTreeMap<(FolderBin, DeviceBin), BTreeMap<DeviceBin, u64>>,
    pub forked: BTreeSet<DeviceBin>,
    /// Streams where two batches announced different records under one
    /// seq (at or after the stream's newest base).
    pub forked_streams: BTreeSet<(StreamKey, u64)>,
    pub snapshots: BTreeMap<(FolderBin, DeviceBin, u64), SnapshotRecord>,
    pub backups_stopped: BTreeSet<FolderBin>,
    /// Events left out: outside the signer's scope, or malformed.
    pub events_refused: u64,
    /// Events of codes this version does not know.
    pub events_unknown: u64,
    /// Block-map marks refused (counted by the map, WP4).
    pub marks_refused: u64,
    /// `finish` ran: members' events are decided.
    pub finished: bool,
}

fn utc32(t: i64) -> u32 {
    t.clamp(0, u32::MAX as i64) as u32
}

fn add_dev(bits: &mut u64, wide: &mut BTreeMap<WideKey, BTreeSet<u16>>, key: WideKey, dev: u16) {
    if dev < 64 {
        *bits |= 1 << dev;
    } else {
        wide.entry(key).or_default().insert(dev);
    }
}

fn bits(mut b: u64) -> impl Iterator<Item = u16> {
    std::iter::from_fn(move || {
        if b == 0 {
            return None;
        }
        let i = b.trailing_zeros();
        b &= b - 1;
        Some(i as u16)
    })
}

/// One live copy of a pack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackCopy {
    pub storage: String,
    pub claimed_by: Vec<DeviceBin>,
    pub verified_by: Vec<DeviceBin>,
    /// Some device other than a claimant read it back (or a replica's own
    /// check of a replica storage), after the newest drop.
    pub independently_verified: bool,
    pub stored_utc: i64,
    pub verified_utc: i64,
}

/// A place of a block: which pack, where in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Place {
    pub pack: PackId,
    pub offset: u32,
    pub len: u32,
}

/// What the ledger view asks of the folder block map (WP4): the places of
/// an object, and whether a place carries a dead or lost mark.
///
/// WP4 integration: the local map table implements this.
pub trait BlockMapView {
    fn places_of(&self, object: &ObjectBin) -> Vec<Place>;
    fn is_marked(&self, place: &Place) -> bool;
}

/// A stand-in map until WP4: known places, never any mark.
#[derive(Clone, Debug, Default)]
pub struct UnmarkedPlaces(pub HashMap<ObjectBin, Vec<Place>>);

impl BlockMapView for UnmarkedPlaces {
    fn places_of(&self, object: &ObjectBin) -> Vec<Place> {
        self.0.get(object).cloned().unwrap_or_default()
    }
    fn is_marked(&self, _: &Place) -> bool {
        false
    }
}

/// One place of a block with the storages that hold its pack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockPlace {
    pub place: Place,
    pub storages: Vec<String>,
    pub marked: bool,
}

impl LedgerView {
    // ---- applying batches ------------------------------------------------

    /// Apply a batch whose signer has `full` scope.
    pub fn apply(&mut self, batch: &Batch) {
        self.apply_scoped(batch, &EventScope::Full)
    }

    /// Apply a batch whose signer has `scope`: events outside it are left
    /// out and counted; members' conditional events wait for `finish`.
    pub fn apply_scoped(&mut self, batch: &Batch, scope: &EventScope) {
        self.apply_scoped_with(batch, scope, &NoRoles)
    }

    /// `apply_scoped` with the folder roles of full devices: a full
    /// device's folder events (`scope::folder_written`) count only while
    /// it writes in that folder at the batch's Lamport time.
    pub fn apply_scoped_with(
        &mut self,
        batch: &Batch,
        scope: &EventScope,
        roles: &dyn FolderRoles,
    ) {
        self.batches += 1;
        self.max_lamport = self.max_lamport.max(batch.lamport);
        let acks = match scope {
            EventScope::Full => Some(self.acks.entry(batch.device).or_default()),
            EventScope::Member(f) | EventScope::Viewer(f) => {
                Some(self.folder_acks.entry((*f, batch.device)).or_default())
            }
            EventScope::Replica => None,
        };
        if let Some(acks) = acks {
            for (d, seq) in &batch.seen {
                let a = acks.entry(*d).or_insert(0);
                *a = (*a).max(*seq);
            }
        }
        let (events, unknown, malformed) = batch.decoded();
        self.events_unknown += unknown;
        self.events_refused += malformed;
        let Some(dev) = self.tables.dev(&batch.device) else {
            self.events_refused += events.len() as u64;
            return;
        };
        let utc = utc32(batch.created_utc);
        for (pos, ev) in events {
            let at = PackStamp {
                lamport: batch.lamport,
                seq: batch.seq,
                pos,
                dev,
            };
            let role_ok = *scope != EventScope::Full
                || folder_written(&ev).is_none_or(|f| {
                    roles.writes_at(&batch.device, &f, batch.lamport) != Some(false)
                });
            let applied = match scope.allows(&ev) {
                _ if !role_ok => false,
                Allow::No => false,
                Allow::Yes => self.apply_event(batch, at, utc, ev),
                _ => match scope.folder() {
                    Some(f) => self.apply_member(f, at, utc, ev),
                    None => false,
                },
            };
            if !applied {
                self.events_refused += 1;
            }
        }
    }

    fn stamp_key(&self, s: &PackStamp) -> (u64, DeviceBin, u64, u32) {
        let d = self.tables.device(s.dev).copied().unwrap_or_default();
        (s.lamport, d, s.seq, s.pos)
    }

    /// Whether stamp `a` is newer than `b` (an unset `b` loses).
    fn newer(&self, a: &PackStamp, b: &PackStamp) -> bool {
        b.is_none() || self.stamp_key(a) > self.stamp_key(b)
    }

    fn apply_event(&mut self, batch: &Batch, at: PackStamp, utc: u32, ev: Event) -> bool {
        let lamport = batch.lamport;
        match ev {
            Event::DeviceEnrolled(e) => {
                let s = (lamport, batch.device, batch.seq, at.pos);
                if self.devices_at.get(&batch.device).is_none_or(|o| *o < s) {
                    self.devices.insert(batch.device, e.name);
                    self.devices_at.insert(batch.device, s);
                }
            }
            Event::FolderAdded(e) => {
                self.folders.insert(e.folder);
            }
            Event::PackStored(p) => return self.claim(&p, at, utc),
            Event::PackVerified(p) => return self.mark_place(&p, SET_VERIFIED, at, utc),
            Event::PackDropped(p) => return self.mark_place(&p, SET_DROPPED, at, utc),
            Event::RecordPublished(a) => self.announce(&batch.device, batch.seq, &a),
            Event::StorageRetired(e) => {
                let r = self.retired.entry(e.storage).or_insert(0);
                *r = (*r).max(lamport);
            }
            Event::SnapshotTaken(e) => {
                self.snapshots
                    .entry((e.backup, batch.device, e.seq))
                    .or_default()
                    .take(&SnapshotRecord {
                        taken: true,
                        taken_utc: e.taken_utc,
                        expires_utc: e.expires_utc,
                        files: e.files,
                        bytes: e.bytes,
                        expired: false,
                        taken_at: Some((lamport, batch.device, batch.seq, at.pos)),
                    });
            }
            Event::SnapshotExpired(e) => {
                self.snapshots
                    .entry((e.backup, e.device, e.seq))
                    .or_default()
                    .expired = true;
            }
            Event::BackupStopped(e) => {
                self.backups_stopped.insert(e.backup);
            }
        }
        true
    }

    fn announce(&mut self, device: &DeviceBin, batch: u64, a: &Announcement) {
        let key = (a.kind, a.scope, *device);
        let keep_all = a.kind == super::envelope::kind::SNAPSHOT;
        let s = self.streams.entry(key).or_default();
        let conflict = s.insert(
            a.seq,
            Announced {
                base: a.base,
                parts: a.parts,
                body_hash: a.body_hash,
                size: a.size,
                batch,
            },
            keep_all,
        );
        if conflict {
            self.forked_streams.insert((key, a.seq));
        }
        if !keep_all {
            let floor = s.floor;
            self.forked_streams
                .retain(|(k, seq)| k != &key || *seq >= floor);
        }
    }

    /// A claim of a full device or a replica.
    fn claim(&mut self, p: &PackStored, at: PackStamp, utc: u32) -> bool {
        let Some(s) = self.tables.storage(&p.storage) else {
            return false;
        };
        let folder = if p.folder == NO_FOLDER {
            None
        } else {
            match self.tables.folder(&p.folder) {
                Some(f) => Some(f),
                None => return false,
            }
        };
        let newer = {
            let cur = self.packs.get(&p.pack).map(|r| r.at).unwrap_or_default();
            folder.is_some() && self.newer(&at, &cur)
        };
        let LedgerView { packs, wide, .. } = self;
        let rec = packs.entry(p.pack).or_default();
        if let Some(f) = folder.filter(|_| newer) {
            rec.class = p.class;
            rec.folder = f;
            rec.writer = at.dev;
            rec.map_seq = p.map_seq;
            rec.at = at;
        } else if rec.at.is_none() {
            rec.class = rec.class.max(p.class);
        }
        let place = rec.place_mut(s);
        add_dev(
            &mut place.claimed_by,
            wide,
            (p.pack, s, SET_CLAIMED),
            at.dev,
        );
        place.stored_at = place.stored_at.max(at.lamport);
        place.stored_utc = place.stored_utc.max(utc);
        true
    }

    fn mark_place(&mut self, p: &PackOn, set: u8, at: PackStamp, utc: u32) -> bool {
        let Some(s) = self.tables.storage(&p.storage) else {
            return false;
        };
        let LedgerView { packs, wide, .. } = self;
        let place = packs.entry(p.pack).or_default().place_mut(s);
        Self::mark(place, wide, (p.pack, s, set), at, utc);
        true
    }

    fn mark(
        place: &mut PackPlace,
        wide: &mut BTreeMap<WideKey, BTreeSet<u16>>,
        key: WideKey,
        at: PackStamp,
        utc: u32,
    ) {
        match key.2 {
            SET_CLAIMED => {
                add_dev(&mut place.claimed_by, wide, key, at.dev);
                place.stored_at = place.stored_at.max(at.lamport);
                place.stored_utc = place.stored_utc.max(utc);
            }
            SET_VERIFIED => {
                add_dev(&mut place.verified_by, wide, key, at.dev);
                place.verified_at = place.verified_at.max(at.lamport);
                place.verified_utc = place.verified_utc.max(utc);
            }
            _ => {
                add_dev(&mut place.dropped_by, wide, key, at.dev);
                place.dropped_at = place.dropped_at.max(at.lamport);
            }
        }
    }

    /// Keep a member's conditional event for `finish`.
    fn apply_member(&mut self, folder: &FolderBin, at: PackStamp, utc: u32, ev: Event) -> bool {
        let (code, storage, pack, class, map_seq) = match &ev {
            Event::PackStored(p) => (ev.code(), &p.storage, p.pack, p.class, p.map_seq),
            Event::PackVerified(p) | Event::PackDropped(p) => (ev.code(), &p.storage, p.pack, 0, 0),
            _ => return false,
        };
        let (Some(storage), Some(folder)) =
            (self.tables.storage(storage), self.tables.folder(folder))
        else {
            return false;
        };
        self.packs
            .entry(pack)
            .or_default()
            .member
            .get_or_insert_with(Default::default)
            .push(MemberEvent {
                code,
                storage,
                folder,
                class,
                map_seq,
                at,
                utc,
            });
        true
    }

    // ---- merging, restricting, finishing ---------------------------------

    /// Merge another view, as if its batches had been applied to this one.
    pub fn merge(&mut self, other: &LedgerView) {
        let mut devs: Vec<Option<Option<u16>>> = vec![None; other.tables.devices.len()];
        let mut folders: Vec<Option<Option<u32>>> = vec![None; other.tables.folders.len()];
        let mut stors: Vec<Option<Option<u16>>> = vec![None; other.tables.storages.len()];
        macro_rules! tr {
            ($cache:ident, $table:ident, $method:ident, $i:expr) => {{
                let i = $i as usize;
                match $cache.get(i) {
                    None => None,
                    Some(Some(v)) => *v,
                    Some(None) => {
                        let v = self.tables.$method(&other.tables.$table[i]);
                        $cache[i] = Some(v);
                        v
                    }
                }
            }};
        }
        for (id, orec) in &other.packs {
            let at = if orec.at.is_none() {
                None
            } else {
                tr!(devs, devices, dev, orec.at.dev).map(|d| PackStamp { dev: d, ..orec.at })
            };
            let folder = if orec.folder == NO_INDEX {
                None
            } else {
                tr!(folders, folders, folder, orec.folder)
            };
            let mut places: SmallVec<[TranslatedPlace; 2]> = SmallVec::new();
            for (s, p) in &orec.places {
                let Some(ts) = tr!(stors, storages, storage, *s) else {
                    continue;
                };
                let mut sets: [Vec<u16>; 3] = Default::default();
                for (k, b) in [p.claimed_by, p.verified_by, p.dropped_by]
                    .into_iter()
                    .enumerate()
                {
                    for i in bits(b) {
                        if let Some(d) = tr!(devs, devices, dev, i) {
                            sets[k].push(d);
                        }
                    }
                }
                places.push((ts, *p, sets));
            }
            let mut members = Vec::new();
            for m in orec.member.iter().flat_map(|v| v.iter()) {
                let (Some(s), Some(f), Some(d)) = (
                    tr!(stors, storages, storage, m.storage),
                    tr!(folders, folders, folder, m.folder),
                    tr!(devs, devices, dev, m.at.dev),
                ) else {
                    continue;
                };
                members.push(MemberEvent {
                    storage: s,
                    folder: f,
                    at: PackStamp { dev: d, ..m.at },
                    ..*m
                });
            }
            let newer = match (&at, folder) {
                (Some(a), Some(_)) => {
                    let cur = self.packs.get(id).map(|r| r.at).unwrap_or_default();
                    self.newer(a, &cur)
                }
                _ => false,
            };
            let LedgerView { packs, wide, .. } = self;
            let rec = packs.entry(*id).or_default();
            if let (true, Some(a), Some(f)) = (newer, at, folder) {
                rec.class = orec.class;
                rec.folder = f;
                rec.writer = a.dev;
                rec.map_seq = orec.map_seq;
                rec.at = a;
            } else if rec.at.is_none() && orec.at.is_none() {
                rec.class = rec.class.max(orec.class);
            }
            for (s, p, sets) in places {
                let place = rec.place_mut(s);
                for (k, set) in sets.iter().enumerate() {
                    let target = match k {
                        0 => &mut place.claimed_by,
                        1 => &mut place.verified_by,
                        _ => &mut place.dropped_by,
                    };
                    for d in set {
                        add_dev(target, wide, (*id, s, k as u8), *d);
                    }
                }
                place.stored_at = place.stored_at.max(p.stored_at);
                place.verified_at = place.verified_at.max(p.verified_at);
                place.dropped_at = place.dropped_at.max(p.dropped_at);
                place.stored_utc = place.stored_utc.max(p.stored_utc);
                place.verified_utc = place.verified_utc.max(p.verified_utc);
            }
            if !members.is_empty() {
                let v = rec.member.get_or_insert_with(Default::default);
                v.extend(members);
                v.sort_unstable();
                v.dedup();
            }
        }
        for ((id, s, set), ds) in &other.wide {
            let Some(ts) = tr!(stors, storages, storage, *s) else {
                continue;
            };
            let tds: Vec<u16> = ds
                .iter()
                .filter_map(|d| tr!(devs, devices, dev, *d))
                .collect();
            let LedgerView { packs, wide, .. } = self;
            let place = packs.entry(*id).or_default().place_mut(ts);
            let target = match *set {
                SET_CLAIMED => &mut place.claimed_by,
                SET_VERIFIED => &mut place.verified_by,
                _ => &mut place.dropped_by,
            };
            for d in tds {
                add_dev(target, wide, (*id, ts, *set), d);
            }
        }
        for (key, s) in &other.streams {
            if key.0 != super::envelope::kind::SNAPSHOT && s.floor > 0 {
                let mine = self.streams.entry(*key).or_default();
                if s.floor > mine.floor {
                    mine.floor = s.floor;
                    mine.records = mine.records.split_off(&s.floor);
                    let floor = s.floor;
                    self.forked_streams
                        .retain(|(k, seq)| k != key || *seq >= floor);
                }
            }
            for (seq, a) in &s.records {
                self.announce(
                    &key.2,
                    a.batch,
                    &Announcement {
                        kind: key.0,
                        scope: key.1,
                        seq: *seq,
                        base: a.base,
                        parts: a.parts,
                        body_hash: a.body_hash,
                        size: a.size,
                    },
                );
            }
        }
        for (key, seq) in &other.forked_streams {
            let floor = self.streams.get(key).map(|s| s.floor).unwrap_or(0);
            if *seq >= floor || key.0 == super::envelope::kind::SNAPSHOT {
                self.forked_streams.insert((*key, *seq));
            }
        }
        for (device, at) in &other.devices_at {
            if self.devices_at.get(device).is_none_or(|s| s < at) {
                if let Some(name) = other.devices.get(device) {
                    self.devices.insert(*device, name.clone());
                    self.devices_at.insert(*device, *at);
                }
            }
        }
        self.folders.extend(other.folders.iter().copied());
        self.max_lamport = self.max_lamport.max(other.max_lamport);
        for (storage, at) in &other.retired {
            let r = self.retired.entry(storage.clone()).or_insert(0);
            *r = (*r).max(*at);
        }
        self.batches += other.batches;
        let max_into = |into: &mut BTreeMap<DeviceBin, u64>, from: &BTreeMap<DeviceBin, u64>| {
            for (d, seq) in from {
                let a = into.entry(*d).or_insert(0);
                *a = (*a).max(*seq);
            }
        };
        for (device, seen) in &other.acks {
            max_into(self.acks.entry(*device).or_default(), seen);
        }
        for (key, seen) in &other.folder_acks {
            max_into(self.folder_acks.entry(*key).or_default(), seen);
        }
        self.forked.extend(other.forked.iter().copied());
        for (key, snap) in &other.snapshots {
            self.snapshots.entry(*key).or_default().take(snap);
        }
        self.backups_stopped
            .extend(other.backups_stopped.iter().copied());
        self.events_refused += other.events_refused;
        self.events_unknown += other.events_unknown;
        self.marks_refused += other.marks_refused;
        self.finished |= other.finished;
    }

    /// Only what `signer` itself said, for a checkpoint signed by it: its
    /// own claims, verifications, drops, announcements, name, snapshots and
    /// acknowledgements. Retirements, folders, stopped backups and expiries
    /// of other devices' snapshots stay (a full device may make those); of
    /// another device's snapshot only that it expired.
    pub fn restricted_to(&self, signer: &DeviceBin) -> LedgerView {
        let mut out = LedgerView {
            tables: self.tables.clone(),
            folders: self.folders.clone(),
            max_lamport: self.max_lamport,
            retired: self.retired.clone(),
            batches: self.batches,
            backups_stopped: self.backups_stopped.clone(),
            ..Default::default()
        };
        out.snapshots = self
            .snapshots
            .iter()
            .filter_map(|((b, d, seq), r)| {
                let rec = if d == signer && r.taken_at.as_ref().is_none_or(|s| &s.1 == signer) {
                    r.clone()
                } else if r.expired {
                    SnapshotRecord {
                        expired: true,
                        ..Default::default()
                    }
                } else {
                    return None;
                };
                Some(((*b, *d, *seq), rec))
            })
            .collect();
        let Some(si) = self.tables.find_dev(signer) else {
            return out;
        };
        let bit = if si < 64 { 1u64 << si } else { 0 };
        for ((id, s, set), ds) in &self.wide {
            if ds.contains(&si) {
                out.wide.insert((*id, *s, *set), BTreeSet::from([si]));
            }
        }
        let has_wide = |id: &PackId, s: u16, set: u8| out.wide.contains_key(&(*id, s, set));
        let mut packs = HashMap::new();
        for (id, rec) in &self.packs {
            let mine = !rec.at.is_none() && rec.at.dev == si;
            let mut r = PackRecord {
                class: rec.class,
                ..Default::default()
            };
            if mine {
                r.folder = rec.folder;
                r.writer = rec.writer;
                r.map_seq = rec.map_seq;
                r.at = rec.at;
            }
            for (s, p) in &rec.places {
                let c = p.claimed_by & bit != 0 || has_wide(id, *s, SET_CLAIMED);
                let v = p.verified_by & bit != 0 || has_wide(id, *s, SET_VERIFIED);
                let d = p.dropped_by & bit != 0 || has_wide(id, *s, SET_DROPPED);
                if !(c || v || d) {
                    continue;
                }
                let mut q = PackPlace::default();
                if c {
                    q.claimed_by = p.claimed_by & bit;
                    q.stored_at = p.stored_at;
                    q.stored_utc = p.stored_utc;
                }
                if v {
                    q.verified_by = p.verified_by & bit;
                    q.verified_at = p.verified_at;
                    q.verified_utc = p.verified_utc;
                }
                if d {
                    q.dropped_by = p.dropped_by & bit;
                    q.dropped_at = p.dropped_at;
                }
                r.places.push((*s, q));
            }
            let members: Vec<MemberEvent> = rec
                .member
                .iter()
                .flat_map(|v| v.iter())
                .filter(|m| m.at.dev == si)
                .copied()
                .collect();
            if !members.is_empty() {
                r.member = Some(Box::new(members));
            }
            if mine || !r.places.is_empty() || r.member.is_some() {
                packs.insert(*id, r);
            }
        }
        out.packs = packs;
        out.streams = self
            .streams
            .iter()
            .filter(|(k, _)| &k.2 == signer)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        out.forked_streams = self
            .forked_streams
            .iter()
            .filter(|(k, _)| &k.2 == signer)
            .copied()
            .collect();
        if let Some(name) = self.devices.get(signer) {
            if let Some(at) = self.devices_at.get(signer).filter(|s| &s.1 == signer) {
                out.devices.insert(*signer, name.clone());
                out.devices_at.insert(*signer, *at);
            }
        }
        if let Some(a) = self.acks.get(signer) {
            out.acks.insert(*signer, a.clone());
        }
        out.folder_acks = self
            .folder_acks
            .iter()
            .filter(|((_, d), _)| d == signer)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        out
    }

    /// The view as callers see it: members' conditional events decided
    /// (counted in `events_refused` when they do not hold) and `forked`
    /// set. The raw view is left as it was.
    pub fn finish(&self, forked: impl IntoIterator<Item = DeviceBin>) -> LedgerView {
        let mut v = self.clone();
        v.finish_in_place(forked);
        v
    }

    pub fn finish_in_place(&mut self, forked: impl IntoIterator<Item = DeviceBin>) {
        self.forked.extend(forked);
        if self.finished {
            return;
        }
        self.finished = true;
        let ids: Vec<PackId> = self
            .packs
            .iter()
            .filter(|(_, r)| r.member.is_some())
            .map(|(id, _)| *id)
            .collect();
        let mut refused = 0;
        for id in ids {
            let mut rec = self.packs.remove(&id).expect("listed");
            let mut evs = *rec.member.take().expect("listed");
            evs.sort_unstable();
            evs.dedup();
            if rec.at.is_none() {
                // No full device named the pack's folder: the newest
                // member claim does.
                let best = evs
                    .iter()
                    .filter(|m| m.code == super::events::code::PACK_STORED)
                    .max_by_key(|m| self.stamp_key(&m.at));
                if let Some(m) = best {
                    rec.class = m.class;
                    rec.folder = m.folder;
                    rec.writer = m.at.dev;
                    rec.map_seq = m.map_seq;
                    rec.at = m.at;
                }
            }
            let stored_by: BTreeSet<u16> = evs
                .iter()
                .filter(|m| m.code == super::events::code::PACK_STORED && m.folder == rec.folder)
                .map(|m| m.at.dev)
                .collect();
            for m in &evs {
                let ok = rec.folder != NO_INDEX
                    && m.folder == rec.folder
                    && (m.code != super::events::code::PACK_DROPPED
                        || stored_by.contains(&m.at.dev));
                if !ok {
                    refused += 1;
                    continue;
                }
                let set = match m.code {
                    super::events::code::PACK_STORED => SET_CLAIMED,
                    super::events::code::PACK_VERIFIED => SET_VERIFIED,
                    _ => SET_DROPPED,
                };
                let place = rec.place_mut(m.storage);
                Self::mark(place, &mut self.wide, (id, m.storage, set), m.at, m.utc);
            }
            self.packs.insert(id, rec);
        }
        self.events_refused += refused;
    }

    /// The same view with interned numbers in sorted order and only the
    /// ids still used: two views of the same batches compare equal through
    /// this whatever order the batches arrived in.
    pub fn canonical(&self) -> LedgerView {
        let mut devs = BTreeSet::new();
        let mut folders = BTreeSet::new();
        let mut stors = BTreeSet::new();
        for (id, r) in &self.packs {
            if !r.at.is_none() {
                devs.insert(r.at.dev);
                devs.insert(r.writer);
            }
            if r.folder != NO_INDEX {
                folders.insert(r.folder);
            }
            for (s, p) in &r.places {
                stors.insert(*s);
                devs.extend(bits(p.claimed_by | p.verified_by | p.dropped_by));
            }
            for m in r.member.iter().flat_map(|v| v.iter()) {
                devs.insert(m.at.dev);
                folders.insert(m.folder);
                stors.insert(m.storage);
            }
            let _ = id;
        }
        for ((_, s, _), ds) in &self.wide {
            stors.insert(*s);
            devs.extend(ds.iter().copied());
        }
        let mut t = Tables::default();
        let mut d: Vec<DeviceBin> = devs
            .iter()
            .filter_map(|i| self.tables.device(*i).copied())
            .collect();
        d.sort_unstable();
        for x in &d {
            t.dev(x);
        }
        let mut f: Vec<FolderBin> = folders
            .iter()
            .filter_map(|i| self.tables.folder_id(*i).copied())
            .collect();
        f.sort_unstable();
        for x in &f {
            t.folder(x);
        }
        let mut s: Vec<String> = stors
            .iter()
            .filter_map(|i| self.tables.storage_name(*i).map(str::to_string))
            .collect();
        s.sort_unstable();
        for x in &s {
            t.storage(x);
        }
        let mut v = LedgerView {
            tables: t,
            ..Default::default()
        };
        v.merge(self);
        for r in v.packs.values_mut() {
            r.places.sort_unstable_by_key(|(s, _)| *s);
        }
        v
    }

    // ---- queries -------------------------------------------------------

    pub fn pack(&self, id: &PackId) -> Option<&PackRecord> {
        self.packs.get(id)
    }

    pub fn pack_folder(&self, id: &PackId) -> Option<FolderBin> {
        let r = self.packs.get(id)?;
        (r.folder != NO_INDEX)
            .then(|| self.tables.folder_id(r.folder).copied())
            .flatten()
    }

    pub fn pack_writer(&self, id: &PackId) -> Option<DeviceBin> {
        let r = self.packs.get(id)?;
        (!r.at.is_none())
            .then(|| self.tables.device(r.writer).copied())
            .flatten()
    }

    fn set_of(&self, id: &PackId, s: u16, set: u8, b: u64) -> Vec<DeviceBin> {
        let mut out: Vec<DeviceBin> = bits(b)
            .chain(self.wide.get(&(*id, s, set)).into_iter().flatten().copied())
            .filter_map(|i| self.tables.device(i).copied())
            .collect();
        out.sort_unstable();
        out
    }

    fn has_claim(&self, id: &PackId, s: u16, p: &PackPlace) -> bool {
        p.claimed_by != 0 || self.wide.contains_key(&(*id, s, SET_CLAIMED))
    }

    /// A place counts as a copy: claimed, its newest claim newer than its
    /// newest drop and than the storage's retirement.
    fn live(&self, id: &PackId, s: u16, p: &PackPlace) -> bool {
        if !self.has_claim(id, s, p) || p.stored_at <= p.dropped_at {
            return false;
        }
        let name = self.tables.storage_name(s).unwrap_or_default();
        self.retired.get(name).is_none_or(|r| p.stored_at > *r)
    }

    fn independently_verified(&self, id: &PackId, s: u16, p: &PackPlace) -> bool {
        if p.verified_at <= p.dropped_at {
            return false;
        }
        let verified = self.set_of(id, s, SET_VERIFIED, p.verified_by);
        let name = self.tables.storage_name(s).unwrap_or_default();
        if name.starts_with("replica:") && !verified.is_empty() {
            return true;
        }
        let claimed = self.set_of(id, s, SET_CLAIMED, p.claimed_by);
        verified.iter().any(|d| !claimed.contains(d))
    }

    /// Storages holding a live copy of the pack, sorted.
    pub fn holders(&self, id: &PackId) -> Vec<&str> {
        let Some(r) = self.packs.get(id) else {
            return Vec::new();
        };
        let mut out: Vec<&str> = r
            .places
            .iter()
            .filter(|(s, p)| self.live(id, *s, p))
            .filter_map(|(s, _)| self.tables.storage_name(*s))
            .collect();
        out.sort_unstable();
        out
    }

    /// Every live copy of the pack with who claimed and verified it.
    pub fn copies(&self, id: &PackId) -> Vec<PackCopy> {
        let Some(r) = self.packs.get(id) else {
            return Vec::new();
        };
        let mut out: Vec<PackCopy> = r
            .places
            .iter()
            .filter(|(s, p)| self.live(id, *s, p))
            .map(|(s, p)| PackCopy {
                storage: self.tables.storage_name(*s).unwrap_or_default().to_string(),
                claimed_by: self.set_of(id, *s, SET_CLAIMED, p.claimed_by),
                verified_by: self.set_of(id, *s, SET_VERIFIED, p.verified_by),
                independently_verified: self.independently_verified(id, *s, p),
                stored_utc: p.stored_utc as i64,
                verified_utc: p.verified_utc as i64,
            })
            .collect();
        out.sort_by(|a, b| a.storage.cmp(&b.storage));
        out
    }

    pub fn is_held(&self, id: &PackId, storage: &str) -> bool {
        let (Some(r), Some(s)) = (self.packs.get(id), self.tables.find_storage(storage)) else {
            return false;
        };
        r.place(s).is_some_and(|p| self.live(id, s, p))
    }

    /// The pack was deliberately removed from `storage` and nobody stored
    /// it there again since (writers do not put it back).
    pub fn dropped_from(&self, id: &PackId, storage: &str) -> bool {
        let (Some(r), Some(s)) = (self.packs.get(id), self.tables.find_storage(storage)) else {
            return false;
        };
        r.place(s)
            .is_some_and(|p| p.dropped_at > 0 && p.stored_at <= p.dropped_at)
    }

    /// Packs with a live copy on `storage` (drains, quotas, staged moves
    /// count packs this way).
    pub fn packs_on<'a>(
        &'a self,
        storage: &str,
    ) -> impl Iterator<Item = (&'a PackId, &'a PackRecord)> + 'a {
        let s = self.tables.find_storage(storage);
        self.packs.iter().filter(move |(id, r)| {
            s.is_some_and(|s| r.place(s).is_some_and(|p| self.live(id, s, p)))
        })
    }

    /// The places of a block with the storages holding each one's pack:
    /// unmarked places first, then places with a dead or lost mark (used
    /// only when no other place exists). Places whose pack is held nowhere
    /// are left out.
    pub fn block_places(&self, object: &ObjectBin, map: &impl BlockMapView) -> Vec<BlockPlace> {
        let mut out: Vec<BlockPlace> = map
            .places_of(object)
            .into_iter()
            .filter_map(|place| {
                let storages: Vec<String> = self
                    .holders(&place.pack)
                    .into_iter()
                    .map(str::to_string)
                    .collect();
                (!storages.is_empty()).then(|| BlockPlace {
                    marked: map.is_marked(&place),
                    place,
                    storages,
                })
            })
            .collect();
        out.sort_by_key(|a| (a.marked, a.place));
        out
    }

    /// Copies of a block: storages holding a live place of it (pack held
    /// there and the place not marked dead or lost). Policies, placement,
    /// staged moves, drains and quotas count this way.
    pub fn block_copies(&self, object: &ObjectBin, map: &impl BlockMapView) -> BTreeSet<String> {
        self.block_places(object, map)
            .into_iter()
            .filter(|p| !p.marked)
            .flat_map(|p| p.storages)
            .collect()
    }

    pub fn stream(&self, kind: u8, scope: &FolderBin, device: &DeviceBin) -> Option<&Stream> {
        self.streams.get(&(kind, *scope, *device))
    }

    /// What the signer's batch announced for record `seq` of a stream (a
    /// record read from a storage is checked against it).
    pub fn announced(
        &self,
        kind: u8,
        scope: &FolderBin,
        device: &DeviceBin,
        seq: u64,
    ) -> Option<&Announced> {
        self.stream(kind, scope, device)?.records.get(&seq)
    }

    /// Count block-map marks the map refused (WP4 calls this).
    pub fn count_marks_refused(&mut self, n: u64) {
        self.marks_refused += n;
    }

    // ---- acknowledgements ------------------------------------------------

    /// The newest batch of `device` that `reader` said it holds: in its
    /// vault batches (full devices), or, when `folder` is given, also in its
    /// folder-scoped batches of that folder (members).
    pub fn acked(&self, reader: &DeviceBin, device: &DeviceBin, folder: Option<&FolderBin>) -> u64 {
        let vault = self
            .acks
            .get(reader)
            .and_then(|a| a.get(device))
            .copied()
            .unwrap_or(0);
        let member = folder
            .and_then(|f| self.folder_acks.get(&(*f, *reader)))
            .and_then(|a| a.get(device))
            .copied()
            .unwrap_or(0);
        vault.max(member)
    }

    /// The writers of `folder` that have not yet acknowledged batch
    /// `batch` of `marker` (the marker itself never waits for itself).
    pub fn settle_waiting_for<'a>(
        &self,
        folder: &FolderBin,
        writers: impl IntoIterator<Item = &'a DeviceBin>,
        marker: &DeviceBin,
        batch: u64,
    ) -> Vec<DeviceBin> {
        let mut out: Vec<DeviceBin> = writers
            .into_iter()
            .filter(|w| *w != marker && self.acked(w, marker, Some(folder)) < batch)
            .copied()
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Section 3 "settled": every current writer of `folder` (owners and
    /// editors, own devices and members, not revoked: the caller's list)
    /// has signed a batch whose `seen` names `marker` at `batch` or later.
    /// Members' folder-scoped acknowledgements count here (and for folder
    /// record pruning), never for vault ledger pruning.
    pub fn settled<'a>(
        &self,
        folder: &FolderBin,
        writers: impl IntoIterator<Item = &'a DeviceBin>,
        marker: &DeviceBin,
        batch: u64,
    ) -> bool {
        self.settle_waiting_for(folder, writers, marker, batch)
            .is_empty()
    }

    /// Vault ledger pruning: every reader other than `device` (full devices
    /// of the vault, trusted and not revoked) said in a vault batch that it
    /// holds `device`'s batches up to `seq`.
    pub fn vault_acked_by_all<'a>(
        &self,
        readers: impl IntoIterator<Item = &'a DeviceBin>,
        device: &DeviceBin,
        seq: u64,
    ) -> bool {
        readers
            .into_iter()
            .filter(|r| *r != device)
            .all(|r| self.acked(r, device, None) >= seq)
    }
}
