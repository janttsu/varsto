// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Data moves and staged moves at pack granularity (design sections 3, 4
//! and 13; spec sections 23 and 59). A move takes the blocks of a folder
//! (or of some of its paths) off one storage and puts them on another.
//!
//! - A pack whose live members are all in scope is copied **whole** (no
//!   key, the bytes are checked against the pack id), claimed with a zero
//!   folder, read back, and only then dropped from the source.
//! - A pack that holds live members outside the scope is not copied: the
//!   members in scope go into **new packs** on the destination (built with
//!   [`crate::packs::first_fit_decreasing`] and [`crate::packs::build`],
//!   padded to size classes), and the members outside the scope into a new
//!   pack on the source (the remainder), after which the old pack goes from
//!   the source. The new places are returned as written packs: the caller
//!   puts them in the mover's map delta ([`crate::blockmap::MapWriter`]),
//!   which also makes their `pack_stored` events.
//! - A disk pool as destination counts its disk group rule by the places
//!   that hold the pack ([`super::pools::group_rule_met`]): a pack whose
//!   places are too few is not dropped from the source yet. A pool disk
//!   without room for a whole pack gets its live members in smaller packs
//!   (halves, each in the smallest class it fits).
//!
//! The source pack is deleted only by [`MoveRun::delete_dropped`], which
//! the caller calls after the map delta is published and the batch with
//! the events is pushed (a drop is in a pushed batch before the bytes go).
//! A move that stops halfway is carried on by planning it again: packs
//! already on the destination are not copied twice, and a pack dropped in
//! the ledger that is still on the source is deleted by the next run.

use std::collections::{BTreeSet, HashMap, HashSet};

use anyhow::Result;

use crate::blockmap::{class_of_len, place_is_live, MapRow, MapTable, WrittenMember, WrittenPack};
use crate::ledger3::events::{Event, PackOn, PackStored};
use crate::ledger3::{FolderBin, LedgerView, ObjectBin, PackId, NO_FOLDER};
use crate::packs::{self, pack_key};
use crate::pool::{pool_error, PoolError, PoolStorage};
use crate::storage::{Storage, MAX_PACK};

/// One member of a pack as the map shows it.
pub type PackMember = MapRow;

/// The live members of the given packs, from one scan of the map table
/// (rows of two writers at one place count once). A member is live when
/// its place is not flagged dead by its writer and carries no dead or
/// lost mark. Dead members are left out.
pub fn members_of_packs(
    table: &MapTable,
    packs: &HashSet<PackId>,
) -> Result<HashMap<PackId, Vec<PackMember>>> {
    let mut out: HashMap<PackId, Vec<PackMember>> = HashMap::new();
    let mut seen: HashSet<(PackId, u32)> = HashSet::new();
    for row in table.scan() {
        let row = row?;
        if !packs.contains(&row.place.pack) {
            continue;
        }
        if !seen.insert((row.place.pack, row.place.offset)) {
            continue;
        }
        let list = out.entry(row.place.pack).or_default();
        if place_is_live(table, &row)? {
            list.push(row);
        }
    }
    for v in out.values_mut() {
        v.sort_by_key(|r| r.place.offset);
    }
    Ok(out)
}

/// What a move does with one pack of the source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackAction {
    /// Every live member is in scope: the pack goes whole. `copy` is false
    /// when the destination holds it already, or every member in scope has
    /// a live place there in other packs.
    Whole {
        pack: PackId,
        class: u8,
        copy: bool,
        /// The destination holds the pack itself (the ledger says so).
        on_destination: bool,
        /// The pack's live members (all in scope).
        members: Vec<PackMember>,
        /// Of those, the members the destination lacks (no live place in
        /// a pack it holds): what a rebuild writes when the pack itself
        /// cannot be read.
        missing: Vec<PackMember>,
    },
    /// Live members outside the scope remain: `moving` go into new packs on
    /// the destination (members the destination lacks only), `staying` into
    /// a new pack on the source, and the old pack goes from the source.
    Rebuild {
        pack: PackId,
        class: u8,
        moving: Vec<PackMember>,
        staying: Vec<PackMember>,
    },
}

impl PackAction {
    pub fn pack(&self) -> &PackId {
        match self {
            PackAction::Whole { pack, .. } | PackAction::Rebuild { pack, .. } => pack,
        }
    }
}

/// A move worked out from the ledger and the map, before anything changes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MovePlan {
    pub folder: FolderBin,
    pub from: String,
    pub to: String,
    pub actions: Vec<PackAction>,
    /// Packs on the source with no live member in scope (they stay).
    pub packs_untouched: u64,
    /// Packs of the folder on the source that the map lists no member of:
    /// not touched (the map may not be pulled completely).
    pub packs_without_members: Vec<PackId>,
    /// Live blocks in scope, and their bytes (object lengths).
    pub blocks: u64,
    pub bytes: u64,
}

/// Plan the move of the blocks `in_scope` accepts from `from` to `to` for
/// one folder. Packs of other folders, packs claimed with no folder and
/// packs the map knows nothing of are not touched.
pub fn plan_move(
    view: &LedgerView,
    table: &MapTable,
    folder: &FolderBin,
    from: &str,
    to: &str,
    in_scope: &dyn Fn(&ObjectBin) -> bool,
) -> Result<MovePlan> {
    let mut plan = MovePlan {
        folder: *folder,
        from: from.to_string(),
        to: to.to_string(),
        ..Default::default()
    };
    let mut packs: Vec<(PackId, u8)> = view
        .packs_on(from)
        .filter(|(id, _)| view.pack_folder(id).is_some_and(|f| f == *folder))
        .map(|(id, r)| (*id, r.class))
        .collect();
    packs.sort_unstable();
    let set: HashSet<PackId> = packs.iter().map(|(id, _)| *id).collect();
    let members = members_of_packs(table, &set)?;
    for (pack, class) in packs {
        let Some(live) = members.get(&pack) else {
            plan.packs_without_members.push(pack);
            continue;
        };
        let (inside, outside): (Vec<&PackMember>, Vec<&PackMember>) =
            live.iter().partition(|m| in_scope(&m.object));
        if inside.is_empty() {
            plan.packs_untouched += 1;
            continue;
        }
        plan.blocks += inside.len() as u64;
        plan.bytes += inside.iter().map(|m| u64::from(m.place.len)).sum::<u64>();
        // Members in scope the destination lacks (no live place in a pack
        // it holds).
        let missing: Vec<PackMember> = inside
            .iter()
            .filter(|m| !view.block_copies(&m.object, table).contains(to))
            .map(|m| **m)
            .collect();
        if outside.is_empty() {
            let on_destination = view.is_held(&pack, to);
            plan.actions.push(PackAction::Whole {
                pack,
                class,
                copy: !on_destination && !missing.is_empty(),
                on_destination,
                members: live.clone(),
                missing,
            });
        } else {
            plan.actions.push(PackAction::Rebuild {
                pack,
                class,
                moving: missing,
                staying: outside.into_iter().copied().collect(),
            });
        }
    }
    Ok(plan)
}

/// A storage a move reads from or writes to.
pub struct Endpoint<'a> {
    pub name: &'a str,
    pub storage: &'a dyn Storage,
    /// Cold storage: packs up to 256 MiB, a write is checked by name only
    /// unless `MoveOptions::confirm_cold_read`.
    pub cold: bool,
    /// The storage is a disk pool (disk group rule, no room per disk).
    pub pool: Option<&'a PoolStorage>,
}

/// Options of a run.
#[derive(Clone, Debug, Default)]
pub struct MoveOptions {
    /// Copy and check, but never drop from the source.
    pub keep_source: bool,
    /// Read a cold destination back to verify it.
    pub confirm_cold_read: bool,
    /// At most this many source packs per run (0: no limit); the report
    /// says when the run stopped early.
    pub max_packs: usize,
    /// A destination without room for a whole pack gets its members in
    /// smaller packs (staged moves to pools).
    pub split_on_no_room: bool,
}

/// What a run did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MoveReport {
    /// Source packs copied whole to the destination.
    pub packs_copied: u64,
    /// New packs written (on the destination, and remainders on the source).
    pub packs_built: u64,
    pub bytes_written: u64,
    /// Source packs that are dropped (and deleted by `delete_dropped`).
    pub packs_dropped: u64,
    /// Blocks now on the destination (in scope), and their bytes.
    pub blocks_moved: u64,
    pub bytes_moved: u64,
    /// Packs whose move was already done (on the destination and dropped
    /// from the source in an earlier run).
    pub already_moved: u64,
    /// Packs not dropped from the source: the destination has too few
    /// places for its disk group rule (packs, bytes).
    pub waiting_place_packs: u64,
    pub waiting_place_bytes: u64,
    /// Packs the destination had no room for (packs, bytes) and the least
    /// room that would help (the smallest block that found none).
    pub waiting_room_packs: u64,
    pub waiting_room_bytes: u64,
    pub waiting_min_bytes: u64,
    /// Source packs whose bytes or members do not match their names: left
    /// alone (repair handles them).
    pub corrupt: Vec<PackId>,
    /// Packs that could not be read or written now (a disk away, an error).
    pub unavailable: Vec<(PackId, String)>,
    pub disks_used: Vec<String>,
    pub stopped_early: bool,
    /// The source packs by what happened to them (for the caller's
    /// reports in blocks): copied whole to the destination, rebuilt into
    /// new packs, dropped from the source, waiting for room or for a
    /// disk group's places.
    pub copied_packs: Vec<PackId>,
    pub rebuilt_packs: Vec<PackId>,
    pub dropped_packs: Vec<PackId>,
    pub waiting_room: Vec<PackId>,
    pub waiting_place: Vec<PackId>,
    /// Blocks in scope that found no room on the destination and went into
    /// the remainder on the source (split moves).
    pub kept_back: Vec<ObjectBin>,
}

/// The result of a run: what the caller publishes and pushes, and then
/// deletes.
#[derive(Clone, Debug, Default)]
pub struct MoveRun {
    /// New packs written, for the mover's map delta
    /// ([`crate::blockmap::MapWriter::publish`] makes their `pack_stored`
    /// events and the delta's announcement).
    pub new_packs: Vec<WrittenPack>,
    /// `pack_stored` and `pack_verified` for packs copied whole, and
    /// `pack_dropped` for source packs that go; same batch as the delta.
    pub events: Vec<Event>,
    /// Source packs to delete after the batch is pushed.
    pub dropped: Vec<PackId>,
    pub report: MoveReport,
}

impl MoveRun {
    /// Delete the dropped packs from the source. Call after the map delta
    /// is published and the batch holding [`MoveRun::events`] is pushed.
    /// Returns how many were deleted.
    pub fn delete_dropped(&self, source: &dyn Storage) -> Result<u64> {
        let mut n = 0;
        for p in &self.dropped {
            source.delete(&pack_key(&hex::encode(p)))?;
            n += 1;
        }
        Ok(n)
    }

    /// Like [`MoveRun::delete_dropped`], going on past a pack that cannot
    /// be deleted now (garbage collection deletes it later: the view shows
    /// it dropped). Returns how many were deleted and the failures.
    pub fn delete_dropped_each(&self, source: &dyn Storage) -> (u64, Vec<(PackId, String)>) {
        let mut n = 0;
        let mut failed = Vec::new();
        for p in &self.dropped {
            match source.delete(&pack_key(&hex::encode(p))) {
                Ok(()) => n += 1,
                Err(e) => failed.push((*p, format!("{e:#}"))),
            }
        }
        (n, failed)
    }
}

/// Packs the ledger shows dropped from `from` that are still there:
/// leftovers of an interrupted move (or of a drop whose delete failed).
pub fn leftovers(view: &LedgerView, from: &str, source: &dyn Storage) -> Result<Vec<PackId>> {
    let mut out = Vec::new();
    for key in source.list(packs::PREFIX)? {
        let Some(id) = packs::pack_of_key(&key) else {
            continue;
        };
        let mut pack = [0u8; 32];
        if hex::decode_to_slice(id, &mut pack).is_err() {
            continue;
        }
        if view.dropped_from(&pack, from) {
            out.push(pack);
        }
    }
    Ok(out)
}

/// Where a run reads what it moves besides the source storage.
pub struct Sources<'a> {
    /// The whole pack from another storage that holds it (whole-pack
    /// copies are readable from any storage the view says holds the pack);
    /// checked here against its id.
    pub pack: &'a dyn Fn(&PackId) -> Option<Vec<u8>>,
    /// The bytes of one member from elsewhere (the files on this device,
    /// the block cache); checked here against the object name.
    pub member: &'a dyn Fn(&PackMember) -> Option<Vec<u8>>,
    /// The source itself may be read (not cold, or the cold read is
    /// confirmed).
    pub read_source: bool,
}

impl Sources<'_> {
    /// The source storage alone.
    pub fn source_only() -> Sources<'static> {
        Sources {
            pack: &|_| None,
            member: &|_| None,
            read_source: true,
        }
    }
}

fn read_pack(ep: &Endpoint, pack: &PackId) -> Result<Option<Vec<u8>>> {
    ep.storage
        .get_bounded(&pack_key(&hex::encode(pack)), MAX_PACK)
}

/// A pack written to `ep` reads back whole and hashes to its id (cold
/// storage: found by name unless a read is confirmed).
fn verified_on(ep: &Endpoint, pack: &PackId, opts: &MoveOptions) -> Result<bool> {
    let key = pack_key(&hex::encode(pack));
    if ep.cold && !opts.confirm_cold_read {
        return ep.storage.exists(&key);
    }
    Ok(ep
        .storage
        .get_bounded(&key, MAX_PACK)?
        .is_some_and(|b| crate::crypto::hash(&b) == *pack))
}

/// A pool with no disk attached: the pack waits like one without room.
fn no_disk(e: &anyhow::Error) -> bool {
    matches!(pool_error(e), Some(PoolError::NoDiskAttached { .. }))
}

fn no_room(e: &anyhow::Error) -> bool {
    matches!(pool_error(e), Some(PoolError::NoRoom { .. }))
}

/// Why a pack could not be handled now.
enum Hold {
    Corrupt,
    NoRoom(u64),
    Unavailable(String),
}

fn hold_of(e: &anyhow::Error) -> Hold {
    Hold::Unavailable(format!("{e:#}"))
}

/// The bytes of a pack's members by object name.
type MemberBytes = HashMap<ObjectBin, Vec<u8>>;

/// A pack's bytes check out: a size class, hashing to its id, and every
/// member in `check` hashing to its object name.
fn pack_checks(bytes: &[u8], pack: &PackId, check: &[&PackMember]) -> bool {
    if class_of_len(bytes.len() as u64).is_none() || crate::crypto::hash(bytes) != *pack {
        return false;
    }
    check.iter().all(|m| {
        let (s, e) = (
            m.place.offset as usize,
            m.place.offset as usize + m.place.len as usize,
        );
        e <= bytes.len() && crate::crypto::hash(&bytes[s..e]) == m.object
    })
}

struct Runner<'a> {
    src: &'a Endpoint<'a>,
    dst: &'a Endpoint<'a>,
    sources: &'a Sources<'a>,
    opts: &'a MoveOptions,
    run: MoveRun,
}

impl Runner<'_> {
    /// Build packs from `members` (their bytes in `bytes`) and write them
    /// to `to`, checking each. Splits in halves when a pool disk has no
    /// room and `split` is set. The written packs are returned; nothing is
    /// recorded in the run yet.
    /// Like [`Runner::build_to`] with halving, but a member that finds no
    /// room is left out instead of failing the lot: (packs written, members
    /// left).
    fn build_partial(
        &mut self,
        to: &Endpoint,
        bytes: &MemberBytes,
        members: &[PackMember],
    ) -> std::result::Result<(Vec<WrittenPack>, Vec<PackMember>), Hold> {
        match self.build_to(to, bytes, members, false) {
            Ok(m) => Ok((m, Vec::new())),
            Err(Hold::NoRoom(_)) if members.len() > 1 => {
                let (a, b) = members.split_at(members.len() / 2);
                let (mut made, mut left) = self.build_partial(to, bytes, a)?;
                let (made_b, left_b) = self.build_partial(to, bytes, b)?;
                made.extend(made_b);
                left.extend(left_b);
                Ok((made, left))
            }
            Err(Hold::NoRoom(_)) => Ok((Vec::new(), members.to_vec())),
            Err(w) => Err(w),
        }
    }

    fn build_to(
        &mut self,
        to: &Endpoint,
        bytes: &MemberBytes,
        members: &[PackMember],
        split: bool,
    ) -> std::result::Result<Vec<WrittenPack>, Hold> {
        if members.is_empty() {
            return Ok(Vec::new());
        }
        let target = if to.cold {
            packs::COLD_TARGET
        } else {
            packs::HOT_TARGET
        };
        let sizes: Vec<usize> = members.iter().map(|m| m.place.len as usize).collect();
        let mut out = Vec::new();
        for mut idx in packs::first_fit_decreasing(&sizes, packs::top_class(target)) {
            idx.sort_unstable(); // the order the pack had
            let group: Vec<&PackMember> = idx.iter().map(|&i| &members[i]).collect();
            let mut named: Vec<(String, &[u8])> = Vec::with_capacity(group.len());
            for m in &group {
                let b = bytes.get(&m.object).ok_or_else(|| {
                    Hold::Unavailable("a member of the pack could not be read".into())
                })?;
                named.push((hex::encode(m.object), b.as_slice()));
            }
            let (id_hex, data, locs) = packs::build(&named, target);
            let mut id = [0u8; 32];
            hex::decode_to_slice(&id_hex, &mut id).map_err(|e| Hold::Unavailable(e.to_string()))?;
            match to.storage.put_if_absent(&pack_key(&id_hex), &data) {
                Ok(_) => {}
                Err(e) if no_disk(&e) => return Err(Hold::NoRoom(0)),
                Err(e) if no_room(&e) && split && group.len() > 1 => {
                    let owned: Vec<PackMember> = group.iter().map(|m| **m).collect();
                    let (a, b) = owned.split_at(owned.len() / 2);
                    out.extend(self.build_to(to, bytes, a, split)?);
                    out.extend(self.build_to(to, bytes, b, split)?);
                    continue;
                }
                Err(e) if no_room(&e) => {
                    return Err(Hold::NoRoom(
                        group
                            .iter()
                            .map(|m| u64::from(m.place.len))
                            .min()
                            .unwrap_or(0),
                    ))
                }
                Err(e) => return Err(hold_of(&e)),
            }
            if !verified_on(to, &id, self.opts).map_err(|e| hold_of(&e))? {
                return Err(Hold::Unavailable(format!(
                    "pack {id_hex} does not read back from {}",
                    to.name
                )));
            }
            let class = class_of_len(data.len() as u64)
                .ok_or_else(|| Hold::Unavailable("a built pack is not a size class".into()))?;
            packs::debug_registry::written(&locs);
            self.note_pool_disks(to, &id);
            self.run.report.packs_built += 1;
            self.run.report.bytes_written += data.len() as u64;
            out.push(WrittenPack {
                id,
                class,
                storages: vec![to.name.to_string()],
                members: group
                    .iter()
                    .zip(locs)
                    .map(|(m, (_, loc))| WrittenMember {
                        object: m.object,
                        chunk: m.chunk,
                        offset: loc.offset as u32,
                        len: loc.len as u32,
                        plain_len: m.plain_len,
                        epoch: m.epoch,
                    })
                    .collect(),
            });
        }
        Ok(out)
    }

    /// Read a source pack whole and check it (a size class, its bytes
    /// hashing to its id, every member in `check` to its object name):
    /// from another storage that holds it, or from the source when it may
    /// be read.
    fn read_checked(
        &self,
        pack: &PackId,
        check: &[&PackMember],
    ) -> std::result::Result<Vec<u8>, Hold> {
        if let Some(b) = (self.sources.pack)(pack) {
            if pack_checks(&b, pack, check) {
                return Ok(b);
            }
        }
        if !self.sources.read_source {
            return Err(Hold::Unavailable(format!(
                "the only copy to read is on cold storage {}: confirm the cold read to move it",
                self.src.name
            )));
        }
        let bytes = read_pack(self.src, pack)
            .map_err(|e| hold_of(&e))?
            .ok_or_else(|| Hold::Unavailable("not on the source".into()))?;
        if !pack_checks(&bytes, pack, check) {
            return Err(Hold::Corrupt);
        }
        Ok(bytes)
    }

    /// The bytes of `members` of a pack: sliced from the pack when it can
    /// be read whole, else each from the member source (checked against
    /// its name).
    fn member_bytes(
        &self,
        pack: &PackId,
        members: &[&PackMember],
    ) -> std::result::Result<MemberBytes, Hold> {
        let mut out = MemberBytes::new();
        match self.read_checked(pack, members) {
            Ok(bytes) => {
                for m in members {
                    let s = m.place.offset as usize;
                    out.insert(m.object, bytes[s..s + m.place.len as usize].to_vec());
                }
                Ok(out)
            }
            Err(Hold::Corrupt) => Err(Hold::Corrupt),
            Err(why) => {
                for m in members {
                    match (self.sources.member)(m) {
                        Some(b) if crate::crypto::hash(&b) == m.object => {
                            out.insert(m.object, b);
                        }
                        _ => return Err(why),
                    }
                }
                Ok(out)
            }
        }
    }

    fn hold(&mut self, pack: &PackId, class: u8, why: Hold) {
        let r = &mut self.run.report;
        let size = crate::ledger3::events::class_bytes(class).unwrap_or(0);
        match why {
            Hold::Corrupt => r.corrupt.push(*pack),
            Hold::NoRoom(min) => {
                r.waiting_room_packs += 1;
                r.waiting_room_bytes += size;
                r.waiting_min_bytes = if r.waiting_min_bytes == 0 {
                    min
                } else {
                    r.waiting_min_bytes.min(min)
                };
                r.waiting_room.push(*pack);
            }
            Hold::Unavailable(e) => r.unavailable.push((*pack, e)),
        }
    }

    fn claim_copy(&mut self, pack: &PackId, class: u8) {
        self.run.events.push(Event::PackStored(PackStored {
            storage: self.dst.name.to_string(),
            pack: *pack,
            class,
            folder: NO_FOLDER,
            map_seq: 0,
        }));
        // A read-back of a cold copy checked by name only is not a
        // verification.
        if !self.dst.cold || self.opts.confirm_cold_read {
            self.run.events.push(Event::PackVerified(PackOn {
                storage: self.dst.name.to_string(),
                pack: *pack,
            }));
        }
    }

    fn drop_source(&mut self, pack: &PackId) {
        if self.opts.keep_source {
            return;
        }
        self.run.events.push(Event::PackDropped(PackOn {
            storage: self.src.name.to_string(),
            pack: *pack,
        }));
        self.run.dropped.push(*pack);
        self.run.report.packs_dropped += 1;
        self.run.report.dropped_packs.push(*pack);
    }

    /// Make sure the destination holds the pack (copying it if `copy`),
    /// checked and counted by its places. False: the pack is held back (or
    /// was handled by `rebuilt`, when it could not be read whole but its
    /// `missing` members could).
    fn ensure(
        &mut self,
        pack: &PackId,
        class: u8,
        copy: bool,
        on_destination: bool,
        live: &[PackMember],
        missing: &[PackMember],
    ) -> bool {
        let check: Vec<&PackMember> = live.iter().collect();
        if copy {
            let data = match self.read_checked(pack, &check) {
                Ok(d) => d,
                Err(Hold::Corrupt) => {
                    self.hold(pack, class, Hold::Corrupt);
                    return false;
                }
                Err(w) => {
                    // The pack cannot be read whole: the members the
                    // destination lacks may come from elsewhere.
                    let need: Vec<&PackMember> = missing.iter().collect();
                    if !need.is_empty() {
                        if let Ok(bytes) = self.member_bytes(pack, &need) {
                            self.rebuilt(pack, class, &bytes, missing, &[]);
                            return false;
                        }
                    }
                    self.hold(pack, class, w);
                    return false;
                }
            };
            match self
                .dst
                .storage
                .put_if_absent(&pack_key(&hex::encode(pack)), &data)
            {
                Ok(written) => {
                    if written {
                        self.run.report.packs_copied += 1;
                        self.run.report.bytes_written += data.len() as u64;
                    }
                }
                Err(e) if no_disk(&e) => {
                    self.hold(pack, class, Hold::NoRoom(0));
                    return false;
                }
                Err(e) if no_room(&e) && self.opts.split_on_no_room && live.len() > 1 => {
                    let mut bytes = MemberBytes::new();
                    for m in live {
                        let s = m.place.offset as usize;
                        bytes.insert(m.object, data[s..s + m.place.len as usize].to_vec());
                    }
                    self.rebuilt(pack, class, &bytes, live, &[]);
                    return false;
                }
                Err(e) if no_room(&e) => {
                    let min = live
                        .iter()
                        .map(|m| u64::from(m.place.len))
                        .min()
                        .unwrap_or(0);
                    self.hold(pack, class, Hold::NoRoom(min));
                    return false;
                }
                Err(e) => {
                    self.hold(pack, class, hold_of(&e));
                    return false;
                }
            }
        }
        // The pack is on the destination (copied now, or held already):
        // read back and hashed, then counted by the pool's places.
        if copy || on_destination {
            match verified_on(self.dst, pack, self.opts) {
                Ok(true) => {}
                Ok(false) => {
                    let why = Hold::Unavailable(format!("not on {} after the copy", self.dst.name));
                    self.hold(pack, class, why);
                    return false;
                }
                Err(e) => {
                    self.hold(pack, class, hold_of(&e));
                    return false;
                }
            }
            if copy {
                self.claim_copy(pack, class);
                self.run.report.copied_packs.push(*pack);
                let dst = self.dst;
                self.note_pool_disks(dst, pack);
            }
            if let Some(pool) = self.dst.pool {
                let mut used = Vec::new();
                let met = super::pools::group_rule_met(pool, pack, &mut used);
                self.note_disks(used);
                if !met {
                    self.run.report.waiting_place_packs += 1;
                    self.run.report.waiting_place_bytes +=
                        crate::ledger3::events::class_bytes(class).unwrap_or(0);
                    self.run.report.waiting_place.push(*pack);
                    return false;
                }
            }
        }
        // Otherwise every member in scope has a live place in other packs
        // on the destination already.
        true
    }

    fn whole(
        &mut self,
        pack: &PackId,
        class: u8,
        copy: bool,
        on_destination: bool,
        live: &[PackMember],
        missing: &[PackMember],
    ) {
        if self.ensure(pack, class, copy, on_destination, live, missing) {
            self.run.report.blocks_moved += live.len() as u64;
            self.run.report.bytes_moved += live.iter().map(|m| u64::from(m.place.len)).sum::<u64>();
            self.drop_source(pack);
        }
    }

    /// The disks of a pool destination that hold `pack` now (reported as
    /// used).
    fn note_pool_disks(&mut self, to: &Endpoint, pack: &PackId) {
        if let Some(pool) = to.pool {
            let labels = pool
                .locate_all(&pack_key(&hex::encode(pack)))
                .into_iter()
                .map(|l| l.label)
                .collect();
            self.note_disks(labels);
        }
    }

    fn note_disks(&mut self, used: Vec<String>) {
        for l in used {
            if !self.run.report.disks_used.contains(&l) {
                self.run.report.disks_used.push(l);
            }
        }
    }

    /// `moving` into new packs on the destination (halved while a pool disk
    /// lacks room), `staying` into a new pack on the source, then the old
    /// pack goes.
    fn rebuilt(
        &mut self,
        pack: &PackId,
        class: u8,
        bytes: &MemberBytes,
        moving: &[PackMember],
        staying: &[PackMember],
    ) {
        let split = self.opts.split_on_no_room;
        let (dst, src) = (self.dst, self.src);
        // With `split` a destination without room for every member takes
        // what fits; the rest stays on the source (in the remainder).
        let (made, left) = if split {
            match self.build_partial(dst, bytes, moving) {
                Ok(x) => x,
                Err(w) => return self.hold(pack, class, w),
            }
        } else {
            match self.build_to(dst, bytes, moving, false) {
                Ok(m) => (m, Vec::new()),
                Err(w) => return self.hold(pack, class, w),
            }
        };
        if !left.is_empty() && made.is_empty() {
            // Nothing fitted: the pack stays as it is.
            let min = left
                .iter()
                .map(|m| u64::from(m.place.len))
                .min()
                .unwrap_or(0);
            return self.hold(pack, class, Hold::NoRoom(min));
        }
        if !left.is_empty() {
            let r = &mut self.run.report;
            r.waiting_room_packs += 1;
            r.waiting_room_bytes += left.iter().map(|m| u64::from(m.place.len)).sum::<u64>();
            let min = left
                .iter()
                .map(|m| u64::from(m.place.len))
                .min()
                .unwrap_or(0);
            r.waiting_min_bytes = if r.waiting_min_bytes == 0 {
                min
            } else {
                r.waiting_min_bytes.min(min)
            };
            r.kept_back.extend(left.iter().map(|m| m.object));
        }
        let moving: Vec<PackMember> = moving
            .iter()
            .filter(|m| !left.iter().any(|l| l.object == m.object))
            .copied()
            .collect();
        let staying: Vec<PackMember> = staying.iter().chain(left.iter()).copied().collect();
        let (moving, staying) = (&moving[..], &staying[..]);
        let ids: Vec<PackId> = made.iter().map(|p| p.id).collect();
        self.run.new_packs.extend(made);
        if let Some(pool) = self.dst.pool {
            // Group rule: each new pack counts by its places.
            for id in ids {
                let mut used = Vec::new();
                let met = super::pools::group_rule_met(pool, &id, &mut used);
                self.note_disks(used);
                if !met {
                    self.run.report.waiting_place_packs += 1;
                    self.run.report.waiting_place_bytes +=
                        crate::ledger3::events::class_bytes(class).unwrap_or(0);
                    self.run.report.waiting_place.push(*pack);
                    return;
                }
            }
        }
        if !self.opts.keep_source {
            let rest = match self.build_to(src, bytes, staying, false) {
                Ok(m) => m,
                Err(w) => return self.hold(pack, class, w),
            };
            self.run.new_packs.extend(rest);
        }
        self.run.report.blocks_moved += moving.len() as u64;
        self.run.report.bytes_moved += moving.iter().map(|m| u64::from(m.place.len)).sum::<u64>();
        self.run.report.rebuilt_packs.push(*pack);
        self.drop_source(pack);
    }
}

/// Carry out a plan from `src` to `dst`, reading only from the source.
/// See [`run_move_with`].
pub fn run_move(plan: &MovePlan, src: &Endpoint, dst: &Endpoint, opts: &MoveOptions) -> MoveRun {
    run_move_with(plan, src, dst, &Sources::source_only(), opts)
}

/// Carry out a plan from `src` to `dst`. Nothing is deleted: the caller
/// publishes the map delta for [`MoveRun::new_packs`], pushes a batch with
/// the delta's events and [`MoveRun::events`], and then calls
/// [`MoveRun::delete_dropped`].
///
/// A source pack is dropped only when its members in scope are on the
/// destination and checked (read back whole, hashed against the id; a
/// cold destination by name unless `confirm_cold_read`), and, for a pool
/// destination, when the pool holds the pack in as many places as its disk
/// group rule asks. `keep_source` copies and checks but drops nothing. A
/// pack is read from another storage that holds it first (`sources`), from
/// the source when it may be read, and member by member from the member
/// source when neither has it (then the members go into new packs).
pub fn run_move_with(
    plan: &MovePlan,
    src: &Endpoint,
    dst: &Endpoint,
    sources: &Sources,
    opts: &MoveOptions,
) -> MoveRun {
    let mut r = Runner {
        src,
        dst,
        sources,
        opts,
        run: MoveRun::default(),
    };
    for (done, a) in plan.actions.iter().enumerate() {
        if opts.max_packs > 0 && done >= opts.max_packs {
            r.run.report.stopped_early = true;
            break;
        }
        match a {
            PackAction::Whole {
                pack,
                class,
                copy,
                on_destination,
                members,
                missing,
            } => r.whole(pack, *class, *copy, *on_destination, members, missing),
            PackAction::Rebuild {
                pack,
                class,
                moving,
                staying,
            } => {
                let all: Vec<&PackMember> = moving.iter().chain(staying.iter()).collect();
                let bytes = match r.member_bytes(pack, &all) {
                    Ok(b) => b,
                    Err(w) => {
                        r.hold(pack, *class, w);
                        continue;
                    }
                };
                r.rebuilt(pack, *class, &bytes, moving, staying);
            }
        }
    }
    r.run
}

/// Objects a plan moves (for reports and for the caller's scope checks).
pub fn objects_moving(plan: &MovePlan) -> BTreeSet<ObjectBin> {
    let mut out = BTreeSet::new();
    for a in &plan.actions {
        match a {
            PackAction::Whole { members, .. } => out.extend(members.iter().map(|m| m.object)),
            PackAction::Rebuild { moving, .. } => out.extend(moving.iter().map(|m| m.object)),
        }
    }
    out
}

/// Carry out a drain plan: each pack with `copy_to` is copied whole to
/// every storage named (`dsts`, by name), checked and claimed, and then
/// dropped from the source `src` (not with `keep_source`). A pack whose
/// plan is blocked is left alone. Like [`run_move`], nothing is deleted:
/// the caller pushes the batch with [`MoveRun::events`] first and calls
/// [`MoveRun::delete_dropped`].
pub fn run_drain(
    view: &LedgerView,
    plan: &super::drain::DrainPlan,
    src: &Endpoint,
    dsts: &[Endpoint],
    opts: &MoveOptions,
) -> MoveRun {
    run_drain_with(view, plan, src, dsts, &Sources::source_only(), opts)
}

/// [`run_drain`] reading packs from other storages that hold them first
/// (`sources`).
pub fn run_drain_with(
    view: &LedgerView,
    plan: &super::drain::DrainPlan,
    src: &Endpoint,
    dsts: &[Endpoint],
    sources: &Sources,
    opts: &MoveOptions,
) -> MoveRun {
    let mut r = Runner {
        src,
        dst: src,
        sources,
        opts,
        run: MoveRun::default(),
    };
    for (done, item) in plan
        .items
        .iter()
        .filter(|i| i.shortfall.is_none())
        .enumerate()
    {
        if opts.max_packs > 0 && done >= opts.max_packs {
            r.run.report.stopped_early = true;
            break;
        }
        let mut ready = true;
        for t in &item.copy_to {
            let Some(dst) = dsts.iter().find(|d| d.name == t.as_str()) else {
                r.hold(
                    &item.pack,
                    item.class,
                    Hold::Unavailable(format!("{t} is not open")),
                );
                ready = false;
                break;
            };
            r.dst = dst;
            // The copy is needed unless the ledger shows the pack there.
            let on = view.is_held(&item.pack, t);
            if !r.ensure(&item.pack, item.class, !on, on, &[], &[]) {
                ready = false;
                break;
            }
        }
        if ready {
            r.run.report.blocks_moved += item.needed_blocks;
            r.drop_source(&item.pack);
        }
    }
    r.run
}
