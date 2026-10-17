// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Verification and repair per pack (section 3, "Verification and
//! repair"; section 26 per pack).
//!
//! Verification reads a whole pack (one GET) and compares its BLAKE3 with
//! the pack id: no folder key is needed, so K3-only devices and replicas
//! verify too. Repair is for a device that writes the folder's maps: it
//! checks every member against its name, fetches corrupt members from
//! elsewhere, writes the good members into a new pack on that storage
//! (cold ones too: a damaged pack must not keep counting), puts `lost`
//! marks on places no copy of the pack gives, and drops the damaged pack.
//! A pack missing on one storage but held on another is copied whole.
//! Which packs to verify when, in which lanes and how fast (section 39)
//! stays with the caller; these functions handle one pack.

use std::collections::BTreeMap;

use anyhow::{bail, Result};

use super::collect::write_packs;
use super::{folder_pack, Commit, MapOut, Standing, Storages};
use crate::blockmap::{MapRow, MapTable, MapWriter};
use crate::ledger3::events::{class_bytes, Event, PackOn, PackStored};
use crate::ledger3::{LedgerView, ObjectBin, PackId, Place, NO_FOLDER};
use crate::packs::pack_key;
use crate::storage::Storage;

/// The outcome of reading one pack back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackCheck {
    /// Its BLAKE3 is its id.
    Good,
    /// The storage does not have it.
    Missing,
    /// It is there with a length other than its class.
    WrongLength(u64),
    /// Its bytes do not hash to its id.
    Mismatch,
}

/// One pack verified on one storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub check: PackCheck,
    /// `pack_verified` for the batch when the pack is good.
    pub event: Option<Event>,
    /// The bytes read when they are damaged (repair checks the members in
    /// them without reading the pack again).
    pub damaged: Option<Vec<u8>>,
}

/// Read pack `pack` of size class `class` from `storage` (one GET) and
/// compare its BLAKE3 with the id. Needs no key. `Err` only for storage
/// errors.
pub fn verify_pack(storage: &dyn Storage, pack: &PackId, class: u8) -> Result<Verified> {
    let Some(size) = class_bytes(class) else {
        bail!("pack {} has class {class}", hex::encode(pack));
    };
    let key = pack_key(&hex::encode(pack));
    // A larger object than its class is read up to the largest pack only.
    let bytes = match storage.get_bounded(&key, crate::storage::MAX_PACK) {
        Ok(b) => b,
        Err(e) if storage.exists(&key).unwrap_or(false) => {
            log::warn!(storage = storage.name(); "verify {}: {e:#}", hex::encode(pack));
            return Ok(Verified {
                check: PackCheck::WrongLength(crate::storage::MAX_PACK + 1),
                event: None,
                damaged: None,
            });
        }
        Err(e) => return Err(e),
    };
    let Some(bytes) = bytes else {
        return Ok(Verified {
            check: PackCheck::Missing,
            event: None,
            damaged: None,
        });
    };
    if bytes.len() as u64 != size {
        return Ok(Verified {
            check: PackCheck::WrongLength(bytes.len() as u64),
            event: None,
            damaged: Some(bytes),
        });
    }
    if crate::crypto::hash(&bytes) != *pack {
        return Ok(Verified {
            check: PackCheck::Mismatch,
            event: None,
            damaged: Some(bytes),
        });
    }
    Ok(Verified {
        check: PackCheck::Good,
        event: Some(Event::PackVerified(PackOn {
            storage: storage.name().to_string(),
            pack: *pack,
        })),
        damaged: None,
    })
}

/// Copy a pack missing on (or damaged on) `to` whole from another storage
/// that holds it in the view, checked against its id, and return the
/// `pack_stored` claim for it under the same id (no key needed). A
/// replica claims with the zero folder and map seq 0. `Ok(None)`: no
/// other storage gave a good copy.
pub fn copy_missing_pack(
    view: &LedgerView,
    pack: &PackId,
    to: &str,
    storages: &dyn Storages,
    as_replica: bool,
) -> Result<Option<Event>> {
    let Some(rec) = view.pack(pack) else {
        return Ok(None);
    };
    let Some(size) = class_bytes(rec.class) else {
        return Ok(None);
    };
    let target = storages
        .open(to)
        .ok_or_else(|| anyhow::anyhow!("storage {to} is not reachable"))?;
    let key = pack_key(&hex::encode(pack));
    for from in view.holders(pack) {
        if from == to {
            continue;
        }
        let Some(s) = storages.open(from) else {
            continue;
        };
        let bytes = match s.get_bounded(&key, size) {
            Ok(Some(b)) => b,
            Ok(None) => continue,
            Err(e) => {
                log::warn!(storage = from; "copy pack {}: {e:#}", hex::encode(pack));
                continue;
            }
        };
        if bytes.len() as u64 != size || crate::crypto::hash(&bytes) != *pack {
            continue;
        }
        if !target.put_if_absent(&key, &bytes)? {
            // Something is there under the id: replace it only if it is
            // not the pack (a damaged copy).
            let there = target
                .get_bounded(&key, crate::storage::MAX_PACK)
                .ok()
                .flatten();
            if there.as_deref().map(crate::crypto::hash) != Some(*pack) {
                target.delete(&key)?;
                target.put_if_absent(&key, &bytes)?;
            }
        }
        let (folder, map_seq) = if as_replica {
            (NO_FOLDER, 0)
        } else {
            (view.pack_folder(pack).unwrap_or(NO_FOLDER), rec.map_seq)
        };
        return Ok(Some(Event::PackStored(PackStored {
            storage: to.to_string(),
            pack: *pack,
            class: rec.class,
            folder,
            map_seq,
        })));
    }
    Ok(None)
}

/// A fetcher of corrupt members from the other places of their object
/// (other packs on any storage holding them), each read checked against
/// the object's name. Peers, the local file and the block cache are the
/// caller's fetchers, tried after this one.
pub fn other_places<'a>(
    table: &'a MapTable,
    view: &'a LedgerView,
    storages: &'a dyn Storages,
    exclude: PackId,
) -> impl Fn(&MapRow) -> Option<Vec<u8>> + 'a {
    move |row: &MapRow| {
        let rows = table.rows_of(&row.object).ok()?;
        for r in rows.iter().filter(|r| r.place.pack != exclude) {
            for h in view.holders(&r.place.pack) {
                let Some(s) = storages.open(h) else { continue };
                let p = &r.place;
                if let Ok(Some(b)) = s.get_range(
                    &pack_key(&hex::encode(p.pack)),
                    u64::from(p.offset),
                    u64::from(p.len),
                ) {
                    if crate::crypto::hash(&b) == row.object {
                        return Some(b);
                    }
                }
            }
        }
        None
    }
}

/// What a repair did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RepairReport {
    /// This device may not repair (it writes no maps of the folder).
    pub refused: bool,
    /// The table lists no member of the pack (another folder's pack, or
    /// the map has not arrived): nothing was done.
    pub unknown: bool,
    /// Members whose bytes in the damaged pack were good.
    pub good: u64,
    /// Corrupt members fetched from another copy of the same pack, and
    /// from elsewhere (another pack, a peer, the local file, the cache).
    pub from_same_place: Vec<ObjectBin>,
    pub from_elsewhere: Vec<ObjectBin>,
    /// Members with no good copy anywhere: they keep their `lost` mark
    /// and the files using them are damaged until a device that holds them
    /// writes them again.
    pub lost: Vec<ObjectBin>,
    /// New packs on the storage, and the map record listing them.
    pub new_packs: Vec<PackId>,
    pub map_seq: u64,
}

/// Repair pack `pack` on `storage`, whose bytes as read are `damaged`
/// (from `verify_pack`): check every member the table lists against its
/// name; take corrupt ones from the same place on another storage holding
/// the pack, else from `fetch` (checked against the name); write every
/// good member into new packs on `storage`; publish a map delta with the
/// new places and `lost` marks on places no copy of the pack gives; one
/// batch with `pack_stored` for the new packs and `pack_dropped` for the
/// damaged one on `storage`; then delete it there.
#[allow(clippy::too_many_arguments)]
pub fn repair_pack(
    standing: &Standing,
    writer: &mut MapWriter,
    table: &mut MapTable,
    view: &LedgerView,
    out: &MapOut,
    storages: &dyn Storages,
    storage: &str,
    pack: &PackId,
    damaged: &[u8],
    fetch: &dyn Fn(&MapRow) -> Option<Vec<u8>>,
    sink: &mut dyn Commit,
) -> Result<RepairReport> {
    let mut report = RepairReport::default();
    if !standing.may_repair() || writer.device != standing.device {
        report.refused = true;
        return Ok(report);
    }
    let mut members: BTreeMap<u32, MapRow> = BTreeMap::new();
    for row in table.scan() {
        let row = row?;
        if row.place.pack == *pack {
            members.entry(row.place.offset).or_insert(row);
        }
    }
    if members.is_empty() {
        report.unknown = true;
        return Ok(report);
    }
    let target = storages.info(storage).target();
    let key = pack_key(&hex::encode(pack));
    let mut keep: Vec<(MapRow, Vec<u8>)> = Vec::new();
    let mut lost_places: Vec<(ObjectBin, Place)> = Vec::new();
    for row in members.values() {
        let (o, l) = (row.place.offset as usize, row.place.len as usize);
        if let Some(b) = damaged.get(o..o + l) {
            if crate::crypto::hash(b) == row.object {
                report.good += 1;
                keep.push((*row, b.to_vec()));
                continue;
            }
        }
        // The same place on another storage that holds the pack.
        let mut same = None;
        for h in view.holders(pack) {
            if h == storage {
                continue;
            }
            let Some(s) = storages.open(h) else { continue };
            if let Ok(Some(b)) = s.get_range(&key, o as u64, l as u64) {
                if crate::crypto::hash(&b) == row.object {
                    same = Some(b);
                    break;
                }
            }
        }
        if let Some(b) = same {
            report.from_same_place.push(row.object);
            keep.push((*row, b));
            continue;
        }
        lost_places.push((row.object, row.place));
        match fetch(row).filter(|b| crate::crypto::hash(b) == row.object) {
            Some(b) => {
                report.from_elsewhere.push(row.object);
                keep.push((*row, b));
            }
            None => report.lost.push(row.object),
        }
    }
    let refs: Vec<(MapRow, &[u8])> = keep.iter().map(|(r, b)| (*r, &b[..])).collect();
    let written = write_packs(&refs, &[storage.to_string()], target, storages)?;
    report.new_packs = written.iter().map(|p| p.id).collect();
    writer.mark_lost(&lost_places);
    let lamport = sink.tick();
    let p = writer.publish(out.writer, out.meta, &written, lamport, Some(table), view)?;
    report.map_seq = p.body.seq;
    let mut events = p.events.clone();
    events.push(Event::PackDropped(PackOn {
        storage: storage.to_string(),
        pack: *pack,
    }));
    if let Err(e) = sink.commit(events) {
        *writer =
            MapWriter::from_view(writer.folder, writer.device, writer.epoch, view, p.body.seq);
        return Err(e);
    }
    p.apply_to(table, &folder_pack(view, writer.folder))?;
    if let Some(s) = storages.open(storage) {
        if let Err(e) = s.delete(&key) {
            log::warn!(storage = storage; "repair: delete damaged pack {}: {e:#}", hex::encode(pack));
        }
    }
    Ok(report)
}
