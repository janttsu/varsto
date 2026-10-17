// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The reader side of the block map (section 3, "Reader", "Finding a
//! block"): lookups on the table, the ledger view's `BlockMapView`, the
//! pull of new map records into the table, and the ranged read of a block
//! through the places the table gives.

use std::sync::{Arc, RwLock};

use anyhow::{anyhow, Result};

use super::record::{BlockMap, MarkKind};
use super::table::{ApplyReport, MapRow, MapTable, MapUpdate};
use crate::ledger3::envelope::kind::BLOCK_MAP;
use crate::ledger3::{BlockMapView, LedgerView, ObjectBin, Place};
use crate::packs::{pack_key, PackLoc, PlaceSource};
use crate::record::{Kind, RecordStore, RecordsRefused, StreamRef};
use crate::storage::Storage;

impl MapTable {
    /// The places of `object`, live ones first (rows of two writers at one
    /// place count once).
    pub fn places_of(&self, object: &ObjectBin) -> Result<Vec<Place>> {
        let mut rows = self.rows_of(object)?;
        let mut keyed = Vec::with_capacity(rows.len());
        for r in rows.drain(..) {
            let dead =
                r.flagged_dead() || self.mark_state(&r.place.pack, r.place.offset)?.is_dead();
            keyed.push((dead, r.place));
        }
        keyed.sort();
        keyed.dedup_by_key(|(_, p)| *p);
        Ok(keyed.into_iter().map(|(_, p)| p).collect())
    }

    /// The mark that decides a place: lost, else the newest of dead and
    /// undead; `None` without marks.
    pub fn is_marked(&self, place: &Place) -> Result<Option<MarkKind>> {
        Ok(self.mark_state(&place.pack, place.offset)?.kind())
    }

    /// The places of chunk `chunk` sealed under `epoch`.
    pub fn places_of_chunk(&self, chunk: &[u8; 32], epoch: u32) -> Result<Vec<MapRow>> {
        Ok(self
            .rows_of_chunk(chunk)?
            .into_iter()
            .filter(|r| r.epoch == epoch)
            .collect())
    }

    /// One place of chunk `chunk` under `epoch`: a live one if there is
    /// one, else any.
    pub fn place_of_chunk(&self, chunk: &[u8; 32], epoch: u32) -> Result<Option<MapRow>> {
        let rows = self.places_of_chunk(chunk, epoch)?;
        for r in &rows {
            if super::dedup::place_is_live(self, r)? {
                return Ok(Some(*r));
            }
        }
        Ok(rows.into_iter().next())
    }
}

/// The ledger view asks the table (`LedgerView::block_places`,
/// `block_copies`). A read error counts as "no place" and is logged: the
/// table is rebuilt when it fails its checks.
impl BlockMapView for MapTable {
    fn places_of(&self, object: &ObjectBin) -> Vec<Place> {
        MapTable::places_of(self, object).unwrap_or_else(|e| {
            log::warn!("block map table {}: {e:#}", self.path().display());
            Vec::new()
        })
    }
    fn is_marked(&self, place: &Place) -> bool {
        match MapTable::is_marked(self, place) {
            Ok(k) => matches!(k, Some(MarkKind::Dead | MarkKind::Lost)),
            Err(e) => {
                log::warn!("block map table {}: {e:#}", self.path().display());
                false
            }
        }
    }
}

/// The pack layer's place hand-over: a format-3 engine gives the
/// `PackContext` its folders' tables (`PackContext::add_place_source`), and
/// a `PackStore` reads `chunks/<xx>/<object>` from the places the tables
/// list, live ones first.
impl PlaceSource for RwLock<MapTable> {
    fn places(&self, object: &str) -> Vec<PackLoc> {
        let mut bin = [0u8; 32];
        if hex::decode_to_slice(object, &mut bin).is_err() {
            return Vec::new();
        }
        let Ok(t) = self.read() else {
            return Vec::new();
        };
        let rows = match t.rows_of(&bin) {
            Ok(r) => r,
            Err(e) => {
                log::warn!("block map table {}: {e:#}", t.path().display());
                return Vec::new();
            }
        };
        let mut out: Vec<(bool, PackLoc)> = rows
            .into_iter()
            .map(|r| {
                let dead = !super::dedup::place_is_live(&t, &r).unwrap_or(false);
                (
                    dead,
                    PackLoc {
                        pack: hex::encode(r.place.pack),
                        offset: u64::from(r.place.offset),
                        len: u64::from(r.place.len),
                        pack_len: r.pack_len(),
                    },
                )
            })
            .collect();
        out.sort();
        out.dedup_by(|a, b| a.1 == b.1);
        out.into_iter().map(|(_, l)| l).collect()
    }
}

/// Pull new map records of the table's folder from one metadata storage.
/// Only streams whose announced newest seq is past the one applied are
/// listed; a stream with a newer announced base is read from that base
/// (its writer's rows are replaced). Records are accepted by `store`'s
/// acceptor (refusals land in `refused`) and their announced base must be
/// the body's. Marks on packs the view gives to another folder are counted
/// in the report (`marks_refused`; add them to the view with
/// `count_marks_refused`).
pub fn pull(
    table: &mut MapTable,
    store: &RecordStore,
    view: &LedgerView,
    refused: &mut RecordsRefused,
) -> Result<ApplyReport> {
    let folder = *table.folder();
    let mut updates = Vec::new();
    let mut skipped = Vec::new();
    for ((kind, scope, device), stream) in &view.streams {
        if *kind != BLOCK_MAP || *scope != folder {
            continue;
        }
        let Some(newest) = stream.newest() else {
            continue;
        };
        let marker = table.marker(device);
        let base = stream.base().map(|b| b.0);
        let after = match (base, marker) {
            (Some(b), m) if m.is_none_or(|m| b > m.base) => b - 1,
            (_, Some(m)) if newest > m.applied => m.applied,
            _ => continue,
        };
        let read = store.read_after::<BlockMap>(
            &StreamRef::new(Kind::BlockMap, folder, *device),
            after,
            refused,
        )?;
        let mut records = Vec::new();
        for r in read.accepted {
            if r.meta.seq > newest {
                break;
            }
            match view.announced(BLOCK_MAP, &folder, device, r.meta.seq) {
                Some(a) if a.base == r.body.base => records.push((r.body, r.meta.body_hash)),
                _ => {
                    skipped.push((*device, r.meta.seq, "announced another base".to_string()));
                    break;
                }
            }
        }
        if !records.is_empty() {
            updates.push(MapUpdate {
                device: *device,
                records,
            });
        }
    }
    // A pack the view does not know (its claim has not arrived) is not
    // known to be of another folder: its marks are kept.
    let mut report = table.apply(updates, &|p| {
        view.pack_folder(p).is_none_or(|f| f == folder)
    })?;
    report.skipped.extend(skipped);
    Ok(report)
}

/// A block read through its places.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundBlock {
    /// The object, checked against its name.
    pub bytes: Vec<u8>,
    /// The place it was read from (chunk id, epoch and lengths to open it).
    pub row: MapRow,
    pub storage: String,
    /// The place carries a dead or lost mark (used only when no other
    /// place had it).
    pub marked: bool,
}

/// Section 3, "Finding a block": object name -> places (table) -> storages
/// holding each pack (view: claimed, not dropped, not retired) -> one
/// ranged read -> the object checked against its name. Unmarked places
/// first. `storage` opens a storage by name (`None`: not reachable from
/// here). `Ok(None)`: no place gave the object; `Err` only when no place
/// gave it and some read failed.
pub fn find_block(
    table: &MapTable,
    view: &LedgerView,
    object: &ObjectBin,
    storage: &dyn Fn(&str) -> Option<Arc<dyn Storage>>,
) -> Result<Option<FoundBlock>> {
    let rows = table.rows_of(object)?;
    let mut last_err = None;
    for bp in view.block_places(object, table) {
        let Some(row) = rows.iter().find(|r| r.place == bp.place) else {
            continue;
        };
        for name in &bp.storages {
            let Some(s) = storage(name) else {
                continue;
            };
            let p = &bp.place;
            match s.get_range(
                &pack_key(&hex::encode(p.pack)),
                u64::from(p.offset),
                u64::from(p.len),
            ) {
                Ok(Some(b)) if b.len() == p.len as usize && crate::crypto::hash(&b) == *object => {
                    return Ok(Some(FoundBlock {
                        bytes: b,
                        row: *row,
                        storage: name.clone(),
                        marked: bp.marked,
                    }));
                }
                Ok(_) => {
                    log::debug!(storage = name.as_str(); "block map: a place did not give its object");
                }
                Err(e) => last_err = Some(e),
            }
        }
    }
    match last_err {
        Some(e) => Err(e),
        None => Ok(None),
    }
}

/// Open a found block: decrypt and check it with the folder's keys.
pub fn open_block(
    fk: &crate::vault::FolderKeys,
    vault: &crate::ids::VaultId,
    found: &FoundBlock,
) -> Result<Vec<u8>> {
    crate::chunk_seal::open_chunk(
        fk,
        vault,
        &crate::ids::ChunkId::from_bytes(&found.row.chunk),
        found.row.epoch,
        u64::from(found.row.plain_len),
        &found.bytes,
    )
    .map_err(|e| anyhow!("block {}: {e:#}", hex::encode(found.row.object)))
}
