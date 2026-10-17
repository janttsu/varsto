// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The writer side of the block map (section 3, "Writer", "Base and
//! delta"): one push, import, data move, repair, rewrite or forward run
//! writes its packs, then one map delta listing their members, then one
//! batch with `pack_stored` for every (pack, storage) and
//! `record_published` for the delta.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};

use super::record::{BlockMap, MapEntry, Mark, MarkKind, PackRef};
use super::table::{ApplyReport, MapTable, MapUpdate};
use crate::ledger3::envelope::kind::BLOCK_MAP;
use crate::ledger3::events::{class_bytes, Announcement, Event, PackStored, MAX_CLASS};
use crate::ledger3::{DeviceBin, FolderBin, Hash32, LedgerView, ObjectBin, PackId, Place};
use crate::packs::NewPack;
use crate::record::{KeyId, Kind, RecordWriter, SealedRecord, StreamRef};
use crate::storage::Storage;

/// A new base after this many deltas since the last one ...
pub const BASE_AFTER_DELTAS: u64 = 1024;
/// ... or when the deltas' bytes reach 1/4 of the base's bytes.
pub const BASE_BYTES_DIVISOR: u64 = 4;

/// One member of a pack this device wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WrittenMember {
    pub object: ObjectBin,
    pub chunk: [u8; 32],
    pub offset: u32,
    pub len: u32,
    pub plain_len: u32,
    pub epoch: u32,
}

/// A pack this device wrote (byte-identical) to `storages`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrittenPack {
    pub id: PackId,
    pub class: u8,
    pub storages: Vec<String>,
    pub members: Vec<WrittenMember>,
}

/// What a written object holds: (chunk id, plaintext length, epoch).
pub type ChunkInfo = ([u8; 32], u32, u32);

/// The class code of a pack length (`None`: not a size class).
pub fn class_of_len(len: u64) -> Option<u8> {
    (0..=MAX_CLASS).find(|c| class_bytes(*c) == Some(len))
}

fn bin32(hex_str: &str) -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    hex::decode_to_slice(hex_str, &mut b).map_err(|_| anyhow!("{hex_str:?} is not a hash"))?;
    Ok(b)
}

/// The packs a `PackStore` wrote (`Storage::take_new_packs`, per storage)
/// as written packs: one per pack id, with every storage that holds it.
/// `info` gives (chunk id, plaintext length, epoch) of an object.
pub fn written_packs(
    per_storage: &[(String, Vec<NewPack>)],
    info: &dyn Fn(&ObjectBin) -> Option<ChunkInfo>,
) -> Result<Vec<WrittenPack>> {
    let mut out: BTreeMap<PackId, WrittenPack> = BTreeMap::new();
    for (storage, packs) in per_storage {
        for p in packs {
            let id = bin32(&p.pack)?;
            if let Some(w) = out.get_mut(&id) {
                if !w.storages.contains(storage) {
                    w.storages.push(storage.clone());
                }
                continue;
            }
            let mut class = None;
            let mut members = Vec::with_capacity(p.members.len());
            for (o, loc) in &p.members {
                let object = bin32(o)?;
                let c = class_of_len(loc.pack_len).ok_or_else(|| {
                    anyhow!(
                        "pack {} has length {}, not a size class",
                        p.pack,
                        loc.pack_len
                    )
                })?;
                class = Some(c);
                let (chunk, plain_len, epoch) =
                    info(&object).ok_or_else(|| anyhow!("no chunk known for object {o}"))?;
                members.push(WrittenMember {
                    object,
                    chunk,
                    offset: u32::try_from(loc.offset)?,
                    len: u32::try_from(loc.len)?,
                    plain_len,
                    epoch,
                });
            }
            let Some(class) = class else {
                continue; // a pack without members lists nothing
            };
            out.insert(
                id,
                WrittenPack {
                    id,
                    class,
                    storages: vec![storage.clone()],
                    members,
                },
            );
        }
    }
    Ok(out.into_values().collect())
}

/// A sealed map record, published, with the events its batch carries.
#[derive(Clone, Debug)]
pub struct MapPublish {
    pub body: BlockMap,
    pub sealed: SealedRecord,
    /// `pack_stored` for every (pack, storage) of the record's new packs,
    /// then `record_published` for the record: put them in the batch.
    pub events: Vec<Event>,
}

impl MapPublish {
    /// Apply the record to this device's own table (its next base is
    /// collected from there).
    pub fn apply_to(
        &self,
        table: &mut MapTable,
        folder_pack: &dyn Fn(&PackId) -> bool,
    ) -> Result<ApplyReport> {
        table.apply(
            vec![MapUpdate {
                device: self.body.device,
                records: vec![(self.body.clone(), self.sealed.published.body_hash)],
            }],
            folder_pack,
        )
    }
}

/// The map stream of one device in one folder: its seq counter, base and
/// delta accounting, and the marks waiting for the next record.
#[derive(Clone, Debug)]
pub struct MapWriter {
    pub folder: FolderBin,
    pub device: DeviceBin,
    /// The folder epoch whose K10 seals the records (the newest held).
    pub epoch: u32,
    seq: u64,
    base: u64,
    prev: Hash32,
    base_size: u64,
    deltas: u64,
    delta_bytes: u64,
    force_base: bool,
    pending: Vec<Mark>,
}

impl MapWriter {
    /// Start from what the view says this device announced. `highest` is
    /// the highest seq of the stream found on the metadata storages
    /// (`RecordStore::highest_seq`): a record there that no batch
    /// announced (a crash before the batch) takes its seq, and the next
    /// record is a base (a delta after it would name a `prev` no reader
    /// can check).
    pub fn from_view(
        folder: FolderBin,
        device: DeviceBin,
        epoch: u32,
        view: &LedgerView,
        highest: u64,
    ) -> MapWriter {
        let mut w = MapWriter {
            folder,
            device,
            epoch,
            seq: 0,
            base: 0,
            prev: [0; 32],
            base_size: 0,
            deltas: 0,
            delta_bytes: 0,
            force_base: false,
            pending: Vec::new(),
        };
        if let Some(st) = view.stream(BLOCK_MAP, &folder, &device) {
            if let Some((newest, a)) = st.records.iter().next_back() {
                w.seq = *newest;
                w.prev = a.body_hash;
            }
            if let Some((b, _, _)) = st.base() {
                w.base = b;
                w.base_size = st.records.get(&b).map_or(0, |a| a.size);
                for (_, a) in st.records.range(b + 1..) {
                    w.deltas += 1;
                    w.delta_bytes += a.size;
                }
            }
        }
        if highest > w.seq {
            w.seq = highest;
            w.prev = [0; 32];
            w.force_base = true;
        }
        if w.base == 0 {
            w.force_base = true;
        }
        w
    }

    /// The seq the next record takes.
    pub fn next_seq(&self) -> u64 {
        self.seq + 1
    }

    pub fn key_id(&self) -> KeyId {
        KeyId::Meta {
            folder: self.folder,
            epoch: self.epoch,
        }
    }

    pub fn stream(&self) -> StreamRef {
        StreamRef::new(Kind::BlockMap, self.folder, self.device)
    }

    /// Section 3's rule: a base after 1024 deltas or when the deltas' bytes
    /// reach a quarter of the base's (and for the first record).
    pub fn base_due(&self) -> bool {
        self.force_base
            || self.deltas >= BASE_AFTER_DELTAS
            || self.delta_bytes * BASE_BYTES_DIVISOR >= self.base_size
    }

    fn mark(&mut self, places: &[(ObjectBin, Place)], kind: MarkKind) {
        for (object, p) in places {
            self.pending.push(Mark {
                object: *object,
                pack: p.pack,
                offset: p.offset,
                kind: kind.code(),
            });
        }
    }

    /// Dead marks on these places in the next record.
    pub fn mark_dead(&mut self, places: &[(ObjectBin, Place)]) {
        self.mark(places, MarkKind::Dead)
    }
    /// Undead marks: this device found a reference to an object it marked.
    pub fn mark_undead(&mut self, places: &[(ObjectBin, Place)]) {
        self.mark(places, MarkKind::Undead)
    }
    /// Lost marks: places whose member failed its check (repair).
    pub fn mark_lost(&mut self, places: &[(ObjectBin, Place)]) {
        self.mark(places, MarkKind::Lost)
    }
    pub fn pending_marks(&self) -> &[Mark] {
        &self.pending
    }

    /// The body of the next record: a delta of `packs` and the pending
    /// marks, or, when a base is due, every live place this writer wrote
    /// (its rows in `table` whose pack the view still shows on a storage)
    /// with `packs`, and its marks on places that are still there.
    pub fn body(
        &self,
        packs: &[WrittenPack],
        lamport: u64,
        table: Option<&MapTable>,
        view: &LedgerView,
    ) -> Result<BlockMap> {
        let base = self.base_due();
        let seq = self.next_seq();
        // (pack id) -> (class, entries keyed by offset)
        let mut by_pack: BTreeMap<PackId, (u8, BTreeMap<u32, MapEntry>)> = BTreeMap::new();
        let mut marks: Vec<Mark> = Vec::new();
        if base {
            let table =
                table.ok_or_else(|| anyhow!("a base of the block map needs the map table"))?;
            for r in table.rows_by(&self.device)? {
                if view.holders(&r.place.pack).is_empty() {
                    continue; // dropped everywhere: leaves the base
                }
                by_pack
                    .entry(r.place.pack)
                    .or_insert((r.class, BTreeMap::new()))
                    .1
                    .insert(
                        r.place.offset,
                        MapEntry {
                            object: r.object,
                            chunk: r.chunk,
                            pack: 0,
                            offset: r.place.offset,
                            len: r.place.len,
                            plain_len: r.plain_len,
                            epoch: r.epoch,
                            flags: r.flags,
                        },
                    );
            }
            // Per place: the newest of this device's dead/undead marks and
            // a lost mark, unless a pending mark of that sort replaces it.
            let mut kept: BTreeMap<(PackId, u32, bool), (u64, Mark)> = BTreeMap::new();
            for m in table.marks_by(&self.device)? {
                if view.holders(&m.pack).is_empty() {
                    continue; // the place is gone: the mark leaves the base
                }
                let lost = m.kind == MarkKind::Lost;
                let mark = Mark {
                    object: m.object,
                    pack: m.pack,
                    offset: m.offset,
                    kind: m.kind.code(),
                };
                let e = kept
                    .entry((m.pack, m.offset, lost))
                    .or_insert((m.lamport, mark));
                if m.lamport >= e.0 {
                    *e = (m.lamport, mark);
                }
            }
            for p in &self.pending {
                let lost = p.kind == MarkKind::Lost.code();
                kept.insert((p.pack, p.offset, lost), (u64::MAX, *p));
            }
            marks = kept.into_values().map(|(_, m)| m).collect();
        } else {
            marks.extend_from_slice(&self.pending);
        }
        for p in packs {
            let e = by_pack.entry(p.id).or_insert((p.class, BTreeMap::new()));
            if e.0 != p.class {
                bail!("pack {} written under two classes", hex::encode(p.id));
            }
            for m in &p.members {
                e.1.insert(
                    m.offset,
                    MapEntry {
                        object: m.object,
                        chunk: m.chunk,
                        pack: 0,
                        offset: m.offset,
                        len: m.len,
                        plain_len: m.plain_len,
                        epoch: m.epoch,
                        flags: 0,
                    },
                );
            }
        }
        let mut refs = Vec::with_capacity(by_pack.len());
        let mut entries = Vec::new();
        for (i, (id, (class, members))) in by_pack.into_iter().enumerate() {
            refs.push(PackRef { id, class });
            entries.extend(members.into_values().map(|mut e| {
                e.pack = i as u32;
                e
            }));
        }
        Ok(BlockMap {
            folder: self.folder,
            device: self.device,
            seq,
            lamport,
            base: if base { seq } else { self.base },
            prev: if seq == 1 { [0; 32] } else { self.prev },
            packs: refs,
            entries,
            marks,
        })
    }

    /// Seal a body made by `body` (it must be this writer's next record).
    pub fn seal(&self, writer: &RecordWriter, body: &BlockMap) -> Result<SealedRecord> {
        if body.seq != self.next_seq() || body.device != self.device || body.folder != self.folder {
            bail!("not the next record of this map stream");
        }
        let sealed = writer.seal(&self.stream(), body.seq, body.base, &self.key_id(), body)?;
        body.check_limits(sealed.published.parts)
            .map_err(|e| anyhow!("block map record {}: {e}", body.seq))?;
        Ok(sealed)
    }

    /// Count a published record: the next one follows it.
    pub fn commit(&mut self, body: &BlockMap, sealed: &SealedRecord) {
        let size = sealed.published.size;
        self.seq = body.seq;
        self.prev = sealed.published.body_hash;
        if body.is_base() {
            self.base = body.seq;
            self.base_size = size;
            self.deltas = 0;
            self.delta_bytes = 0;
            self.force_base = false;
        } else {
            self.deltas += 1;
            self.delta_bytes += size;
        }
        self.pending.clear();
    }

    /// The events of the batch: `pack_stored` per (pack, storage) and the
    /// record's `record_published`.
    pub fn events(
        &self,
        packs: &[WrittenPack],
        body: &BlockMap,
        sealed: &SealedRecord,
    ) -> Vec<Event> {
        let mut out = Vec::new();
        for p in packs {
            for s in &p.storages {
                out.push(Event::PackStored(PackStored {
                    storage: s.clone(),
                    pack: p.id,
                    class: p.class,
                    folder: self.folder,
                    map_seq: body.seq,
                }));
            }
        }
        let a = &sealed.published;
        out.push(Event::RecordPublished(Announcement {
            kind: a.kind,
            scope: a.scope,
            seq: a.seq,
            base: a.base,
            parts: a.parts,
            body_hash: a.body_hash,
            size: a.size,
        }));
        out
    }

    /// Make, seal and write the next record to every metadata storage, and
    /// return it with its batch events. A seq already taken on the first
    /// storage (a record of an earlier attempt no batch announced) is
    /// skipped and the record becomes a base.
    pub fn publish(
        &mut self,
        writer: &RecordWriter,
        storages: &[&dyn Storage],
        packs: &[WrittenPack],
        lamport: u64,
        table: Option<&MapTable>,
        view: &LedgerView,
    ) -> Result<MapPublish> {
        let first = storages
            .first()
            .ok_or_else(|| anyhow!("no metadata storage to write the block map to"))?;
        for _ in 0..4 {
            let body = self.body(packs, lamport, table, view)?;
            let sealed = self.seal(writer, &body)?;
            let mut taken = false;
            for (name, bytes) in &sealed.parts {
                if !first.put_if_absent(name, bytes)? {
                    taken = true;
                    break;
                }
            }
            if taken {
                self.seq += 1;
                self.prev = [0; 32];
                self.force_base = true;
                continue;
            }
            for s in &storages[1..] {
                for (name, bytes) in &sealed.parts {
                    // Already there from an earlier try of this very record
                    // is fine; another record under the name is not
                    // checked here (readers refuse it by its hash).
                    s.put_if_absent(name, bytes)?;
                }
            }
            let events = self.events(packs, &body, &sealed);
            self.commit(&body, &sealed);
            return Ok(MapPublish {
                body,
                sealed,
                events,
            });
        }
        bail!(
            "block map seqs of this device are taken on {}",
            first.name()
        )
    }
}
