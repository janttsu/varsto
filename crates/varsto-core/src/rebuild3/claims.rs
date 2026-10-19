// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Steps 4 and 5 of a rebuild: the events this device must sign again
//! because the batches that carried them are gone.

use super::{Counts, RebuildInput, RebuildOptions, WithView};
use crate::blockmap::{class_of_len, BlockMap};
use crate::fsck3::{list_packs, probe_len, LenProbe, PackCheck, PackVerdict, StorageDesc};
use crate::ledger3::events::{Announcement, Event, FolderAdded, PackStored};
use crate::ledger3::{FolderBin, LedgerView, PackId, NO_FOLDER};
use crate::manifest3::ManifestBody;
use crate::record::{Acceptor, Kind, RecordBody, RecordStore, RecordsRefused, StreamRef};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};

/// A record of this device that is on a storage.
struct OwnRecord {
    kind: Kind,
    folder: FolderBin,
    seq: u64,
    base: u64,
    parts: u16,
    body_hash: [u8; 32],
    size: u64,
    /// Pack ids the record's places are in, with their class.
    packs: Vec<(PackId, u8)>,
}

fn own_records<T: RecordBody>(
    store: &RecordStore,
    stream: &StreamRef,
    kind: Kind,
    folder: FolderBin,
    refused: &mut RecordsRefused,
    skipped: &mut Vec<String>,
    summarise: impl Fn(&T) -> (u64, Vec<(PackId, u8)>),
) -> Result<Vec<OwnRecord>> {
    let read = store.read_after::<T>(stream, 0, refused)?;
    if read.dropped_ahead > 0 {
        skipped.push(format!(
            "{} further {} records of folder {} were not read; run the rebuild again",
            read.dropped_ahead,
            kind.name(),
            short(&folder)
        ));
    }
    Ok(read
        .accepted
        .into_iter()
        .chain(read.waiting)
        .map(|r| {
            let (base, packs) = summarise(&r.body);
            OwnRecord {
                kind,
                folder,
                seq: r.meta.seq,
                base,
                parts: r.meta.parts,
                body_hash: r.meta.body_hash,
                size: r.meta.size,
                packs,
            }
        })
        .collect())
}

/// The events to sign: pack claims from the maps this device wrote and
/// from the listing of the storages, announcements of its own records,
/// folders it holds that the ledger does not know.
pub(super) fn reconstruct(
    input: &RebuildInput,
    opts: &RebuildOptions,
    view: &LedgerView,
    counts: &mut Counts,
) -> Result<Vec<Event>> {
    let me = input.me;
    let mut events = Vec::new();
    let mut refused = RecordsRefused::default();
    let trust = WithView {
        inner: input.record_trust,
        view,
    };
    let acceptor = || Acceptor {
        vault: input.vault,
        keys: input.record_keys,
        trust: &trust,
    };

    // Folders whose own streams are read: the ones the ledger knows and
    // the ones the engine holds keys for.
    let mut folders: BTreeSet<FolderBin> = view.folders.iter().copied().collect();
    folders.extend(input.folders.iter().copied());

    // What is on the storages.
    let meta: Vec<&StorageDesc> = input
        .storages
        .iter()
        .filter(|s| s.meta && (!s.cold || opts.confirm_cold_read))
        .collect();
    let mut records: BTreeMap<(u8, FolderBin, u64), OwnRecord> = BTreeMap::new();
    for folder in &folders {
        for s in &meta {
            let store = RecordStore {
                storage: s.storage,
                acceptor: acceptor(),
            };
            let maps = StreamRef::new(Kind::BlockMap, *folder, me);
            let found = own_records::<BlockMap>(
                &store,
                &maps,
                Kind::BlockMap,
                *folder,
                &mut refused,
                &mut counts.skipped,
                |b| {
                    let used: BTreeSet<u32> = b.entries.iter().map(|e| e.pack).collect();
                    (
                        b.base,
                        used.into_iter()
                            .filter_map(|i| b.packs.get(i as usize))
                            .map(|p| (p.id, p.class))
                            .collect(),
                    )
                },
            )?;
            let mans = StreamRef::new(Kind::Manifest, *folder, me);
            let found_m = own_records::<ManifestBody>(
                &store,
                &mans,
                Kind::Manifest,
                *folder,
                &mut refused,
                &mut counts.skipped,
                |b| (b.base, Vec::new()),
            )?;
            for r in found.into_iter().chain(found_m) {
                records.entry((r.kind.code(), r.folder, r.seq)).or_insert(r);
            }
        }
    }
    counts.own_records = records.len() as u64;

    // Pack listings and which packs this device's maps name.
    let mut listed = BTreeMap::new();
    for s in input.storages {
        if let Ok(l) = list_packs(s.storage) {
            listed.insert(s.name.as_str(), l);
        }
    }
    let mut named: BTreeMap<PackId, (u8, FolderBin, u64)> = BTreeMap::new();
    for r in records.values().filter(|r| r.kind == Kind::BlockMap) {
        for (id, class) in &r.packs {
            let e = named.entry(*id).or_insert((*class, r.folder, r.seq));
            e.2 = e.2.min(r.seq);
        }
    }

    // Packs named by this device's maps: claimed again where they are,
    // at their class length.
    let me_claims = |id: &PackId, storage: &str| {
        view.copies(id)
            .iter()
            .any(|c| c.storage == storage && c.claimed_by.contains(&me))
    };
    for (id, (class, folder, map_seq)) in &named {
        let class_len = crate::ledger3::events::class_bytes(*class).unwrap_or(0);
        for s in input.storages {
            let Some(l) = listed.get(s.name.as_str()) else {
                continue;
            };
            if !l.contains_key(id) || view.dropped_from(id, &s.name) || me_claims(id, &s.name) {
                continue;
            }
            if *class > s.max_class() {
                counts.skipped.push(format!(
                    "pack {} on {}: class not allowed",
                    short(id),
                    s.name
                ));
                continue;
            }
            match probe_len(s.storage, id, class_len)? {
                LenProbe::Exact => {}
                _ => {
                    counts.skipped.push(format!(
                        "pack {} on {}: not {class_len} bytes",
                        short(id),
                        s.name
                    ));
                    continue;
                }
            }
            if opts.verify_named && !verified(input, s, id, class_len, counts) {
                // Not claimed: the repair queue takes it.
                counts
                    .named_corrupt
                    .push(format!("{}:{}", s.name, hex::encode(id)));
                continue;
            }
            events.push(Event::PackStored(PackStored {
                storage: s.name.clone(),
                pack: *id,
                class: *class,
                folder: *folder,
                map_seq: *map_seq,
            }));
            counts.claims_from_maps += 1;
        }
    }

    // Packs no map of this device names: claimed only when nobody claims
    // them on that storage and their hash is the pack id.
    for s in input.storages {
        let Some(l) = listed.get(s.name.as_str()) else {
            continue;
        };
        for id in l.keys() {
            if named.contains_key(id) || view.is_held(id, &s.name) || view.dropped_from(id, &s.name)
            {
                continue;
            }
            if s.cold && !opts.confirm_cold_read {
                counts.skipped.push(format!(
                    "pack {} on {} (cold storage: read only with --confirm-cold-read)",
                    short(id),
                    s.name
                ));
                continue;
            }
            let Some(class_len) = crate::fsck3::find_class_len(s.storage, id, s.max_class())?
            else {
                counts
                    .skipped
                    .push(format!("pack {} on {}: no size class", short(id), s.name));
                continue;
            };
            if input.verify_pack.is_none() {
                counts.skipped.push(format!(
                    "pack {} on {}: no verification available, not claimed",
                    short(id),
                    s.name
                ));
                continue;
            }
            if !verified(input, s, id, class_len, counts) {
                counts
                    .unnamed_corrupt
                    .push(format!("{}:{}", s.name, hex::encode(id)));
                continue;
            }
            events.push(Event::PackStored(PackStored {
                storage: s.name.clone(),
                pack: *id,
                class: class_of_len(class_len).unwrap_or(0),
                folder: NO_FOLDER,
                map_seq: 0,
            }));
            counts.claims_from_listing += 1;
        }
    }

    // Records of this device that no batch of the ledger announces. The
    // view keeps a stream from its newest base on: records below it are
    // superseded (and wait for pruning), not lost announcements.
    for r in records.values() {
        let newest_base = view
            .stream(r.kind.code(), &r.folder, &me)
            .and_then(|s| s.base())
            .map(|(b, _, _)| b);
        if newest_base.is_some_and(|b| r.seq < b) {
            continue;
        }
        let known = view.announced(r.kind.code(), &r.folder, &me, r.seq);
        match known {
            Some(a) if a.body_hash == r.body_hash => continue,
            Some(_) => {
                counts.skipped.push(format!(
                    "{} {} of folder {}: the ledger announces another record under this seq",
                    r.kind.name(),
                    r.seq,
                    short(&r.folder)
                ));
                continue;
            }
            None => {}
        }
        events.push(Event::RecordPublished(Announcement {
            kind: r.kind.code(),
            scope: r.folder,
            seq: r.seq,
            base: r.base,
            parts: r.parts,
            body_hash: r.body_hash,
            size: r.size,
        }));
        counts.announced += 1;
    }

    // Folders the engine holds that the ledger does not know.
    for f in &input.folders {
        if !view.folders.contains(f) {
            events.push(Event::FolderAdded(FolderAdded { folder: *f }));
            counts.folders_added += 1;
        }
    }
    counts.refused_records = refused.total();
    counts.skipped.sort();
    counts.skipped.dedup();
    Ok(events)
}

fn short(id: &[u8]) -> String {
    hex::encode(id)[..12.min(id.len() * 2)].to_string()
}

fn verified(
    input: &RebuildInput,
    s: &StorageDesc,
    id: &PackId,
    class_len: u64,
    counts: &mut Counts,
) -> bool {
    let Some(v) = input.verify_pack else {
        return true;
    };
    match v(&PackCheck {
        storage: &s.name,
        backend: s.storage,
        pack: *id,
        class_len,
    }) {
        PackVerdict::Ok => {
            counts.verified += 1;
            true
        }
        _ => false,
    }
}
