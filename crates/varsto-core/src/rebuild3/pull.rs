// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Step 1 of a rebuild: take every device's checkpoint and batches back
//! from the metadata storages into the local store.

use super::{Counts, RebuildError, RebuildInput, RebuildOptions};
use crate::ledger3::checkpoint::{batch_key, Checkpoint, LedgerObject};
use crate::ledger3::EventScope;
use crate::ledger3::{DeviceBin, Ingest, LedgerStore, SignedRecord};
use anyhow::Result;
use std::collections::BTreeMap;

/// What a storage lists under `ledger/<device>/`.
#[derive(Default)]
struct Listing {
    batches: Vec<u64>,
    /// Newest checkpoint with its parts' names.
    checkpoint: Option<(u64, Vec<String>)>,
}

fn parse_key(key: &str) -> Option<(DeviceBin, LedgerObject)> {
    let rest = key.strip_prefix("ledger/")?;
    let (dev, file) = rest.split_once('/')?;
    let device: DeviceBin = hex::decode(dev).ok()?.try_into().ok()?;
    Some((device, LedgerObject::parse(file)?))
}

/// A device's listing and its checkpoint parts by seq.
type DeviceObjects = (Listing, BTreeMap<u64, Vec<(u16, String)>>);

fn list_device_objects(keys: &[String]) -> BTreeMap<DeviceBin, DeviceObjects> {
    let mut out: BTreeMap<DeviceBin, DeviceObjects> = BTreeMap::new();
    for k in keys {
        let Some((device, obj)) = parse_key(k) else {
            continue;
        };
        let e = out.entry(device).or_default();
        match obj {
            LedgerObject::Batch(seq) => e.0.batches.push(seq),
            LedgerObject::Checkpoint(seq, part) => {
                e.1.entry(seq).or_default().push((part, k.clone()))
            }
        }
    }
    for (l, cps) in out.values_mut() {
        l.batches.sort_unstable();
        // The newest checkpoint is the only one worth reading.
        if let Some((seq, parts)) = cps.iter_mut().next_back() {
            parts.sort();
            l.checkpoint = Some((*seq, parts.iter().map(|(_, n)| n.clone()).collect()));
        }
    }
    out
}

/// Pull everything the metadata storages hold of the ledger.
pub(super) fn pull_ledger(
    store: &mut LedgerStore,
    input: &RebuildInput,
    opts: &RebuildOptions,
    counts: &mut Counts,
) -> Result<(), RebuildError> {
    let me = input.me;
    for s in input.storages.iter().filter(|s| s.meta) {
        if s.cold && !opts.confirm_cold_read {
            counts.skipped.push(format!(
                "{} (cold storage: read only with --confirm-cold-read)",
                s.name
            ));
            continue;
        }
        let keys = s
            .storage
            .list("ledger/")
            .map_err(|e| RebuildError::StorageUnreachable(format!("{}: {e:#}", s.name)))?;
        for (device, (listing, _)) in list_device_objects(&keys) {
            let own = device == me;
            let Some(pubkey) = (input.pubkey_of)(&device) else {
                counts
                    .skipped
                    .push(format!("device {}: no trusted key", hex::encode(device)));
                continue;
            };
            if own {
                if let Some(last) = listing.batches.last() {
                    let e = counts.own_on_storage.entry(s.name.clone()).or_insert(0);
                    *e = (*e).max(*last);
                }
            }
            // The checkpoint first, when it is ahead of what is held.
            if let Some((seq, names)) = &listing.checkpoint {
                let held = store.head(&device);
                let held_to = held.seq.max(held.base.as_ref().map_or(0, |b| b.seq));
                if *seq > held_to {
                    let mut parts = Vec::new();
                    for n in names {
                        if let Some(b) = s.storage.get_bounded(n, crate::record::MAX_PART_READ)? {
                            if let Ok(r) = SignedRecord::decode(&b) {
                                parts.push(r);
                            }
                        }
                    }
                    let usable = parts.len() == names.len()
                        && parts.iter().all(|p| p.verify(&pubkey).is_ok())
                        && parts.first().is_some_and(|p| {
                            own || (input.scope_of)(&device, &p.key_id) == Some(EventScope::Full)
                        });
                    if usable {
                        if let Some(key) = (input.key_for)(&parts[0].key_id) {
                            match Checkpoint::open(&parts, &key) {
                                Ok(cp) if cp.device == device => {
                                    let anchor = s
                                        .storage
                                        .get_bounded(
                                            &batch_key(&device, cp.seq),
                                            crate::record::MAX_PART_READ,
                                        )?
                                        .and_then(|b| SignedRecord::decode(&b).ok());
                                    match store.ingest_checkpoint(&parts, &cp, anchor.as_ref())? {
                                        Ingest::Fork => counts.forks.push(device),
                                        Ingest::New => counts.checkpoints += 1,
                                        _ => {}
                                    }
                                }
                                _ => counts.malformed += 1,
                            }
                        }
                    } else {
                        counts.malformed += 1;
                    }
                }
            }
            // Then the batches after what is held, in order.
            let floor = {
                let h = store.head(&device);
                h.seq.max(h.base.as_ref().map_or(0, |b| b.seq))
            };
            // A storage that is not ahead is compared at its newest batch
            // only: equal hashes there mean equal histories below (every
            // batch names the hash of the one before), a different one is
            // a second history.
            let seqs: Vec<u64> = match listing.batches.last() {
                Some(top) if *top <= floor => vec![*top],
                _ => listing
                    .batches
                    .iter()
                    .copied()
                    .filter(|q| *q > floor)
                    .collect(),
            };
            for seq in seqs {
                let Some(bytes) = s
                    .storage
                    .get_bounded(&batch_key(&device, seq), crate::record::MAX_PART_READ)?
                else {
                    continue;
                };
                let Ok(rec) = SignedRecord::decode(&bytes) else {
                    counts.malformed += 1;
                    continue;
                };
                let key = (input.key_for)(&rec.key_id);
                let res = if own {
                    store.ingest_own_restored(rec, &pubkey, key.as_ref())
                } else {
                    store.ingest(rec, &pubkey, key.as_ref())
                };
                match res {
                    Ok(Ingest::New) => counts.batches += 1,
                    Ok(Ingest::Fork) => counts.forks.push(device),
                    Ok(Ingest::Refused) => counts.refused += 1,
                    Ok(_) => {}
                    Err(_) => counts.malformed += 1,
                }
            }
        }
    }
    counts.forks.sort_unstable();
    counts.forks.dedup();
    Ok(())
}
