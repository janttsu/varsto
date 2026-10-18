// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Replica rounds on packs (design sections 4, 9 and 10). A replica holds
//! no key: it copies packs whole between storages, checks each against its
//! id (the BLAKE3 of all its bytes), and claims it with `pack_stored` (zero
//! folder, `map_seq` 0) and `pack_verified`. Everything else on the source
//! (block maps, manifests, trash and other records, ledger batches) is
//! copied as it is and never opened; a replica never writes a map, a mark
//! or a record of any kind. What it can claim is bounded by the ledger's
//! replica scope ([`crate::ledger3::EventScope::Replica`]).
//!
//! The caller (WP12) puts [`ReplicaRound::events`] in one replica batch.

use std::collections::HashSet;

use anyhow::{bail, Result};

use crate::blockmap::class_of_len;
use crate::ledger3::events::{Event, PackOn, PackStored};
use crate::ledger3::scope::Allow;
use crate::ledger3::{EventScope, PackId, NO_FOLDER};
use crate::packs;
use crate::storage::{Storage, MAX_PACK};

/// What one round did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReplicaReport {
    /// Keys on the source.
    pub objects_seen: u64,
    /// Packs written to the target.
    pub packs_copied: u64,
    /// Records and other non-pack objects written to the target.
    pub records_copied: u64,
    pub bytes_copied: u64,
    /// Packs claimed and verified this round (copied now, or found on the
    /// target unclaimed).
    pub packs_claimed: u64,
    /// Packs on the source whose bytes do not hash to their id, or that
    /// read back wrong from the target: never replicated or claimed.
    pub packs_corrupt: u64,
    /// Packs whose length is not a size class: refused.
    pub packs_refused: u64,
    /// Names that are not objects of this layout (`chunks/...`, a name
    /// under `packs/` that is no pack): skipped, never copied.
    pub skipped_junk: u64,
}

/// A round's report and the events for the replica's batch.
#[derive(Clone, Debug, Default)]
pub struct ReplicaRound {
    pub report: ReplicaReport,
    pub events: Vec<Event>,
}

fn is_record_prefix(key: &str) -> bool {
    key.starts_with(packs::INDEX_PREFIX) || key.starts_with(packs::TOMBSTONE_PREFIX)
}

fn pack_id(hex_id: &str) -> Option<PackId> {
    let mut id = [0u8; 32];
    hex::decode_to_slice(hex_id, &mut id).ok()?;
    Some(id)
}

/// One replication round from `src` to `tgt`. `storage_name` is the name
/// the claims carry (the replica's storage, `replica:<name>`); `claimed`
/// says whether the replica's own ledger already claims a pack there.
///
/// Packs are checked before they are written (id, size class) and read
/// back from the target afterwards; a pack that fails either is not
/// claimed. A pack already on the target but never claimed (a crash
/// between the write and the batch) is read, checked and claimed.
pub fn replicate(
    src: &dyn Storage,
    tgt: &dyn Storage,
    storage_name: &str,
    claimed: &dyn Fn(&PackId) -> bool,
) -> Result<ReplicaRound> {
    let mut round = ReplicaRound::default();
    let have: HashSet<String> = tgt.list("")?.into_iter().collect();
    for key in src.list("")? {
        round.report.objects_seen += 1;
        let pack = packs::pack_of_key(&key).and_then(pack_id);
        let junk = key.starts_with("chunks/")
            || (key.starts_with(packs::PREFIX) && pack.is_none() && !is_record_prefix(&key));
        if junk {
            if round.report.skipped_junk == 0 {
                log::warn!(
                    "replica {storage_name}: skipping junk on {}: {key:?}",
                    src.name()
                );
            }
            round.report.skipped_junk += 1;
            continue;
        }
        let Some(id) = pack else {
            // A record, a map, a batch: as it is, never opened.
            if have.contains(&key) {
                continue;
            }
            let Some(data) = src.get(&key)? else { continue };
            if tgt.put_if_absent(&key, &data)? {
                round.report.records_copied += 1;
                round.report.bytes_copied += data.len() as u64;
            }
            continue;
        };
        let on_target = have.contains(&key);
        if on_target && claimed(&id) {
            continue;
        }
        // The bytes to claim: the source's, or the target's own copy.
        let from = if on_target { tgt } else { src };
        let Some(data) = from.get_bounded(&key, MAX_PACK)? else {
            continue;
        };
        let Some(class) = class_of_len(data.len() as u64) else {
            round.report.packs_refused += 1;
            continue;
        };
        if crate::crypto::hash(&data) != id {
            round.report.packs_corrupt += 1;
            continue; // never replicate or claim a corrupt pack
        }
        if !on_target {
            if tgt.put_if_absent(&key, &data)? {
                round.report.packs_copied += 1;
                round.report.bytes_copied += data.len() as u64;
            }
            // Read back what the target holds: a claim says the pack is
            // there and whole.
            let back = tgt.get_bounded(&key, MAX_PACK)?;
            if back.is_none_or(|b| crate::crypto::hash(&b) != id) {
                round.report.packs_corrupt += 1;
                // Our own write that reads back wrong goes again next round.
                let _ = tgt.delete(&key);
                continue;
            }
        }
        round.events.push(Event::PackStored(PackStored {
            storage: storage_name.to_string(),
            pack: id,
            class,
            folder: NO_FOLDER,
            map_seq: 0,
        }));
        round.events.push(Event::PackVerified(PackOn {
            storage: storage_name.to_string(),
            pack: id,
        }));
        round.report.packs_claimed += 1;
    }
    Ok(round)
}

/// A replica's batch may carry only claims and verifications of whole
/// packs with a zero folder, and its enrolment. Anything else (a
/// `record_published`, a claim naming a folder or a map record, a drop)
/// is a bug of the caller: refused here before it is sealed, and ignored
/// by every reader anyway.
pub fn check_replica_events(events: &[Event]) -> Result<()> {
    for ev in events {
        if EventScope::Replica.allows(ev) != Allow::Yes {
            bail!("a replica may not make the event {ev:?}");
        }
    }
    Ok(())
}
