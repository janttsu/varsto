// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Storage aliases (design section 5, "Storage names"): ledger events name
//! storages by their writer's local name, and `storage-names` records
//! (kind 19) map each writer's names to storage identities. A reader maps
//! (writer, name) to its own name, so that a pack another device claimed on
//! "nas" counts as held on this device's "home-nas" when both name one
//! storage. [`localize`] does that on a finished view: every place is
//! renamed by the alias of the devices that claimed it (then of those that
//! dropped or verified it), and places that become one storage are merged
//! (claims and verifications are unions, times maxima, as when the events
//! are applied).

use std::collections::{BTreeMap, BTreeSet};

use crate::ledger3::view::{PackPlace, SET_CLAIMED, SET_DROPPED, SET_VERIFIED};
use crate::ledger3::{DeviceBin, LedgerView};

fn members(b: u64) -> impl Iterator<Item = u16> {
    (0..64u16).filter(move |i| b & (1 << i) != 0)
}

fn merge(into: &mut PackPlace, from: &PackPlace) {
    into.claimed_by |= from.claimed_by;
    into.verified_by |= from.verified_by;
    into.dropped_by |= from.dropped_by;
    into.stored_at = into.stored_at.max(from.stored_at);
    into.verified_at = into.verified_at.max(from.verified_at);
    into.dropped_at = into.dropped_at.max(from.dropped_at);
    into.stored_utc = into.stored_utc.max(from.stored_utc);
    into.verified_utc = into.verified_utc.max(from.verified_utc);
}

/// `view` with other devices' storage names replaced by this device's:
/// `aliases` maps a device to (its name -> the local name). Storages no
/// alias names keep their names.
pub fn localize(
    mut view: LedgerView,
    aliases: &BTreeMap<DeviceBin, BTreeMap<String, String>>,
) -> LedgerView {
    if aliases.is_empty() {
        return view;
    }
    // Device numbers that have an alias, and the storage numbers named.
    let mut by_dev: BTreeMap<u16, &BTreeMap<String, String>> = BTreeMap::new();
    for (d, m) in aliases {
        if let Some(i) = view.tables.find_dev(d) {
            by_dev.insert(i, m);
        }
    }
    if by_dev.is_empty() {
        return view;
    }
    let mut new_index: BTreeMap<String, u16> = BTreeMap::new();
    for m in by_dev.values() {
        for local in m.values() {
            if !new_index.contains_key(local) {
                if let Some(i) = view.tables.storage(local) {
                    new_index.insert(local.clone(), i);
                }
            }
        }
    }
    let names: Vec<String> = (0..u16::MAX)
        .map_while(|i| view.tables.storage_name(i).map(str::to_string))
        .collect();
    let wide = std::mem::take(&mut view.wide);
    let mut new_wide = BTreeMap::new();
    for (id, rec) in view.packs.iter_mut() {
        let mut places: Vec<(u16, PackPlace)> = Vec::with_capacity(rec.places.len());
        for (s, p) in rec.places.iter() {
            let name = names.get(*s as usize).map(String::as_str).unwrap_or("");
            let wide_of = |set: u8| -> BTreeSet<u16> {
                wide.get(&(*id, *s, set)).cloned().unwrap_or_default()
            };
            let order = members(p.claimed_by)
                .chain(wide_of(SET_CLAIMED))
                .chain(members(p.dropped_by))
                .chain(wide_of(SET_DROPPED))
                .chain(members(p.verified_by))
                .chain(wide_of(SET_VERIFIED));
            let target = order
                .filter_map(|d| by_dev.get(&d).and_then(|m| m.get(name)))
                .find_map(|local| new_index.get(local).copied())
                .unwrap_or(*s);
            for set in [SET_CLAIMED, SET_VERIFIED, SET_DROPPED] {
                if let Some(w) = wide.get(&(*id, *s, set)) {
                    new_wide
                        .entry((*id, target, set))
                        .or_insert_with(BTreeSet::new)
                        .extend(w.iter().copied());
                }
            }
            match places.iter_mut().find(|(t, _)| *t == target) {
                Some((_, into)) => merge(into, p),
                None => places.push((target, *p)),
            }
        }
        places.sort_unstable_by_key(|(s, _)| *s);
        rec.places = places.into_iter().collect();
    }
    view.wide = new_wide;
    view
}
