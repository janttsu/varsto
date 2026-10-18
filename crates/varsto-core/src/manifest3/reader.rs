// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Every writer's newest manifest view of one folder: which streams a pull
//! reads (only those announced past what was applied, section 25 adapted),
//! applying their records, and the queries other parts need from them:
//! `held` / `holders` (in place of `chunk_on_device`, section 4) and the
//! references garbage collection starts from (section 3).

use super::record::{FileEntry, ManifestBody};
use super::state::{ApplyError, WriterView};
use super::{stream, Hash32, Id16};
use crate::ledger3::LedgerView;
use crate::record::{Kind, RecordStore, RecordsRefused, Refusal, Refused};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// What a batch announced for record `seq` of a stream, in the form
/// `record::RecordTrust::announcement` returns (for the engine's trust).
pub fn announcement(
    view: &LedgerView,
    device: &Id16,
    kind: Kind,
    scope: &Id16,
    seq: u64,
) -> Option<crate::record::Announced> {
    view.announced(kind.code(), scope, device, seq)
        .map(|a| crate::record::Announced {
            parts: a.parts,
            body_hash: a.body_hash,
            base: a.base,
        })
}

/// One stream a pull reads: records after `after` (a newer base than the
/// applied record: from that base).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Want {
    pub device: Id16,
    pub after: u64,
    /// The newest announced seq.
    pub newest: u64,
    /// The view is rebuilt from a newer base.
    pub rebuild: bool,
}

/// What one pull did.
#[derive(Clone, Debug, Default)]
pub struct PullReport {
    /// Paths that changed, per writer (what a merge must look at again).
    pub changed: BTreeMap<Id16, BTreeSet<String>>,
    /// Records applied.
    pub applied: u64,
    /// Records that wait for the batch that announces them.
    pub waiting: usize,
    pub refused: Vec<Refused>,
    /// Writers newly found forked (their views stay as last accepted).
    pub forked: Vec<Id16>,
}

/// The newest views of every writer of a folder this device read.
#[derive(Clone, Debug, Default)]
pub struct FolderManifests {
    pub folder: Id16,
    pub views: BTreeMap<Id16, WriterView>,
    /// Writers whose manifest stream forked: not read until cleared.
    pub forked: BTreeSet<Id16>,
}

impl FolderManifests {
    pub fn new(folder: Id16) -> FolderManifests {
        FolderManifests {
            folder,
            ..Default::default()
        }
    }

    /// The seq applied of `device` (0: none).
    pub fn applied(&self, device: &Id16) -> u64 {
        self.views.get(device).map_or(0, |v| v.seq)
    }

    /// Streams whose announced seq is newer than the one applied, other
    /// than `me`'s and forked ones. With nothing new, nothing is listed.
    pub fn wanted(&self, view: &LedgerView, me: &Id16) -> Vec<Want> {
        let kind = Kind::Manifest.code();
        let mut out = Vec::new();
        for ((k, scope, device), s) in &view.streams {
            if *k != kind || scope != &self.folder || device == me || self.forked.contains(device) {
                continue;
            }
            // Two batches announced different records: the ledger's fork.
            let key = (*k, *scope, *device);
            if view.forked.contains(device)
                || view
                    .forked_streams
                    .range((key, 0)..=(key, u64::MAX))
                    .next()
                    .is_some()
            {
                continue;
            }
            let Some(newest) = s.newest() else { continue };
            let applied = self.applied(device);
            if newest <= applied {
                continue;
            }
            let base = s.base().map_or(0, |b| b.0);
            let rebuild = base > applied;
            out.push(Want {
                device: *device,
                after: if rebuild {
                    base.saturating_sub(1)
                } else {
                    applied
                },
                newest,
                rebuild,
            });
        }
        out
    }

    /// Read every wanted stream from one storage and apply what is
    /// accepted. `Err` only for storage errors.
    pub fn pull(
        &mut self,
        store: &RecordStore,
        view: &LedgerView,
        me: &Id16,
        counter: &mut RecordsRefused,
    ) -> Result<PullReport> {
        let mut report = PullReport::default();
        for want in self.wanted(view, me) {
            let read = store.read_after::<ManifestBody>(
                &stream(self.folder, want.device),
                want.after,
                counter,
            )?;
            report.waiting += read.waiting.len();
            let mut forked = read.refused.iter().any(|r| r.reason == Refusal::Forked);
            report.refused.extend(read.refused);
            let v = self
                .views
                .entry(want.device)
                .or_insert_with(|| WriterView::new(want.device));
            for rec in read.accepted {
                match v.apply(&rec.body, rec.meta.body_hash) {
                    Ok(changed) => {
                        report.applied += 1;
                        if !changed.is_empty() {
                            report
                                .changed
                                .entry(want.device)
                                .or_default()
                                .extend(changed);
                        }
                    }
                    Err(ApplyError::Stale { .. }) => {}
                    Err(ApplyError::Gap { .. }) => break,
                    Err(ApplyError::Forked { .. }) => {
                        forked = true;
                        break;
                    }
                    Err(ApplyError::Bad(e)) => {
                        let r = Refused {
                            name: String::new(),
                            kind: Some(Kind::Manifest),
                            seq: rec.meta.seq,
                            device: Some(want.device),
                            reason: Refusal::Junk(crate::record::Junk::BadBody(e)),
                        };
                        counter.note(&r);
                        report.refused.push(r);
                        break;
                    }
                }
            }
            if v.seq == 0 {
                self.views.remove(&want.device);
            }
            if forked && self.forked.insert(want.device) {
                report.forked.push(want.device);
            }
        }
        Ok(report)
    }

    /// The fork of `device` was resolved (the ledger cleared it): read its
    /// stream again from its newest base.
    pub fn clear_fork(&mut self, device: &Id16) {
        self.forked.remove(device);
        self.views.remove(device);
    }

    /// Put a view in (this device's own, as its writer published it).
    pub fn insert_view(&mut self, v: WriterView) {
        self.views.insert(v.device, v);
    }

    /// A writer that is no longer accepted (removed past its cut-off and
    /// its records gone, or a viewer): its view no longer counts.
    pub fn remove_writer(&mut self, device: &Id16) {
        self.views.remove(device);
    }

    /// The views of every writer but `me`, for `merge::merge_views`.
    pub fn others(&self, me: &Id16) -> Vec<&BTreeMap<String, FileEntry>> {
        self.views
            .iter()
            .filter(|(d, _)| *d != me)
            .map(|(_, v)| &v.files)
            .collect()
    }

    /// Object names of every current file in every writer's newest view
    /// (repeats are possible), for garbage collection; WP7 adds trash,
    /// history and snapshot references.
    pub fn references(&self) -> impl Iterator<Item = &Hash32> {
        self.views
            .values()
            .flat_map(|v| v.files.values())
            .flat_map(FileEntry::objects)
    }

    /// `references` as a set.
    pub fn reference_set(&self) -> HashSet<Hash32> {
        self.references().copied().collect()
    }

    /// Whether any current file of any writer names `object`.
    pub fn is_referenced(&self, object: &Hash32) -> bool {
        self.references().any(|o| o == object)
    }

    /// Who holds which object, from every writer's newest view (`held`).
    pub fn held_index(&self) -> HeldIndex {
        let mut idx = HeldIndex::default();
        for (d, v) in &self.views {
            idx.writers.insert(*d);
            for f in v.files.values().filter(|f| f.held && !f.deleted) {
                for c in &f.chunks {
                    let e = idx.objects.entry(c.object).or_insert((c.size, Vec::new()));
                    if !e.1.contains(d) {
                        e.1.push(*d);
                    }
                }
            }
        }
        for e in idx.objects.values_mut() {
            e.1.sort_unstable();
        }
        idx
    }
}

/// "Device D holds object O" = some entry of D's newest manifest with
/// `held` names O (section 4). Replaces `chunk_on_device` for transferrer
/// targeting and emptying, the safety indicator, `where` and the
/// forwarding report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HeldIndex {
    /// Object -> (plaintext size, holders sorted).
    objects: HashMap<Hash32, (u64, Vec<Id16>)>,
    /// Every writer with a view of the folder ("uses the folder").
    writers: BTreeSet<Id16>,
}

impl HeldIndex {
    /// The devices that hold `object`, sorted.
    pub fn holders(&self, object: &Hash32) -> &[Id16] {
        self.objects.get(object).map_or(&[], |e| e.1.as_slice())
    }

    pub fn held_by(&self, object: &Hash32, device: &Id16) -> bool {
        self.holders(object).contains(device)
    }

    /// Some device other than `me` holds it (a carrier without
    /// destinations takes only what no other device has, F-048).
    pub fn held_elsewhere(&self, object: &Hash32, me: &Id16) -> bool {
        self.holders(object).iter().any(|d| d != me)
    }

    /// Every one of `devices` holds it (a carrier with destinations is
    /// emptied of it).
    pub fn held_by_all<'a>(
        &self,
        object: &Hash32,
        devices: impl IntoIterator<Item = &'a Id16>,
    ) -> bool {
        let h = self.holders(object);
        devices.into_iter().all(|d| h.contains(d))
    }

    /// Writers with a manifest view of the folder.
    pub fn writers(&self) -> &BTreeSet<Id16> {
        &self.writers
    }

    /// Whether `device` uses the folder: it published a manifest of it.
    pub fn uses(&self, device: &Id16) -> bool {
        self.writers.contains(device)
    }

    /// Bytes and blocks each device holds (each object once), for `where`.
    pub fn bytes_by_device(&self) -> BTreeMap<Id16, (u64, u64)> {
        let mut out: BTreeMap<Id16, (u64, u64)> = BTreeMap::new();
        for (size, holders) in self.objects.values() {
            for d in holders {
                let e = out.entry(*d).or_default();
                e.0 += size;
                e.1 += 1;
            }
        }
        out
    }

    /// Objects `device` holds.
    pub fn held_objects<'a>(&'a self, device: &'a Id16) -> impl Iterator<Item = &'a Hash32> + 'a {
        self.objects
            .iter()
            .filter(move |(_, (_, h))| h.contains(device))
            .map(|(o, _)| o)
    }

    /// Number of objects some device holds.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}
