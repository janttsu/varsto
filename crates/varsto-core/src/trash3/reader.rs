// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Every device's trash record of one folder: which streams a pull reads,
//! applying their records, and the merged trash and history the rest of
//! the program asks for (section 43's union and removal rules, section
//! 50's thinning), plus the references garbage collection starts from.

use super::record::{Entry, Removal};
use super::settings::Settings;
use super::state::{ApplyError, DeviceTrash, TrashSnapshot};
use super::{stream, Hash32, Id16};
use crate::ledger3::LedgerView;
use crate::manifest3::{PullReport, Want};
use crate::record::{Kind, RecordStore, RecordsRefused, Refusal, Refused};
use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const DAY: i64 = 86_400;
/// A record keeps an entry, and a removal, this long past the entry's
/// expiry so every device sees it go; then the writer forgets it.
pub const KEEP_LISTED_SECS: i64 = 7 * DAY;

/// Which devices count for what when the trash is merged.
#[derive(Clone, Debug, Default)]
pub struct Trust {
    /// Records of these devices are not used at all (revoked devices).
    pub ignore: BTreeSet<Id16>,
    /// Removals of these devices do not count (members of a shared folder,
    /// on the owner's devices: another person cannot take entries out of
    /// the owner's trash; their deletions do count).
    pub no_removals: BTreeSet<Id16>,
}

/// The trash of a folder at some time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrashSets {
    /// In the trash: newest deletion first.
    pub visible: Vec<Entry>,
    /// Expired or purged: their blocks may go (when nothing else uses them).
    pub gone: Vec<Entry>,
    /// Restored: out of the trash, the file is current again.
    pub restored: Vec<Entry>,
    /// Kept versions of the history: newest replacement first.
    pub versions: Vec<Entry>,
    /// Versions the thinning or the history days let go.
    pub versions_gone: Vec<Entry>,
}

/// The newest views of every device's trash record of a folder.
#[derive(Clone, Debug, Default)]
pub struct FolderTrash {
    pub folder: Id16,
    pub devices: BTreeMap<Id16, DeviceTrash>,
    /// Writers whose trash stream forked: not read until cleared.
    pub forked: BTreeSet<Id16>,
    /// Versions this device has already let go (queued their blocks for
    /// dropping): never kept again, also if a clock goes back.
    pub let_go: HashSet<Id16>,
}

impl FolderTrash {
    pub fn new(folder: Id16) -> FolderTrash {
        FolderTrash {
            folder,
            ..Default::default()
        }
    }

    /// The seq applied of `device` (0: none).
    pub fn applied(&self, device: &Id16) -> u64 {
        self.devices.get(device).map_or(0, |v| v.seq)
    }

    /// Streams whose announced seq is newer than the one applied, other
    /// than `me`'s and forked ones. With nothing new, nothing is listed.
    pub fn wanted(&self, view: &LedgerView, me: &Id16) -> Vec<Want> {
        let kind = Kind::Trash.code();
        let mut out = Vec::new();
        for ((k, scope, device), s) in &view.streams {
            if *k != kind || scope != &self.folder || device == me || self.forked.contains(device) {
                continue;
            }
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
    /// accepted. `Err` only for storage errors. `PullReport::changed` is
    /// not filled (trash changes are ids, not paths).
    pub fn pull(
        &mut self,
        store: &RecordStore,
        view: &LedgerView,
        me: &Id16,
        counter: &mut RecordsRefused,
    ) -> Result<PullReport> {
        let mut report = PullReport::default();
        for want in self.wanted(view, me) {
            let read = store.read_after::<super::record::TrashBody>(
                &stream(self.folder, want.device),
                want.after,
                counter,
            )?;
            report.waiting += read.waiting.len();
            let mut forked = read.refused.iter().any(|r| r.reason == Refusal::Forked);
            report.refused.extend(read.refused);
            let v = self
                .devices
                .entry(want.device)
                .or_insert_with(|| DeviceTrash::new(want.device));
            for rec in read.accepted {
                match v.apply(&rec.body, rec.meta.body_hash) {
                    Ok(_) => report.applied += 1,
                    Err(ApplyError::Stale { .. }) => {}
                    Err(ApplyError::Gap { .. }) => break,
                    Err(ApplyError::Forked { .. }) => {
                        forked = true;
                        break;
                    }
                    Err(ApplyError::Bad(e)) => {
                        let r = Refused {
                            name: String::new(),
                            kind: Some(Kind::Trash),
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
                self.devices.remove(&want.device);
            }
            if forked && self.forked.insert(want.device) {
                report.forked.push(want.device);
            }
        }
        Ok(report)
    }

    /// The fork of `device` was resolved: read its stream again from its
    /// newest base.
    pub fn clear_fork(&mut self, device: &Id16) {
        self.forked.remove(device);
        self.devices.remove(device);
    }

    /// Put a device's state in (this device's own, as its writer published
    /// it).
    pub fn insert(&mut self, d: DeviceTrash) {
        self.devices.insert(d.device, d);
    }

    /// A writer that is no longer accepted: its record no longer counts.
    pub fn remove_writer(&mut self, device: &Id16) {
        self.devices.remove(device);
    }

    /// Merge every device's record at `now` (section 43): the union of the
    /// entries less those any device removed (restore against purge: the
    /// removal with the largest Lamport time wins, a purge on a tie) less
    /// those older than the trash days; the version history of section 50
    /// thinned per path.
    pub fn sets(&self, now: i64, settings: &Settings, trust: &Trust) -> TrashSets {
        let days = i64::from(settings.trash_days_for(&self.folder));
        let history_days = settings.history_keep_days(&self.folder);
        let live = || {
            self.devices
                .iter()
                .filter(|(d, _)| !trust.ignore.contains(*d))
        };

        // (lamport, purged, device) orders removals of one entry.
        let mut removed: HashMap<Id16, ((u64, bool, Id16), &Removal)> = HashMap::new();
        for (dev, d) in live().filter(|(d, _)| !trust.no_removals.contains(*d)) {
            for r in d.state.removals.values() {
                let key = (r.lamport, !r.restored, *dev);
                match removed.get(&r.id) {
                    Some((old, _)) if *old >= key => {}
                    _ => {
                        removed.insert(r.id, (key, r));
                    }
                }
            }
        }

        let mut all: BTreeMap<Id16, &Entry> = BTreeMap::new();
        let mut versions: BTreeMap<Id16, &Entry> = BTreeMap::new();
        for (_, d) in live() {
            for e in d.state.entries.values() {
                all.entry(e.id).or_insert(e);
            }
            for e in d.state.versions.values() {
                versions.entry(e.id).or_insert(e);
            }
        }

        let mut sets = TrashSets::default();
        let mut by_path: BTreeMap<&str, Vec<&Entry>> = BTreeMap::new();
        for e in versions.values() {
            by_path.entry(e.path.as_str()).or_default().push(e);
        }
        for list in by_path.into_values() {
            let ids: Vec<String> = list.iter().map(|e| hex::encode(e.id)).collect();
            let keys: Vec<(i64, u64, &str)> = list
                .iter()
                .zip(&ids)
                .map(|(e, id)| (e.deleted_utc, e.clock, id.as_str()))
                .collect();
            let kept = crate::engine::history_kept(&keys, now, history_days);
            for (e, k) in list.into_iter().zip(kept) {
                if k && !self.let_go.contains(&e.id) {
                    sets.versions.push(e.clone());
                } else {
                    sets.versions_gone.push(e.clone());
                }
            }
        }
        sets.versions
            .sort_by_key(|a| std::cmp::Reverse((a.deleted_utc, a.clock, a.id)));
        for (id, e) in all {
            match removed.get(&id) {
                Some((_, r)) if r.restored => sets.restored.push(e.clone()),
                Some(_) => sets.gone.push(e.clone()),
                None if now >= e.deleted_utc + days * DAY => sets.gone.push(e.clone()),
                None => sets.visible.push(e.clone()),
            }
        }
        sets.visible
            .sort_by(|a, b| b.deleted_utc.cmp(&a.deleted_utc).then(a.path.cmp(&b.path)));
        sets
    }

    /// Object names of the entries in the trash and the versions the
    /// history keeps at `now` (they count as used), for garbage
    /// collection. Repeats are possible.
    pub fn references(&self, now: i64, settings: &Settings, trust: &Trust) -> Vec<Hash32> {
        let sets = self.sets(now, settings, trust);
        sets.visible
            .iter()
            .chain(&sets.versions)
            .flat_map(|e| e.objects().copied())
            .collect()
    }

    /// `references` as a set.
    pub fn reference_set(&self, now: i64, settings: &Settings, trust: &Trust) -> HashSet<Hash32> {
        self.references(now, settings, trust).into_iter().collect()
    }

    /// What this device's own record may forget at `now`: entries (and
    /// versions) seven days past their expiry and removals of such
    /// entries, and versions the history let go seven days ago (`gone_at`
    /// is when this device first saw each go). Returns the snapshot with
    /// those removed; the delta carries them as `forget`.
    pub fn forgetting(
        own: &TrashSnapshot,
        now: i64,
        settings: &Settings,
        folder: &Id16,
        gone_at: &BTreeMap<Id16, i64>,
    ) -> TrashSnapshot {
        let keep = i64::from(settings.trash_days_for(folder)) * DAY + KEEP_LISTED_SECS;
        TrashSnapshot {
            entries: own
                .entries
                .iter()
                .filter(|(_, e)| now < e.deleted_utc + keep)
                .map(|(i, e)| (*i, e.clone()))
                .collect(),
            removals: own
                .removals
                .iter()
                .filter(|(_, r)| now < r.deleted_utc + keep)
                .map(|(i, r)| (*i, r.clone()))
                .collect(),
            versions: own
                .versions
                .iter()
                .filter(|(i, _)| gone_at.get(*i).is_none_or(|t| now < t + KEEP_LISTED_SECS))
                .map(|(i, e)| (*i, e.clone()))
                .collect(),
        }
    }
}
