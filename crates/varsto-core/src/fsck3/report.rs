// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The report of a format-3 `fsck` and its text.

use serde::Serialize;
use std::collections::BTreeMap;

/// One pack copy that is wrong.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct PackIssue {
    pub pack: String,
    pub storage: String,
    pub detail: String,
}

/// A pack on a storage that the ledger does not claim there.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Orphan {
    pub storage: String,
    pub pack: String,
    /// `unknown` (the view has never heard of it), `claimed_elsewhere`
    /// (claimed on another storage only) or `dropped` (deliberately
    /// removed from this storage).
    pub kind: String,
    /// Its length when it is a size class.
    pub bytes: Option<u64>,
    pub age_days: Option<i64>,
    /// Older than `ORPHAN_DAYS`: garbage collection takes it.
    pub gc_due: bool,
}

/// What the places of one folder's map are checked for.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct MapFindings {
    pub folder: String,
    pub places: u64,
    pub packs: u64,
    /// A place that ends beyond its pack class ("pack:offset+len").
    pub outside_pack: Vec<String>,
    /// A place in a pack the view has no claim for.
    pub unknown_pack: Vec<String>,
    /// A place whose class is not the class the view has for the pack.
    pub class_mismatch: Vec<String>,
    /// Places of one pack that overlap or name different objects.
    pub overlapping: Vec<String>,
    /// Packs the view gives to the folder that no applied map record lists.
    pub unmapped_packs: Vec<String>,
}

impl MapFindings {
    pub fn problems(&self) -> u64 {
        (self.outside_pack.len()
            + self.unknown_pack.len()
            + self.class_mismatch.len()
            + self.overlapping.len()) as u64
    }
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct BlockCounts {
    /// Distinct objects current manifests reference.
    pub referenced: u64,
    /// With an unmarked place in a pack some storage really holds.
    pub live: u64,
    /// Only places with a dead or lost mark are left.
    pub only_marked: u64,
    /// No place on any storage.
    pub missing: u64,
}

/// A current file that has a block with no place left.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct DamagedFile {
    pub folder: String,
    pub writer: String,
    pub path: String,
    pub blocks: u64,
    pub blocks_missing: u64,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct RecordIssue {
    pub kind: String,
    pub scope: String,
    pub device: String,
    pub seq: u64,
    pub storage: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct RecordFindings {
    /// Records the view announces (newest base and the ones after it).
    pub announced: u64,
    /// (record, storage) pairs probed.
    pub checked: u64,
    /// Announced but on no metadata storage.
    pub missing: Vec<RecordIssue>,
    /// On some metadata storage, absent or incomplete on another.
    pub missing_on: Vec<RecordIssue>,
    /// Announcement not applied yet or kept waiting.
    pub waiting: Vec<RecordIssue>,
    pub refused: Vec<RecordIssue>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct StorageError {
    pub storage: String,
    pub detail: String,
}

/// A pack copied whole to a storage that lacked it.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct FixAction {
    pub pack: String,
    pub from: String,
    pub to: String,
    pub bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Fsck3Report {
    pub verify: bool,
    /// Packs with at least one live copy in the view.
    pub packs: u64,
    pub copies_claimed: u64,
    pub copies_present: u64,
    pub copies_verified_now: u64,
    pub missing_copies: Vec<PackIssue>,
    pub wrong_length: Vec<PackIssue>,
    pub corrupt_copies: Vec<PackIssue>,
    pub verify_errors: Vec<PackIssue>,
    pub orphans: Vec<Orphan>,
    pub maps: Vec<MapFindings>,
    pub blocks: BlockCounts,
    pub damaged_files: Vec<DamagedFile>,
    pub records: RecordFindings,
    pub forked_devices: Vec<String>,
    pub forked_streams: Vec<String>,
    pub records_refused: BTreeMap<String, u64>,
    pub events_refused: u64,
    pub events_unknown: u64,
    pub marks_refused: u64,
    /// Storages the ledger places packs on that were not given (cold,
    /// away, not opened): their copies were not checked.
    pub unchecked_storages: Vec<String>,
    pub storage_errors: Vec<StorageError>,
    pub fixed: Vec<FixAction>,
    pub fix_failed: Vec<PackIssue>,
    pub handed_to_repair: Vec<PackIssue>,
}

fn short(hex: &str) -> &str {
    &hex[..hex.len().min(12)]
}

fn list<T>(out: &mut String, title: &str, items: &[T], one: impl Fn(&T) -> String, max: usize) {
    if items.is_empty() {
        return;
    }
    out.push_str(&format!("\n{title} ({}):", items.len()));
    for i in items.iter().take(max) {
        out.push_str(&format!("\n  {}", one(i)));
    }
    if items.len() > max {
        out.push_str(&format!("\n  ... and {} more", items.len() - max));
    }
}

impl Fsck3Report {
    /// Findings that mean data or bookkeeping is wrong (orphans and
    /// waiting records are not).
    pub fn problems(&self) -> u64 {
        (self.missing_copies.len()
            + self.wrong_length.len()
            + self.corrupt_copies.len()
            + self.verify_errors.len()
            + self.damaged_files.len()
            + self.records.missing.len()
            + self.records.refused.len()
            + self.forked_devices.len()
            + self.forked_streams.len()
            + self.storage_errors.len()) as u64
            + self.maps.iter().map(MapFindings::problems).sum::<u64>()
    }

    /// Nothing wrong (the command exits 0).
    pub fn is_clean(&self) -> bool {
        self.problems() == 0
    }

    /// Text in the style of today's `fsck`: one line of counts, then
    /// what is wrong, at most 20 lines per list.
    pub fn describe(&self) -> String {
        let r = self;
        let mut out = format!(
            "packs {} | copies claimed {} | present {} | verified now {} | missing {} | wrong length {} | corrupt {} | orphans {} (due {}) | blocks referenced {} | live {} | only marked {} | missing {} | damaged files {} | forked {:?} | refused {} records, {} events, {} marks | unchecked storages {:?}",
            r.packs,
            r.copies_claimed,
            r.copies_present,
            r.copies_verified_now,
            r.missing_copies.len(),
            r.wrong_length.len(),
            r.corrupt_copies.len(),
            r.orphans.len(),
            r.orphans.iter().filter(|o| o.gc_due).count(),
            r.blocks.referenced,
            r.blocks.live,
            r.blocks.only_marked,
            r.blocks.missing,
            r.damaged_files.len(),
            r.forked_devices,
            r.records_refused.values().sum::<u64>(),
            r.events_refused,
            r.marks_refused,
            r.unchecked_storages,
        );
        let pack = |p: &PackIssue| format!("{} on {}: {}", short(&p.pack), p.storage, p.detail);
        list(
            &mut out,
            "pack missing on a storage",
            &r.missing_copies,
            pack,
            20,
        );
        list(
            &mut out,
            "pack has the wrong length",
            &r.wrong_length,
            pack,
            20,
        );
        list(&mut out, "pack is corrupt", &r.corrupt_copies, pack, 20);
        list(
            &mut out,
            "pack could not be verified",
            &r.verify_errors,
            pack,
            20,
        );
        list(
            &mut out,
            "file damaged (block missing)",
            &r.damaged_files,
            |f| {
                format!(
                    "{}: {} of {} blocks missing (folder {}, device {})",
                    f.path,
                    f.blocks_missing,
                    f.blocks,
                    short(&f.folder),
                    short(&f.writer)
                )
            },
            20,
        );
        for m in &r.maps {
            let f = short(&m.folder);
            for (what, items) in [
                ("place outside its pack", &m.outside_pack),
                ("place in an unknown pack", &m.unknown_pack),
                ("place with another class than its pack", &m.class_mismatch),
                ("places overlap", &m.overlapping),
            ] {
                list(
                    &mut out,
                    &format!("folder {f}: {what}"),
                    items,
                    |s| s.clone(),
                    20,
                );
            }
        }
        let rec = |i: &RecordIssue| {
            format!(
                "{} {} of {} on {}: {}",
                i.kind,
                i.seq,
                short(&i.device),
                i.storage,
                i.detail
            )
        };
        list(
            &mut out,
            "record announced but not stored",
            &r.records.missing,
            rec,
            20,
        );
        list(
            &mut out,
            "record missing on a storage",
            &r.records.missing_on,
            rec,
            20,
        );
        list(&mut out, "record waiting", &r.records.waiting, rec, 20);
        list(&mut out, "record refused", &r.records.refused, rec, 20);
        list(
            &mut out,
            "forked streams",
            &r.forked_streams,
            |s| s.clone(),
            20,
        );
        list(
            &mut out,
            "orphan packs",
            &r.orphans,
            |o| {
                format!(
                    "{} on {} ({}{})",
                    short(&o.pack),
                    o.storage,
                    o.kind,
                    match (o.age_days, o.gc_due) {
                        (Some(d), true) => format!(", {d} days old, due for collection"),
                        (Some(d), false) => format!(", {d} days old"),
                        _ => String::new(),
                    }
                )
            },
            20,
        );
        list(
            &mut out,
            "storage errors",
            &r.storage_errors,
            |e| format!("{}: {}", e.storage, e.detail),
            20,
        );
        list(
            &mut out,
            "copied back",
            &r.fixed,
            |f| {
                format!(
                    "{} from {} to {} ({} bytes)",
                    short(&f.pack),
                    f.from,
                    f.to,
                    f.bytes
                )
            },
            20,
        );
        list(&mut out, "could not be fixed", &r.fix_failed, pack, 20);
        list(&mut out, "handed to repair", &r.handed_to_repair, pack, 20);
        out
    }
}
