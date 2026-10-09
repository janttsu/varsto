// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Storage prices and placement: what each storage and folder costs per
//! month under the price model (`crate::price`), and the one placement
//! change Varsto can carry out today: keep a folder's idle files only on
//! the storages and free their copies on this device.
//!
//! Varsto writes every block to every storage, so freeing a local copy does
//! not change the storage bill; it frees disk space here. It is refused for a
//! file unless every block has a copy on a storage this device reads without
//! confirmation (cold storages and transferrers do not count), unless the
//! folder's copy rules still hold for it, and unless the file is synced
//! (`Engine::free_file`). A block whose readable copies nobody has verified
//! yet is downloaded and hash-checked first.

use super::{chunk_storage_key, Engine, FileEntry, FolderState};
use crate::advice::{
    self, add_cost, Advice, ApplyReport, Costs, FolderCost, StorageEstimate, Suggestion,
    FREE_IDLE_PREFIX,
};
use crate::crypto;
use crate::ids::ObjectName;
use crate::ledger::{Event, LedgerView};
use crate::manifest::FileState;
use crate::policy::{self, ChunkFacts, Policy, PolicyState};
use crate::price::{self, StoragePrice};
use crate::storage::Storage;
use crate::util;
use crate::vault::FolderRecord;
use anyhow::{bail, Result};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// Decimal sizes for messages ("3.2 GB").
fn fmt_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

fn fmt_costs(c: &Costs) -> String {
    c.iter()
        .map(|(cur, v)| {
            if *v < 0.01 {
                format!("less than 0.01 {cur}")
            } else {
                format!("about {v:.2} {cur}")
            }
        })
        .collect::<Vec<_>>()
        .join(" + ")
}

/// Idle by the same rule as the advice: no access or change for `idle_days`.
fn is_idle(e: &FileEntry, idle_days: i64, now_utc: i64) -> bool {
    let last = e
        .last_accessed_utc
        .unwrap_or(e.modified_utc)
        .max(e.modified_utc);
    (now_utc - last) / 86_400 >= idle_days
}

/// Idle files that are on this device and not pinned, largest first.
fn idle_local(list: &[FileEntry], idle_days: i64, now_utc: i64) -> Vec<FileEntry> {
    let mut out: Vec<FileEntry> = list
        .iter()
        .filter(|e| e.state == "local" && !e.pinned && is_idle(e, idle_days, now_utc))
        .cloned()
        .collect();
    out.sort_by_key(|e| std::cmp::Reverse(e.size));
    out
}

/// The configured storages as placement sees them.
#[derive(Default)]
struct Places {
    prices: BTreeMap<String, Option<StoragePrice>>,
    /// Read without confirmation: not cold and not a transferrer.
    readable: BTreeSet<String>,
    carriers: BTreeSet<String>,
    place: BTreeMap<String, String>,
}

impl Places {
    fn price(&self, name: &str) -> Option<&StoragePrice> {
        self.prices.get(name).and_then(|p| p.as_ref())
    }
    /// Configured, not a transferrer: a copy that stays.
    fn durable(&self, name: &str) -> bool {
        self.prices.contains_key(name) && !self.carriers.contains(name)
    }
}

impl Engine {
    /// The price of a storage: the figures the user set, the others from the
    /// built-in price data when the provider is recognised.
    pub fn storage_price(&self, name: &str) -> Option<StoragePrice> {
        let spec = self.config.storages.iter().find(|s| s.name() == name)?;
        StoragePrice::merged(self.config.prices.get(name), price::builtin_for(spec))
    }

    /// The figures the user set for a storage (empty when none).
    pub fn storage_prices_set_by_user(&self, name: &str) -> StoragePrice {
        self.config.prices.get(name).cloned().unwrap_or_default()
    }

    /// Set the user's figures for a storage. `None`, or a price without any
    /// figure, removes them so that only the built-in figures apply.
    pub fn set_storage_price(&mut self, name: &str, price: Option<StoragePrice>) -> Result<()> {
        if !self.config.storages.iter().any(|s| s.name() == name) {
            bail!("unknown storage {name}");
        }
        match price.filter(|p| !p.is_empty()) {
            Some(mut p) => {
                let figures = [p.storage_per_gb_month, p.egress_per_gb, p.retrieval_per_gb];
                if figures.iter().flatten().any(|v| !v.is_finite() || *v < 0.0) {
                    bail!("prices must be zero or more");
                }
                p.currency = p.currency.trim().to_uppercase();
                p.source = String::new();
                self.config.prices.insert(name.to_string(), p);
            }
            None => {
                self.config.prices.remove(name);
            }
        }
        self.config.save(&self.home)
    }

    fn places(&self) -> Places {
        let mut p = Places::default();
        for spec in &self.config.storages {
            let n = spec.name().to_string();
            p.prices.insert(n.clone(), self.storage_price(&n));
            p.place.insert(n.clone(), spec.place());
            if spec.is_carrier() {
                p.carriers.insert(n);
            } else if !spec.is_cold() {
                p.readable.insert(n);
            }
        }
        p
    }

    /// Every configured storage with its price and the monthly cost of what
    /// the ledger records on it.
    pub fn storage_estimates(&self) -> Result<Vec<StorageEstimate>> {
        let view = self.view()?;
        Ok(self.estimates_from(&view, &BTreeMap::new()))
    }

    fn estimates_from(
        &self,
        view: &LedgerView,
        idle_on: &BTreeMap<String, u64>,
    ) -> Vec<StorageEstimate> {
        let mut bytes: BTreeMap<&str, u64> = BTreeMap::new();
        for rec in view.chunks.values() {
            for (name, loc) in &rec.storages {
                if !loc.claimed_by.is_empty() {
                    *bytes.entry(name.as_str()).or_default() += rec.size;
                }
            }
        }
        self.config
            .storages
            .iter()
            .map(|spec| {
                let name = spec.name();
                let price = self.storage_price(name);
                let b = bytes.get(name).copied().unwrap_or(0);
                StorageEstimate {
                    name: name.to_string(),
                    kind: spec.kind().to_string(),
                    cold: spec.is_cold(),
                    carrier: spec.is_carrier(),
                    bytes: b,
                    monthly_cost: price.as_ref().and_then(|p| p.monthly_cost(b)),
                    idle_monthly_cost: idle_on
                        .get(name)
                        .and_then(|i| price.as_ref().and_then(|p| p.monthly_cost(*i))),
                    currency: price
                        .as_ref()
                        .map(|p| p.currency.clone())
                        .unwrap_or_default(),
                    price,
                }
            })
            .collect()
    }

    /// The placement advice for every attached folder: idle files, the
    /// built-in class estimates, the configured storages with their prices,
    /// the monthly cost per folder, and the suggestions that can be applied.
    pub fn placement_advice(&self, idle_days: i64, now_utc: i64) -> Result<Advice> {
        let mut files = Vec::new();
        let mut entries: Vec<(FolderRecord, Vec<FileEntry>)> = Vec::new();
        for (rec, mount) in self.folders() {
            if mount.is_none() {
                continue;
            }
            let list = self.list_files(rec.folder_id.as_str())?;
            for e in &list {
                files.push((
                    rec.name.clone(),
                    e.path.clone(),
                    e.size,
                    e.last_accessed_utc,
                    e.modified_utc,
                ));
            }
            entries.push((rec, list));
        }
        let mut advice = advice::storage_advice(&files, idle_days, now_utc);
        let view = self.view()?;
        let places = self.places();
        let mut idle_on_total: BTreeMap<String, u64> = BTreeMap::new();
        for (rec, list) in &entries {
            let state = self.load_state(&rec.folder_id)?;
            let idle: HashSet<&str> = list
                .iter()
                .filter(|e| is_idle(e, idle_days, now_utc))
                .map(|e| e.path.as_str())
                .collect();
            let mut seen = HashSet::new();
            let mut on: BTreeMap<String, u64> = BTreeMap::new();
            let mut idle_on: BTreeMap<String, u64> = BTreeMap::new();
            let (mut bytes, mut idle_bytes) = (0u64, 0u64);
            for f in state.files.values().filter(|f| !f.deleted) {
                let f_idle = idle.contains(f.path.as_str());
                bytes += f.size;
                if f_idle {
                    idle_bytes += f.size;
                }
                for c in &f.chunks {
                    if !seen.insert(&c.chunk) {
                        continue;
                    }
                    let Some(r) = view.locate(&rec.folder_id, &c.chunk) else {
                        continue;
                    };
                    for (name, loc) in &r.storages {
                        if loc.claimed_by.is_empty() || !places.durable(name) {
                            continue;
                        }
                        *on.entry(name.clone()).or_default() += c.size;
                        if f_idle {
                            *idle_on.entry(name.clone()).or_default() += c.size;
                        }
                    }
                }
            }
            let mut monthly = Costs::new();
            let mut idle_monthly = Costs::new();
            let mut unpriced = Vec::new();
            for (name, b) in &on {
                match places
                    .price(name)
                    .and_then(|p| Some((p.monthly_cost(*b)?, p)))
                {
                    Some((cost, p)) => {
                        add_cost(&mut monthly, &p.currency, cost);
                        let i = idle_on.get(name).copied().unwrap_or(0);
                        add_cost(
                            &mut idle_monthly,
                            &p.currency,
                            p.monthly_cost(i).unwrap_or(0.0),
                        );
                    }
                    None => unpriced.push(name.clone()),
                }
            }
            for (n, b) in idle_on {
                *idle_on_total.entry(n).or_default() += b;
            }
            advice.folders.push(FolderCost {
                folder: rec.name.clone(),
                bytes,
                idle_bytes,
                monthly,
                idle_monthly,
                unpriced_storages: unpriced,
            });
            if let Some(s) =
                self.free_idle_suggestion(rec, list, &state, &view, &places, idle_days, now_utc)
            {
                advice.suggestions.push(s);
            }
        }
        advice.storages = self.estimates_from(&view, &idle_on_total);
        if !advice.storages.is_empty() {
            advice.notes.push("Storage prices are the ones you set (varsto storage price) and otherwise come from the built-in price data when the provider, region and class are recognised. Varsto writes every block to every storage, so a folder's monthly cost is the sum over the storages that hold it, and freeing files on this device frees disk space here without lowering the storage bill.".to_string());
        }
        Ok(advice)
    }

    /// Can the local copy of `file` go? Returns the bytes of blocks whose
    /// readable copies nobody has verified yet (checked before freeing), or
    /// the reason the copy must stay.
    fn placement_check(
        &self,
        rec: &FolderRecord,
        file: &FileState,
        view: &LedgerView,
        places: &Places,
        now_utc: i64,
    ) -> std::result::Result<u64, String> {
        let mut unverified = 0u64;
        let mut facts = Vec::new();
        for c in &file.chunks {
            let Some(r) = view.locate(&rec.folder_id, &c.chunk) else {
                return Err("not on any storage yet; sync first".to_string());
            };
            let readable: Vec<_> = r
                .storages
                .iter()
                .filter(|(n, l)| places.readable.contains(*n) && !l.claimed_by.is_empty())
                .collect();
            if readable.is_empty() {
                return Err("no copy on a storage this device reads without confirmation (cold storages and transferrers do not count); sync first".to_string());
            }
            if readable.iter().all(|(_, l)| l.verified_by.is_empty()) {
                unverified += c.size;
            }
            facts.push(ChunkFacts {
                copies: r
                    .storages
                    .iter()
                    .filter(|(n, l)| !l.claimed_by.is_empty() && !places.carriers.contains(*n))
                    .map(|(n, _)| {
                        let place = if n.starts_with("replica:") {
                            "replica".to_string()
                        } else {
                            places
                                .place
                                .get(n)
                                .cloned()
                                .unwrap_or_else(|| "other".to_string())
                        };
                        (n.clone(), place, false, 0)
                    })
                    .collect(),
            });
        }
        if let Some(p) = rec
            .policy
            .as_ref()
            .filter(|p| p.min_copies > 0 || !p.min_per_place.is_empty())
        {
            let copy_rules = Policy {
                verified_within_days: None,
                ..p.clone()
            };
            let r = policy::evaluate(
                &rec.name,
                &copy_rules,
                &facts,
                &BTreeMap::new(),
                &[],
                now_utc,
            );
            if r.state == PolicyState::Violated {
                return Err(format!(
                    "the folder's policy ({}) is not met for this file ({}), so the copy on this device stays",
                    p.describe(),
                    r.reasons.join("; ")
                ));
            }
        }
        Ok(unverified)
    }

    #[allow(clippy::too_many_arguments)]
    fn free_idle_suggestion(
        &self,
        rec: &FolderRecord,
        list: &[FileEntry],
        state: &FolderState,
        view: &LedgerView,
        places: &Places,
        idle_days: i64,
        now_utc: i64,
    ) -> Option<Suggestion> {
        let (mut files, mut bytes, mut verify_first) = (0u64, 0u64, 0u64);
        let mut examples = Vec::new();
        let mut blocked = Vec::new();
        let mut holders: BTreeSet<String> = BTreeSet::new();
        for e in idle_local(list, idle_days, now_utc) {
            let Some(f) = state.files.get(&e.path) else {
                continue;
            };
            match self.placement_check(rec, f, view, places, now_utc) {
                Ok(unverified) => {
                    files += 1;
                    bytes += f.size;
                    verify_first += unverified;
                    if examples.len() < 5 {
                        examples.push(e.path.clone());
                    }
                    for c in &f.chunks {
                        if let Some(r) = view.locate(&rec.folder_id, &c.chunk) {
                            for (n, l) in &r.storages {
                                if !l.claimed_by.is_empty() && places.durable(n) {
                                    holders.insert(n.clone());
                                }
                            }
                        }
                    }
                }
                Err(reason) => blocked.push((e.path.clone(), reason)),
            }
        }
        if files == 0 {
            return None;
        }
        let mut keep_on: Vec<String> = holders.into_iter().collect();
        keep_on.sort_by(|a, b| {
            let pa = places.price(a).and_then(|p| p.storage_per_gb_month);
            let pb = places.price(b).and_then(|p| p.storage_per_gb_month);
            pa.unwrap_or(f64::INFINITY)
                .partial_cmp(&pb.unwrap_or(f64::INFINITY))
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.cmp(b))
        });
        let cheapest = keep_on
            .first()
            .filter(|n| {
                places
                    .price(n)
                    .and_then(|p| p.storage_per_gb_month)
                    .is_some()
            })
            .cloned();
        let mut monthly = Costs::new();
        for n in &keep_on {
            if let Some(p) = places.price(n) {
                if let Some(c) = p.monthly_cost(bytes) {
                    add_cost(&mut monthly, &p.currency, c);
                }
            }
        }
        let mut read_back = Costs::new();
        if let Some((cost, cur)) = keep_on
            .iter()
            .filter(|n| places.readable.contains(*n))
            .filter_map(|n| {
                let p = places.price(n)?;
                Some((p.read_cost(bytes)?, p.currency.clone()))
            })
            .min_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
        {
            add_cost(&mut read_back, &cur, cost);
        }
        let mut summary = format!(
            "Free {files} idle file{} ({}) of folder {} on this device: each becomes a placeholder and is downloaded again when opened. The data stays on {}",
            if files == 1 { "" } else { "s" },
            fmt_size(bytes),
            rec.name,
            keep_on.join(", ")
        );
        if !monthly.is_empty() {
            summary += &format!(", where it costs {} a month", fmt_costs(&monthly));
        }
        summary += ".";
        if !read_back.is_empty() {
            summary += &format!(
                " Reading it all back later costs {}.",
                fmt_costs(&read_back)
            );
        }
        if verify_first > 0 {
            summary += &format!(
                " Blocks no device has verified on a readable storage yet ({}) are downloaded and hash-checked first.",
                fmt_size(verify_first)
            );
        }
        summary += &format!(
            " Saving: {} of disk space here; the storage bill does not change, because every storage already holds every block.",
            fmt_size(bytes)
        );
        let mut warnings = Vec::new();
        if !blocked.is_empty() {
            warnings.push(format!(
                "{} other idle file{} stay{} on this device: {}",
                blocked.len(),
                if blocked.len() == 1 { "" } else { "s" },
                if blocked.len() == 1 { "s" } else { "" },
                blocked[0].1
            ));
        }
        Some(Suggestion {
            id: format!("{FREE_IDLE_PREFIX}{}", rec.name),
            folder: rec.name.clone(),
            files,
            bytes,
            examples,
            keep_on,
            cheapest,
            monthly_cost: monthly,
            read_back_cost: read_back,
            verify_first_bytes: verify_first,
            blocked,
            summary,
            warnings,
        })
    }

    /// Carry out a suggestion: `free-idle:<folder>` (or just the folder name)
    /// frees the folder's idle files on this device after the checks above.
    /// Files that cannot go are listed in the report and left alone.
    pub fn apply_suggestion(&mut self, id: &str, idle_days: i64) -> Result<ApplyReport> {
        // The push, the checks and the frees record into one batch.
        self.one_batch(|e| e.apply_suggestion_now(id, idle_days))
    }

    fn apply_suggestion_now(&mut self, id: &str, idle_days: i64) -> Result<ApplyReport> {
        let folder = id.strip_prefix(FREE_IDLE_PREFIX).unwrap_or(id);
        let (rec, _) = self.resolve_folder(folder)?;
        let fid = rec.folder_id.to_string();
        // Upload what the storages still lack, so the ledger is current.
        self.push(&fid)?;
        let now = util::now_utc();
        let list = self.list_files(&fid)?;
        let state = self.load_state(&rec.folder_id)?;
        let view = self.view()?;
        let places = self.places();
        let mut backends: BTreeMap<String, Box<dyn Storage>> = BTreeMap::new();
        for spec in self.config.storages.clone() {
            if places.readable.contains(spec.name()) {
                if let Ok(b) = self.open_spec(&spec) {
                    backends.insert(spec.name().to_string(), b);
                }
            }
        }
        let mut report = ApplyReport {
            id: format!("{FREE_IDLE_PREFIX}{}", rec.name),
            folder: rec.name.clone(),
            ..Default::default()
        };
        for e in idle_local(&list, idle_days, now) {
            let Some(f) = state.files.get(&e.path) else {
                continue;
            };
            let checked =
                self.placement_check(&rec, f, &view, &places, now)
                    .and_then(|unverified| {
                        if unverified == 0 {
                            return Ok(0);
                        }
                        self.verify_copies(&rec, f, &view, &places, &backends)
                    });
            match checked {
                Ok(verified) => report.blocks_verified += verified,
                Err(reason) => {
                    report.skipped.push((e.path.clone(), reason));
                    continue;
                }
            }
            match self.free_file(&fid, &e.path) {
                Ok(()) => {
                    report.files_freed += 1;
                    report.bytes_freed += f.size;
                }
                Err(err) => report.skipped.push((e.path.clone(), format!("{err:#}"))),
            }
        }
        self.commit_batch()?;
        Ok(report)
    }

    /// Download and hash-check every block of `file` whose readable copies
    /// nobody has verified, recording the checks in the ledger.
    fn verify_copies(
        &mut self,
        rec: &FolderRecord,
        file: &FileState,
        view: &LedgerView,
        places: &Places,
        backends: &BTreeMap<String, Box<dyn Storage>>,
    ) -> std::result::Result<u64, String> {
        let mut verified = 0u64;
        for c in &file.chunks {
            let Some(r) = view.locate(&rec.folder_id, &c.chunk) else {
                return Err("not on any storage yet; sync first".to_string());
            };
            let holders: Vec<&String> = r
                .storages
                .iter()
                .filter(|(n, l)| places.readable.contains(*n) && !l.claimed_by.is_empty())
                .map(|(n, _)| n)
                .collect();
            if r.storages
                .iter()
                .any(|(n, l)| holders.contains(&n) && !l.verified_by.is_empty())
            {
                continue;
            }
            let key = chunk_storage_key(&r.object);
            let good = holders.into_iter().find(|n| {
                backends
                    .get(*n)
                    .and_then(|b| b.get(&key).ok().flatten())
                    .is_some_and(|ct| ObjectName::from_bytes(&crypto::hash(&ct)) == r.object)
            });
            let Some(storage) = good else {
                return Err(format!(
                    "no readable copy of block {} could be downloaded and matched its hash",
                    r.object.short()
                ));
            };
            self.pending.push(Event::ChunkVerified {
                folder: rec.folder_id.clone(),
                chunk: c.chunk.clone(),
                object: r.object.clone(),
                storage: storage.clone(),
            });
            verified += 1;
        }
        Ok(verified)
    }
}
