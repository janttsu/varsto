// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Draining a storage: emptying it onto the other storages without ever
//! weakening a folder's copies (`docs/spec/alpha-0-format.md` section 44).
//!
//! Starting a drain publishes it with the storage's shared settings
//! (`quotas`), so no device writes new blocks there any more; the storage
//! stays readable. The device that started it (the driver) then works
//! through the blocks the ledger places on the storage, in runs (the
//! service runs one after every sync), within a daily budget of bytes
//! copied:
//!
//! 1. Blocks that already have the copies they need elsewhere come first:
//!    they only have to be dropped. Then the others, oldest first.
//! 2. For each block, the copies it should keep without this one: the
//!    folder's placement says which storages take the folder's blocks
//!    (storages being drained and storages at their quota excepted), and
//!    every copy that dropping this one leaves must still meet the folder's
//!    policy as far as the copies met it before (its minimum count and
//!    per-place minimums, capped at what was there). A block is never left
//!    without a copy. Missing copies are written first and read back to
//!    check them (a cold target is checked by name only).
//! 3. Only then is the copy recorded as dropped (`ChunkDropped`, sealed and
//!    pushed) and deleted from the storage. A block whose policy cannot be
//!    met elsewhere stays, and the drain reports what is missing.
//! 4. When the storage holds no block, every record, ledger batch,
//!    manifest and thumbnail there is copied to the other storages that hold
//!    records, and the drain is published as finished ("drained"): no device
//!    writes to the storage or reads records from it any more. With
//!    "remove when empty" the driver then removes it.
//!
//! A run that stops halfway is carried on by the next one: copies already
//! made are found on their storages, drops already recorded are not made
//! twice, and blocks recorded as dropped are deleted at the end.

use super::data_moves::MoveItem;
use super::placement::fmt_size;
use super::quotas::QuotaGate;
use super::*;
use crate::advice::{add_cost, Costs};
use crate::storage_settings::{DrainPhase, DrainSetting};

/// Blocks per ledger batch: their drops are sealed and pushed before any
/// of them is deleted.
const DRAIN_GROUP: usize = 64;
/// How many distinct reasons a report lists.
const REASONS: usize = 10;
/// Local progress of the drains this device drives.
const STATE_FILE: &str = "drains.json";
/// The service's share per run (the daily budget applies as well).
pub const SERVICE_RUN_BYTES: u64 = 2 << 30;
pub const SERVICE_RUN_ITEMS: usize = 4096;

/// How a drain is started.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DrainOptions {
    pub remove_when_empty: bool,
    pub budget_bytes_per_day: Option<u64>,
    pub confirm_cold_read: bool,
}

/// How much one run may do (besides the daily budget).
#[derive(Clone, Debug, Default)]
pub struct DrainRunLimits {
    pub max_items: Option<usize>,
    pub max_bytes: Option<u64>,
}

impl DrainRunLimits {
    /// What the background service does per run.
    pub fn service() -> Self {
        DrainRunLimits {
            max_items: Some(SERVICE_RUN_ITEMS),
            max_bytes: Some(SERVICE_RUN_BYTES),
        }
    }
}

/// What draining a storage takes, worked out from the ledger.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DrainPlan {
    pub storage: String,
    pub cold: bool,
    /// Blocks the ledger places on the storage, and their bytes.
    pub blocks: u64,
    pub bytes: u64,
    /// Of those, blocks whose copies elsewhere already suffice.
    pub blocks_drop_only: u64,
    /// Blocks copied elsewhere first, and the bytes written for them (a
    /// block written to two storages counts twice).
    pub blocks_to_copy: u64,
    pub bytes_to_copy: u64,
    /// Bytes written per receiving storage.
    pub targets: BTreeMap<String, u64>,
    /// Bytes read from the storage itself (the rest comes from this
    /// device, its block cache or another storage).
    pub bytes_read_here: u64,
    /// Egress and retrieval of those reads, from the price data.
    pub egress_cost: Costs,
    /// What the storage still bills for its minimum storage duration.
    pub early_deletion_cost: Costs,
    pub budget_bytes_per_day: Option<u64>,
    /// Days the copies take at the daily budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days_at_budget: Option<f64>,
    /// Blocks that cannot leave now, and why (distinct reasons).
    pub blocks_blocked: u64,
    pub blocked: Vec<String>,
    /// Why the records cannot be moved, if they cannot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub records_blocked: Option<String>,
    /// "ok": every block keeps its folder's policy without this storage;
    /// "blocked": some cannot (see `blocked`).
    pub policy: String,
    pub notes: Vec<String>,
    pub summary: String,
}

/// What one run did.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct DrainRunReport {
    pub storage: String,
    pub blocks_copied: u64,
    pub bytes_copied: u64,
    pub copies_verified: u64,
    pub blocks_dropped: u64,
    pub bytes_dropped: u64,
    /// Objects deleted from the storage (blocks, and leftovers at the end).
    pub objects_deleted: u64,
    /// Blocks that stay for now, with a few reasons.
    pub blocks_kept: u64,
    pub kept: Vec<String>,
    /// Blocks left for later runs (budget or run limit).
    pub blocks_left_for_later: u64,
    pub records_copied: u64,
    /// The storage holds nothing Varsto needs any more.
    pub drained: bool,
    /// And was removed from this device's configuration.
    pub removed: bool,
    pub summary: String,
}

/// A drain as `storage drain status` shows it.
#[derive(Clone, Debug, Serialize)]
pub struct DrainStatus {
    pub storage: String,
    /// "draining", "blocked" (only blocks that cannot leave are left) or "drained".
    pub phase: String,
    pub started_utc: i64,
    pub driver: String,
    pub driven_here: bool,
    pub remove_when_empty: bool,
    pub budget_bytes_per_day: Option<u64>,
    pub confirm_cold_read: bool,
    pub blocks_left: u64,
    pub bytes_left: u64,
    /// Bytes on the storage when the drain started (known to the driver).
    pub bytes_at_start: Option<u64>,
    /// By bytes; 100 once nothing is left.
    pub percent: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_utc: Option<i64>,
    pub bytes_today: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run_utc: Option<i64>,
    pub blocked: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub summary: String,
}

/// This device's progress on a drain it drives.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct DrainState {
    started_utc: i64,
    bytes_at_start: u64,
    /// UTC day (days since the epoch) `bytes_today` counts.
    day: i64,
    bytes_today: u64,
    bytes_moved: u64,
    last_run_utc: Option<i64>,
    #[serde(default)]
    blocked: Vec<String>,
    /// The last run moved nothing because of `blocked`.
    #[serde(default)]
    stalled: bool,
    last_error: Option<String>,
}

/// One block on the draining storage, worked out.
struct DrainItem {
    folder: FolderId,
    chunk: ChunkId,
    object: ObjectName,
    epoch: u32,
    size: u64,
    claimed_utc: i64,
    /// The names its claims on the draining storage are under (this
    /// device's, and other devices' names for the same storage).
    sources: Vec<String>,
    /// Storages to copy it to first.
    targets: Vec<String>,
    /// The copies that stay (name, place).
    after: Vec<(String, String)>,
    /// The folder's copy rules capped at what the copies met before.
    rules: Option<Policy>,
    /// Files of the folder on this device that contain it.
    files: Vec<PathBuf>,
}

struct DrainWork {
    items: Vec<DrainItem>,
    plan: DrainPlan,
}

/// What a folder's blocks need, for a drain.
struct FolderNeeds {
    name: String,
    rules: Option<Policy>,
    /// Storages the folder's blocks go to (placement), drained ones out.
    targets: Vec<String>,
    /// Blocks current files (or known snapshots) use; `None`: unknown, all count.
    referenced: Option<HashSet<ChunkId>>,
    /// Key epoch and local files of each block, for re-encrypting locally.
    local: HashMap<ChunkId, (u32, Vec<PathBuf>)>,
}

/// Why the copies that stay do not hold, or `None` when they do.
fn shortfall(folder: &str, after: &[(String, String)], rules: Option<&Policy>) -> Option<String> {
    if after.is_empty() {
        return Some(format!(
            "a block of {folder} has no other copy and no other storage can take one: add another storage"
        ));
    }
    let r = rules?;
    for (place, n) in &r.min_per_place {
        let have = after.iter().filter(|(_, p)| p == place).count() as u32;
        if have < *n {
            return Some(format!(
                "folder {folder} needs {n} cop{} {} and no other storage there can take {}: add another {place} storage or lower the policy",
                if *n == 1 { "y" } else { "ies" },
                crate::policy::place_phrase(place),
                if *n - have == 1 { "it" } else { "them" }
            ));
        }
    }
    if (after.len() as u32) < r.min_copies {
        return Some(format!(
            "folder {folder} needs {} copies and no other storage can take another one: add another storage or lower the policy",
            r.min_copies
        ));
    }
    None
}

fn push_reason(list: &mut Vec<String>, why: String) {
    if !list.contains(&why) && list.len() < REASONS {
        list.push(why);
    }
}

fn fmt_costs(c: &Costs) -> String {
    c.iter()
        .map(|(cur, v)| format!("{v:.2} {cur}"))
        .collect::<Vec<_>>()
        .join(" + ")
}

impl Engine {
    // ----- local progress ------------------------------------------------------

    fn drain_states(&self) -> BTreeMap<String, DrainState> {
        util::read_json_or_default(&self.home.join("state").join(STATE_FILE)).unwrap_or_default()
    }

    fn save_drain_state(&self, name: &str, st: Option<&DrainState>) -> Result<()> {
        let mut all = self.drain_states();
        match st {
            Some(s) => {
                all.insert(name.to_string(), s.clone());
            }
            None => {
                all.remove(name);
            }
        }
        util::write_json(&self.home.join("state").join(STATE_FILE), &all)
    }

    pub(super) fn forget_drain_state(&self, name: &str) {
        let _ = self.save_drain_state(name, None);
    }

    // ----- planning -----------------------------------------------------------

    fn folder_needs(&self, rec: &FolderRecord, candidates: &[&StorageSpec]) -> FolderNeeds {
        let rules = rec
            .effective_policy()
            .filter(|p| p.min_copies > 0 || p.min_per_place.values().any(|n| *n > 0))
            .map(|p| Policy {
                verified_within_days: None,
                ..p
            });
        let placed = self.write_targets(rec);
        let mut targets: Vec<String> = candidates
            .iter()
            .filter(|s| placed.wants(s.name(), None))
            .map(|s| s.name().to_string())
            .collect();
        if targets.is_empty() {
            targets = candidates.iter().map(|s| s.name().to_string()).collect();
        }
        // Warm storages first: a cold one is written, rarely read.
        targets.sort_by_key(|n| {
            candidates
                .iter()
                .any(|s| s.name() == n.as_str() && s.is_cold())
        });
        let mut referenced = None;
        let mut local = HashMap::new();
        if rec.is_backup() {
            let known = self.backup_blocks_known(&rec.folder_id);
            if !known.is_empty() {
                referenced = Some(known.into_iter().map(|(c, _)| c).collect());
            }
        } else if let Ok(state) = self.load_state(&rec.folder_id) {
            let root = self
                .config
                .folders
                .iter()
                .find(|m| m.folder_id == rec.folder_id)
                .map(|m| m.path.clone());
            let plain_here = root.is_some() && !self.mount_is_encrypted(&rec.folder_id);
            let mut refs = HashSet::new();
            for f in state.files.values().filter(|f| !f.deleted) {
                let path = match &root {
                    Some(r) if plain_here && state.local_index.contains_key(&f.path) => {
                        Some(self.disk_of(r, &state, &f.path))
                    }
                    _ => None,
                };
                for c in &f.chunks {
                    refs.insert(c.chunk.clone());
                    let e = local
                        .entry(c.chunk.clone())
                        .or_insert_with(|| (c.epoch, Vec::new()));
                    e.1.extend(path.clone());
                }
            }
            // A folder never synced here has no state: every block counts.
            if !state.files.is_empty() {
                referenced = Some(refs);
            }
        }
        FolderNeeds {
            name: rec.name.clone(),
            rules,
            targets,
            referenced,
            local,
        }
    }

    /// Work out a drain of `name` from the ledger, taking room on the
    /// receiving storages from `gate`.
    fn drain_work(
        &self,
        name: &str,
        confirm_cold_read: bool,
        gate: &QuotaGate,
    ) -> Result<DrainWork> {
        let spec = self
            .config
            .storages
            .iter()
            .find(|s| s.name() == name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown storage {name}"))?;
        let view = self.view()?;
        let closed = self.closed_storages();
        let carriers: BTreeSet<&str> = self
            .config
            .storages
            .iter()
            .filter(|s| s.is_carrier())
            .map(|s| s.name())
            .collect();
        let place_of = |n: &str| -> Option<String> {
            if n.starts_with("replica:") {
                return Some("replica".to_string());
            }
            self.config
                .storages
                .iter()
                .find(|s| s.name() == n && !s.is_carrier())
                .map(|s| s.place())
        };
        let hot: BTreeSet<&str> = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_cold() && !s.is_carrier() && s.name() != name)
            .map(|s| s.name())
            .collect();
        let candidates: Vec<&StorageSpec> = self
            .config
            .storages
            .iter()
            .filter(|s| s.name() != name && !s.is_carrier() && !closed.contains(s.name()))
            .collect();
        let mut needs: HashMap<FolderId, FolderNeeds> = HashMap::new();
        for rec in self.keyring.folders.values() {
            let n = if rec.is_removed() {
                // Nothing needs a removed folder's blocks beyond not losing
                // the last copy.
                FolderNeeds {
                    name: rec.name.clone(),
                    rules: None,
                    targets: candidates.iter().map(|s| s.name().to_string()).collect(),
                    referenced: Some(HashSet::new()),
                    local: HashMap::new(),
                }
            } else {
                self.folder_needs(rec, &candidates)
            };
            needs.insert(rec.folder_id.clone(), n);
        }
        let unknown = FolderNeeds {
            name: "(a folder this device does not know)".to_string(),
            rules: None,
            targets: candidates.iter().map(|s| s.name().to_string()).collect(),
            referenced: Some(HashSet::new()),
            local: HashMap::new(),
        };
        let price = self.storage_price(name);
        let now = util::now_utc();
        let mut plan = DrainPlan {
            storage: name.to_string(),
            cold: spec.is_cold(),
            ..Default::default()
        };
        let mut items = Vec::new();
        let mut early = Costs::new();
        let source_place = spec.place();
        let mut quota_refused: BTreeSet<String> = BTreeSet::new();
        // Claims name storages by their writers' names: each is matched to
        // a storage here by identity (section 20), or by equal name.
        let names = self.drain_resolver();
        let configured: BTreeSet<String> = self
            .config
            .storages
            .iter()
            .map(|s| s.name().to_string())
            .collect();
        let mut keys: Vec<(&(FolderId, ChunkId), Vec<String>)> = view
            .chunks
            .iter()
            .filter(|((f, _), _)| !f.as_str().is_empty())
            .filter_map(|(k, r)| {
                let sources: Vec<String> = r
                    .storages
                    .iter()
                    .filter(|(n, l)| {
                        !l.claimed_by.is_empty()
                            && names.resolve_any(n, &l.claimed_by, &configured).as_deref()
                                == Some(name)
                    })
                    .map(|(n, _)| n.clone())
                    .collect();
                (!sources.is_empty()).then_some((k, sources))
            })
            .collect();
        keys.sort();
        for (key, sources) in keys {
            let r = &view.chunks[key];
            let (folder, chunk) = key;
            let claimed_utc = sources
                .iter()
                .map(|n| r.storages[n].claimed_utc)
                .min()
                .unwrap_or(0);
            plan.blocks += 1;
            plan.bytes += r.size;
            let need = needs.get(folder).unwrap_or(&unknown);
            // The copies that stay: on the other storages known here.
            let mut after: Vec<(String, String)> = Vec::new();
            for (n, l) in &r.storages {
                if l.claimed_by.is_empty() {
                    continue;
                }
                let Some(local) = names.resolve_any(n, &l.claimed_by, &configured) else {
                    continue;
                };
                if local == name || carriers.contains(local.as_str()) {
                    continue;
                }
                if after.iter().any(|(x, _)| *x == local) {
                    continue;
                }
                if let Some(p) = place_of(&local) {
                    after.push((local, p));
                }
            }
            // The rules as far as the copies met them before.
            let rules = need.rules.as_ref().map(|p| {
                let before: Vec<&str> = after
                    .iter()
                    .map(|(_, p)| p.as_str())
                    .chain(std::iter::once(source_place.as_str()))
                    .collect();
                let mut capped = p.clone();
                capped.min_copies = capped.min_copies.min(before.len() as u32);
                for (place, n) in capped.min_per_place.iter_mut() {
                    let have = before.iter().filter(|p| **p == place).count() as u32;
                    *n = (*n).min(have);
                }
                capped
            });
            let referenced = need.referenced.as_ref().is_none_or(|s| s.contains(chunk));
            let mut targets: Vec<String> = Vec::new();
            let holds = |t: &str| after.iter().any(|(n, _)| n == t);
            if referenced {
                // Every storage the placement takes, as far as there is room.
                for t in &need.targets {
                    if holds(t) {
                        continue;
                    }
                    if gate.take(t, r.size) {
                        targets.push(t.clone());
                    } else {
                        quota_refused.insert(t.clone());
                    }
                }
            } else if after.is_empty() {
                // Nothing uses it any more: one copy elsewhere is enough.
                for t in &need.targets {
                    if gate.take(t, r.size) {
                        targets.push(t.clone());
                        break;
                    }
                    quota_refused.insert(t.clone());
                }
            }
            let mut with: Vec<(String, String)> = after.clone();
            for t in &targets {
                with.push((t.clone(), place_of(t).unwrap_or_default()));
            }
            let mut why = shortfall(&need.name, &with, rules.as_ref());
            let local = need.local.get(chunk);
            let files: Vec<PathBuf> = local.map(|(_, f)| f.clone()).unwrap_or_default();
            let read_here = !targets.is_empty()
                && files.is_empty()
                && !after.iter().any(|(n, _)| hot.contains(n.as_str()));
            if why.is_none() && read_here && spec.is_cold() && !confirm_cold_read {
                why = Some(format!(
                    "the only copy to read is on cold storage {name}: confirm the cold read (retrieval fees and restore delays apply)"
                ));
            }
            if let Some(why) = why {
                for t in &targets {
                    gate.give_back(t, r.size);
                }
                plan.blocks_blocked += 1;
                let why = match quota_refused.iter().next() {
                    Some(full) if why.contains("no other storage") => {
                        format!("{why} ({})", gate.message(full))
                    }
                    _ => why,
                };
                push_reason(&mut plan.blocked, why);
                continue;
            }
            if targets.is_empty() {
                plan.blocks_drop_only += 1;
            } else {
                plan.blocks_to_copy += 1;
                for t in &targets {
                    plan.bytes_to_copy += r.size;
                    *plan.targets.entry(t.clone()).or_default() += r.size;
                }
                if read_here {
                    plan.bytes_read_here += r.size;
                }
            }
            if let Some(p) = &price {
                let days = ((now - claimed_utc).max(0) / 86_400) as u32;
                if let Some(c) = p.early_deletion_cost(r.size, days).filter(|c| *c > 0.0) {
                    add_cost(&mut early, &p.currency, c);
                }
            }
            items.push(DrainItem {
                folder: folder.clone(),
                chunk: chunk.clone(),
                object: r.object.clone(),
                epoch: local.map(|(e, _)| *e).unwrap_or(0),
                size: r.size,
                claimed_utc,
                sources,
                targets,
                after,
                rules,
                files,
            });
        }
        // Drops first (no egress), then the oldest blocks.
        items.sort_by_key(|i| (!i.targets.is_empty(), i.claimed_utc));
        if let Some(p) = &price {
            if let Some(c) = p.read_cost(plan.bytes_read_here).filter(|c| *c > 0.0) {
                add_cost(&mut plan.egress_cost, &p.currency, c);
            }
        }
        plan.early_deletion_cost = early;
        plan.policy = if plan.blocks_blocked == 0 {
            "ok"
        } else {
            "blocked"
        }
        .to_string();
        plan.records_blocked = self.records_blocker(name);
        if spec.is_cold() {
            plan.notes.push(if confirm_cold_read {
                format!("{name} is cold storage: reading blocks from it costs retrieval fees and may wait for restores")
            } else {
                format!("{name} is cold storage: blocks whose only readable copy is there stay until you confirm the cold read (--confirm-cold-read)")
            });
        }
        if !plan.early_deletion_cost.is_empty() {
            plan.notes.push(format!(
                "{name} bills a minimum storage duration: deleting blocks now still costs about {}",
                fmt_costs(&plan.early_deletion_cost)
            ));
        }
        for t in &quota_refused {
            plan.notes.push(gate.message(t));
        }
        for t in plan.targets.keys() {
            if candidates
                .iter()
                .any(|s| s.name() == t.as_str() && s.is_cold())
            {
                plan.notes.push(format!(
                    "{t} is cold storage: copies there are checked by name only, and reading them later needs confirmation"
                ));
            }
        }
        Ok(DrainWork { items, plan })
    }

    /// Why the records on `name` cannot be moved now, if they cannot.
    fn records_blocker(&self, name: &str) -> Option<String> {
        let spec = self.config.storages.iter().find(|s| s.name() == name)?;
        if spec.is_data_only() {
            return None;
        }
        let closed = self.closed_storages();
        let others = self.config.storages.iter().any(|s| {
            s.name() != name && !s.is_data_only() && !s.is_carrier() && !closed.contains(s.name())
        });
        (!others).then(|| {
            format!("{name} is the only storage that holds the vault's records and ledger: add another storage (not a disk pool) first")
        })
    }

    fn drain_summary(&self, plan: &mut DrainPlan) {
        let mut s = format!(
            "{} holds {} block{} ({}).",
            plan.storage,
            plan.blocks,
            if plan.blocks == 1 { "" } else { "s" },
            fmt_size(plan.bytes)
        );
        if plan.blocks_drop_only > 0 {
            s += &format!(
                " {} already have the copies they need elsewhere and are only deleted.",
                plan.blocks_drop_only
            );
        }
        if plan.blocks_to_copy > 0 {
            s += &format!(
                " {} are copied first ({} to {}), each read back before the old copy goes.",
                plan.blocks_to_copy,
                fmt_size(plan.bytes_to_copy),
                plan.targets
                    .iter()
                    .map(|(t, b)| format!("{t} {}", fmt_size(*b)))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        if plan.bytes_read_here > 0 {
            s += &format!(
                " {} is read from {}",
                fmt_size(plan.bytes_read_here),
                plan.storage
            );
            s += &if plan.egress_cost.is_empty() {
                " (no price known for its egress).".to_string()
            } else {
                format!(", about {} of egress.", fmt_costs(&plan.egress_cost))
            };
        }
        if let Some(d) = plan.days_at_budget {
            s += &format!(
                " At the daily budget this takes about {:.0} day{}.",
                d.ceil(),
                if d.ceil() == 1.0 { "" } else { "s" }
            );
        }
        if plan.blocks_blocked == 0 {
            s += " Every folder's policy holds without it.";
        } else {
            s += &format!(
                " {} block{} cannot leave: {}.",
                plan.blocks_blocked,
                if plan.blocks_blocked == 1 { "" } else { "s" },
                plan.blocked.join("; ")
            );
        }
        if let Some(r) = &plan.records_blocked {
            s += &format!(" {r}.");
        }
        plan.summary = s;
    }

    /// What draining `name` takes now (the drain dialog, `--plan`).
    pub fn drain_plan(&self, name: &str, opts: &DrainOptions) -> Result<DrainPlan> {
        self.drain_check(name)?;
        let view = self.view()?;
        let gate = self.quota_gate(&view);
        let current = self.storage_settings(name).drain;
        let confirm =
            opts.confirm_cold_read || current.as_ref().is_some_and(|d| d.confirm_cold_read);
        let mut plan = self.drain_work(name, confirm, &gate)?.plan;
        plan.budget_bytes_per_day = opts
            .budget_bytes_per_day
            .or(current.and_then(|d| d.budget_bytes_per_day));
        plan.days_at_budget = plan
            .budget_bytes_per_day
            .filter(|b| *b > 0 && plan.bytes_to_copy > 0)
            .map(|b| plan.bytes_to_copy as f64 / b as f64);
        self.drain_summary(&mut plan);
        Ok(plan)
    }

    fn drain_check(&self, name: &str) -> Result<&StorageSpec> {
        let spec = self
            .config
            .storages
            .iter()
            .find(|s| s.name() == name)
            .ok_or_else(|| anyhow!("unknown storage {name}"))?;
        if spec.is_carrier() {
            bail!("{name} is a transferrer: it empties itself as devices receive what it carries");
        }
        Ok(spec)
    }

    // ----- starting and stopping ------------------------------------------------

    /// Start draining `name` (or change how an ongoing drain runs): publish
    /// it so no device writes new blocks there, and drive it from this
    /// device. Returns the plan as of now.
    pub fn drain_start(&mut self, name: &str, opts: &DrainOptions) -> Result<DrainPlan> {
        self.ensure_active()?;
        if self.vault.member {
            bail!("a member device cannot drain the owner's storages");
        }
        self.org_allows(|p| p.members_may_add_storages, "drain storages")?;
        self.drain_check(name)?;
        let closed = self.closed_storages();
        if !self
            .config
            .storages
            .iter()
            .any(|s| s.name() != name && !s.is_carrier() && !closed.contains(s.name()))
        {
            bail!("{name} is the only storage left to keep the data: add the storage it should go to first");
        }
        if opts.budget_bytes_per_day == Some(0) {
            bail!("a daily budget must be more than zero");
        }
        if self.storage_settings(name).drain.is_none() {
            let folders = self.folders_placed_on(name);
            if !folders.is_empty() {
                bail!(
                    "{name} is still where {} {} written to: change their placement first (Policies > Placement, or `varsto folder placement <folder> --storage <other>`), then drain {name}",
                    folders.join(", "),
                    if folders.len() == 1 { "is" } else { "are" }
                );
            }
        }
        let mut settings = self.storage_settings(name);
        let prev = settings.drain.clone();
        settings.drain = Some(DrainSetting {
            phase: prev.as_ref().map(|d| d.phase).unwrap_or_default(),
            started_utc: prev
                .as_ref()
                .map(|d| d.started_utc)
                .unwrap_or_else(util::now_utc),
            driver: self.vault.device_id.clone(),
            remove_when_empty: opts.remove_when_empty,
            budget_bytes_per_day: opts.budget_bytes_per_day,
            confirm_cold_read: opts.confirm_cold_read,
            drained_utc: prev.as_ref().and_then(|d| d.drained_utc),
        });
        self.publish_storage_settings(name, settings)?;
        let mut st = self.drain_states().remove(name).unwrap_or_default();
        if st.started_utc == 0 {
            st.started_utc = util::now_utc();
            st.bytes_at_start = self.claimed_bytes_on(name)?.1;
        }
        self.save_drain_state(name, Some(&st))?;
        self.drain_plan(name, opts)
    }

    /// Folders whose placement names `name` (or the only open storage of
    /// its place), so a drain would leave them with nowhere to write.
    fn folders_placed_on(&self, name: &str) -> Vec<String> {
        let Some(spec) = self.config.storages.iter().find(|s| s.name() == name) else {
            return Vec::new();
        };
        let place = spec.place();
        let closed = self.closed_storages();
        let only_in_place = !self.config.storages.iter().any(|s| {
            s.name() != name && !s.is_carrier() && s.place() == place && !closed.contains(s.name())
        });
        let mut out: Vec<String> = self
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed())
            .filter(|r| {
                r.placement.as_ref().is_some_and(|p| {
                    p.storages.iter().any(|s| s == name)
                        || (only_in_place && p.places.contains(&place))
                })
            })
            .map(|r| r.name.clone())
            .collect();
        out.sort();
        out
    }

    /// Stop draining: the storage takes new blocks again. Copies already
    /// moved stay where they are now.
    pub fn drain_stop(&mut self, name: &str) -> Result<()> {
        self.org_allows(|p| p.members_may_add_storages, "drain storages")?;
        let mut settings = self.storage_settings(name);
        if settings.drain.is_none() {
            bail!("{name} is not being drained");
        }
        settings.drain = None;
        self.publish_storage_settings(name, settings)?;
        self.forget_drain_state(name);
        Ok(())
    }

    /// Storage identities and the other devices' names for them.
    pub(super) fn drain_resolver(&self) -> super::verify::NameResolver {
        let mut readable: BTreeMap<String, Box<dyn Storage>> = BTreeMap::new();
        for spec in &self.config.storages {
            if spec.is_cold() || spec.is_carrier() {
                continue;
            }
            if let Ok(b) = self.open_spec(spec) {
                readable.insert(spec.name().to_string(), b);
            }
        }
        self.storage_resolver(&readable)
    }

    /// Blocks some claim still places on `name`, under any device's name
    /// for it.
    fn claims_left_on(&self, name: &str, names: &super::verify::NameResolver) -> Result<u64> {
        let configured: BTreeSet<String> = self
            .config
            .storages
            .iter()
            .map(|s| s.name().to_string())
            .collect();
        let view = self.view()?;
        Ok(view
            .chunks
            .iter()
            .filter(|((f, _), _)| !f.as_str().is_empty())
            .filter(|(_, r)| {
                r.storages.iter().any(|(n, l)| {
                    !l.claimed_by.is_empty()
                        && names.resolve_any(n, &l.claimed_by, &configured).as_deref() == Some(name)
                })
            })
            .count() as u64)
    }

    /// Objects that must stay on `name`: a claim places them there (under
    /// any device's name for it), or on a storage this device cannot
    /// match to one of its own (it may be this one).
    fn objects_kept_on(
        &self,
        name: &str,
        names: &super::verify::NameResolver,
    ) -> Result<HashSet<ObjectName>> {
        let configured: BTreeSet<String> = self
            .config
            .storages
            .iter()
            .map(|s| s.name().to_string())
            .collect();
        let view = self.view()?;
        let mut out = HashSet::new();
        for r in view.chunks.values() {
            for (n, l) in &r.storages {
                if l.claimed_by.is_empty() {
                    continue;
                }
                match names.resolve_any(n, &l.claimed_by, &configured) {
                    Some(local) if local != name => {}
                    _ => {
                        out.insert(r.object.clone());
                    }
                }
            }
        }
        Ok(out)
    }

    /// (blocks, bytes) the ledger places on `name`.
    fn claimed_bytes_on(&self, name: &str) -> Result<(u64, u64)> {
        let view = self.view()?;
        let mut seen = HashSet::new();
        let (mut blocks, mut bytes) = (0u64, 0u64);
        for r in view.chunks.values() {
            if r.storages
                .get(name)
                .is_some_and(|l| !l.claimed_by.is_empty())
                && seen.insert(&r.object)
            {
                blocks += 1;
                bytes += r.size;
            }
        }
        Ok((blocks, bytes))
    }

    // ----- running ------------------------------------------------------------------

    /// The drains this device drives that have work left (the service runs
    /// them after a sync).
    /// A drained storage is run again only when a block arrived there
    /// after all (a device that had not synced yet) or it is still to be
    /// removed.
    pub fn drains_to_run(&self) -> Vec<String> {
        self.config
            .storage_settings
            .iter()
            .filter(|(n, e)| {
                e.settings.drain.as_ref().is_some_and(|d| {
                    d.driver == self.vault.device_id
                        && (d.phase == DrainPhase::Draining
                            || d.remove_when_empty
                            || self.claimed_bytes_on(n).is_ok_and(|(b, _)| b > 0))
                }) && self.config.storages.iter().any(|s| s.name() == n.as_str())
            })
            .map(|(n, _)| n.clone())
            .collect()
    }

    /// One run of a drain: copy, check, drop and delete as many blocks as
    /// the limits and the daily budget allow; when none is left, move the
    /// records and finish.
    pub fn drain_run(&mut self, name: &str, limits: &DrainRunLimits) -> Result<DrainRunReport> {
        let result = self.drain_run_inner(name, limits);
        // Removed with the storage: nothing to note.
        if let Some(mut st) = self.drain_states().remove(name) {
            st.last_run_utc = Some(util::now_utc());
            st.last_error = result.as_ref().err().map(|e| format!("{e:#}"));
            if let Ok(r) = &result {
                st.stalled = !r.drained
                    && r.blocks_dropped == 0
                    && r.blocks_copied == 0
                    && !st.blocked.is_empty();
            }
            self.save_drain_state(name, Some(&st))?;
        }
        result
    }

    fn drain_run_inner(&mut self, name: &str, limits: &DrainRunLimits) -> Result<DrainRunReport> {
        self.ensure_active()?;
        if self.vault.member {
            bail!("a member device cannot drain the owner's storages");
        }
        if self.forked_self {
            bail!("this device's ledger is forked; it must be re-enrolled as a new device");
        }
        let spec = self.drain_check(name)?.clone();
        let Some(setting) = self.storage_settings(name).drain else {
            bail!("{name} is not being drained (start with: varsto storage drain {name})");
        };
        self.pull_ledger_once()?;
        let mut st = self.drain_states().remove(name).unwrap_or_default();
        let today = util::now_utc().div_euclid(86_400);
        if st.day != today {
            st.day = today;
            st.bytes_today = 0;
        }
        let mut report = DrainRunReport {
            storage: name.to_string(),
            ..Default::default()
        };
        let view = self.view()?;
        let gate = self.quota_gate(&view);
        let work = self.drain_work(name, setting.confirm_cold_read, &gate)?;
        st.blocked = work.plan.blocked.clone();
        report.blocks_kept += work.plan.blocks_blocked;
        report.kept = work.plan.blocked.clone();
        // What this run takes: drops always, copies within the budget.
        let budget_left = setting
            .budget_bytes_per_day
            .map(|b| b.saturating_sub(st.bytes_today));
        let mut planned_copy = 0u64;
        let mut chosen: Vec<DrainItem> = Vec::new();
        let total = work.items.len();
        for item in work.items {
            if limits.max_items.is_some_and(|m| chosen.len() >= m) {
                break;
            }
            let cost = item.size * item.targets.len() as u64;
            if cost > 0 {
                // The first block of a day goes even when larger than the budget.
                let first = planned_copy == 0 && st.bytes_today == 0;
                if !first
                    && (budget_left.is_some_and(|l| planned_copy + cost > l)
                        || limits.max_bytes.is_some_and(|m| planned_copy + cost > m))
                {
                    break;
                }
                planned_copy += cost;
            }
            chosen.push(item);
        }
        report.blocks_left_for_later = (total - chosen.len()) as u64;
        if !chosen.is_empty() {
            self.drain_blocks(&spec, &setting, chosen, &mut report)?;
        }
        st.bytes_today += report.bytes_copied;
        st.bytes_moved += report.bytes_dropped;
        // Finished with the blocks: the records follow, then the drain ends.
        let left = self.claims_left_on(name, &self.drain_resolver())?;
        if left == 0 {
            if let Some(why) = self.records_blocker(name) {
                push_reason(&mut report.kept, why.clone());
                push_reason(&mut st.blocked, why);
            } else {
                report.objects_deleted += self.delete_leftovers(&spec);
                self.retire_stale_locations(name)?;
                report.records_copied = self.drain_records(&spec)?;
                let mut settings = self.storage_settings(name);
                if let Some(d) = settings.drain.as_mut() {
                    if d.phase != DrainPhase::Drained {
                        d.phase = DrainPhase::Drained;
                        d.drained_utc = Some(util::now_utc());
                        self.publish_storage_settings(name, settings.clone())?;
                    }
                }
                report.drained = true;
                st.blocked.clear();
                if setting.remove_when_empty {
                    self.remove_storage(name, false)?;
                    report.removed = true;
                }
            }
        }
        if !report.removed {
            self.save_drain_state(name, Some(&st))?;
        }
        report.summary = Self::run_summary(&report);
        Ok(report)
    }

    /// Copy, check, drop and delete the chosen blocks, one batch per group.
    fn drain_blocks(
        &mut self,
        spec: &StorageSpec,
        setting: &DrainSetting,
        items: Vec<DrainItem>,
        report: &mut DrainRunReport,
    ) -> Result<()> {
        let name = spec.name().to_string();
        let source = self.open_spec(spec)?;
        let names = self.drain_resolver();
        let read_source = !spec.is_cold() || setting.confirm_cold_read;
        let others: OpenStorages = self
            .open_storages(false)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier() && s.name() != name)
            .collect();
        let mut targets: BTreeMap<String, (StorageSpec, Box<dyn Storage>)> = BTreeMap::new();
        let task = activity::start(
            activity::DRAIN,
            &name,
            items.iter().map(|i| i.size).sum(),
            activity::Unit::Bytes,
        );
        task.set_phase("copy");
        for group in items.chunks(DRAIN_GROUP) {
            let mut deletes: Vec<(ObjectName, u64)> = Vec::new();
            // Ciphertexts re-made from the files on this device, per folder.
            let mut local: HashMap<ObjectName, Vec<u8>> = HashMap::new();
            let mut by_folder: BTreeMap<&FolderId, Vec<MoveItem>> = BTreeMap::new();
            for i in group
                .iter()
                .filter(|i| !i.targets.is_empty() && !i.files.is_empty())
            {
                by_folder
                    .entry(&i.folder)
                    .or_default()
                    .push(self.move_item(i));
            }
            for (fid, list) in by_folder {
                let Some(rec) = self.keyring.folders.get(fid).cloned() else {
                    continue;
                };
                if let Ok(fk) = self.folder_keys(&rec) {
                    local.extend(self.local_ciphertexts(&fk, list.iter()));
                }
            }
            // Every copy this group needs, written per target in one go (as
            // packs on a storage that keeps them, `crate::packs`).
            let mut cts: HashMap<ObjectName, Vec<u8>> = HashMap::new();
            for item in group.iter().filter(|i| !i.targets.is_empty()) {
                let ct = local.remove(&item.object).or_else(|| {
                    self.move_source(&self.move_item(item), &others, source.as_ref(), read_source)
                });
                if let Some(ct) = ct {
                    cts.insert(item.object.clone(), ct);
                }
            }
            let mut write_failed: BTreeMap<String, String> = BTreeMap::new();
            let wanted_targets: BTreeSet<String> = group
                .iter()
                .filter(|i| cts.contains_key(&i.object))
                .flat_map(|i| i.targets.iter().cloned())
                .collect();
            for t in wanted_targets {
                if !targets.contains_key(&t) {
                    let Some(tspec) = self.config.storages.iter().find(|s| s.name() == t).cloned()
                    else {
                        continue;
                    };
                    match self.open_spec(&tspec) {
                        Ok(b) => {
                            targets.insert(t.clone(), (tspec, b));
                        }
                        Err(e) => {
                            write_failed.insert(t.clone(), format!("{t} cannot be opened: {e:#}"));
                            continue;
                        }
                    }
                }
                let members: Vec<(String, &[u8])> = group
                    .iter()
                    .filter(|i| i.targets.contains(&t))
                    .filter_map(|i| {
                        cts.get(&i.object)
                            .map(|c| (i.object.as_str().to_string(), c.as_slice()))
                    })
                    .collect();
                if let Err(e) = targets[&t].1.put_pack(&members) {
                    let why = match pool::pool_error(&e) {
                        Some(pe) => pe.to_string(),
                        None => format!("writing to {t} failed: {e:#}"),
                    };
                    write_failed.insert(t.clone(), why);
                }
            }
            for item in group {
                task.advance(item.size);
                let mut made: Vec<(String, String)> = Vec::new();
                if !item.targets.is_empty() {
                    let Some(ct) = cts.get(&item.object) else {
                        report.blocks_kept += 1;
                        push_reason(
                            &mut report.kept,
                            "no readable copy of a block was found; it stays".to_string(),
                        );
                        continue;
                    };
                    let key = chunk_storage_key(&item.object);
                    for t in &item.targets {
                        if let Some(why) = write_failed.get(t) {
                            push_reason(&mut report.kept, why.clone());
                            continue;
                        }
                        let Some((tspec, backend)) = targets.get(t) else {
                            continue;
                        };
                        // Read back before the old copy may go.
                        let read_back = !tspec.is_cold();
                        let ok = if read_back {
                            matches!(backend.get(&key), Ok(Some(b)) if ObjectName::from_bytes(&crypto::hash(&b)) == item.object)
                        } else {
                            backend.exists(&key).unwrap_or(false)
                        };
                        if !ok {
                            push_reason(
                                &mut report.kept,
                                format!("the copy on {t} could not be checked"),
                            );
                            continue;
                        }
                        report.copies_verified += 1;
                        report.bytes_copied += ct.len() as u64;
                        self.pending.push(Event::ChunkStored {
                            folder: item.folder.clone(),
                            chunk: item.chunk.clone(),
                            object: item.object.clone(),
                            storage: t.clone(),
                            size: ct.len() as u64,
                            pack: None,
                        });
                        if read_back {
                            self.pending.push(Event::ChunkVerified {
                                folder: item.folder.clone(),
                                chunk: item.chunk.clone(),
                                object: item.object.clone(),
                                storage: t.clone(),
                            });
                        }
                        made.push((t.clone(), tspec.place()));
                    }
                    if !made.is_empty() {
                        report.blocks_copied += 1;
                    }
                }
                // The copies that stay, with those just made, must hold.
                let mut with = item.after.clone();
                with.extend(made);
                let folder_name = self
                    .keyring
                    .folders
                    .get(&item.folder)
                    .map(|r| r.name.clone())
                    .unwrap_or_else(|| item.folder.short().to_string());
                if let Some(why) = shortfall(&folder_name, &with, item.rules.as_ref()) {
                    report.blocks_kept += 1;
                    push_reason(&mut report.kept, why);
                    continue;
                }
                for source_name in &item.sources {
                    self.pending.push(Event::ChunkDropped {
                        folder: item.folder.clone(),
                        chunk: item.chunk.clone(),
                        object: item.object.clone(),
                        storage: source_name.clone(),
                    });
                }
                deletes.push((item.object.clone(), item.size));
            }
            // The copies and drops are sealed and pushed before anything is deleted.
            self.commit_batch()?;
            let in_use = self.objects_kept_on(&name, &names)?;
            for (object, size) in deletes {
                report.blocks_dropped += 1;
                report.bytes_dropped += size;
                if in_use.contains(&object) {
                    continue;
                }
                match source.delete(&chunk_storage_key(&object)) {
                    Ok(()) => report.objects_deleted += 1,
                    Err(e) => push_reason(
                        &mut report.kept,
                        format!("a block recorded as dropped could not be deleted from {name} ({e:#}); the next run tries again"),
                    ),
                }
            }
        }
        Ok(())
    }

    fn move_item(&self, i: &DrainItem) -> MoveItem {
        MoveItem {
            chunk: i.chunk.clone(),
            object: i.object.clone(),
            epoch: i.epoch,
            size: i.size,
            on_to: false,
            files: i.files.clone(),
        }
    }

    /// Delete the block objects still on a storage that no claim counts any
    /// more (drops recorded by a run that stopped before deleting).
    fn delete_leftovers(&self, spec: &StorageSpec) -> u64 {
        let Ok(source) = self.open_spec(spec) else {
            return 0;
        };
        let Ok(in_use) = self.objects_kept_on(spec.name(), &self.drain_resolver()) else {
            return 0;
        };
        let Ok(keys) = source.list("chunks/") else {
            return 0;
        };
        let mut n = 0;
        for key in keys {
            let Some(obj) =
                crate::packs::object_of(&key).and_then(|o| ObjectName::from_hex(o).ok())
            else {
                continue;
            };
            if !in_use.contains(&obj) && source.delete(&key).is_ok() {
                n += 1;
            }
        }
        n
    }

    /// Locations the view still lists on `name` although no claim counts
    /// there (a verification a device made before it saw the drop, an old
    /// record): dropped for every file, so no status lists the storage.
    fn retire_stale_locations(&mut self, name: &str) -> Result<()> {
        let names = self.drain_resolver();
        let configured: BTreeSet<String> = self
            .config
            .storages
            .iter()
            .map(|s| s.name().to_string())
            .collect();
        let view = self.view()?;
        let mut any = false;
        for ((folder, chunk), r) in &view.chunks {
            if folder.as_str().is_empty() {
                continue;
            }
            for (n, l) in &r.storages {
                let who = if l.claimed_by.is_empty() {
                    &l.verified_by
                } else {
                    &l.claimed_by
                };
                if names.resolve_any(n, who, &configured).as_deref() == Some(name) {
                    self.pending.push(Event::ChunkDropped {
                        folder: folder.clone(),
                        chunk: chunk.clone(),
                        object: r.object.clone(),
                        storage: n.clone(),
                    });
                    any = true;
                }
            }
        }
        if any {
            self.commit_batch()?;
        }
        Ok(())
    }

    /// Make sure every record, ledger batch, manifest and thumbnail on
    /// `spec` is on every other storage that holds records. Returns how
    /// many objects were copied.
    fn drain_records(&self, spec: &StorageSpec) -> Result<u64> {
        if spec.is_data_only() {
            return Ok(0);
        }
        let name = spec.name();
        let closed = self.closed_storages();
        let mut others: Vec<(String, Box<dyn Storage>)> = Vec::new();
        for s in &self.config.storages {
            if s.name() == name || s.is_data_only() || s.is_carrier() || closed.contains(s.name()) {
                continue;
            }
            match self.open_spec(s) {
                Ok(b) => others.push((s.name().to_string(), b)),
                Err(e) => bail!(
                    "{} must be reachable to take the records of {name}: {e:#}",
                    s.name()
                ),
            }
        }
        if others.is_empty() {
            bail!("{name} is the only storage that holds the vault's records and ledger: add another storage (not a disk pool) first");
        }
        let source = self.open_spec(spec)?;
        let task = activity::start(activity::DRAIN, name, 0, activity::Unit::Items);
        task.set_phase("records");
        let keys: Vec<String> = source
            .list("")?
            .into_iter()
            .filter(|k| {
                !k.starts_with("chunks/")
                    && !k.starts_with(crate::packs::PREFIX)
                    && k != "vault/storage-id.json"
            })
            .collect();
        task.set_total(keys.len() as u64);
        let prefixes: BTreeSet<String> = keys
            .iter()
            .map(|k| match k.split_once('/') {
                Some((top, _)) => format!("{top}/"),
                None => k.clone(),
            })
            .collect();
        let mut theirs: Vec<HashSet<String>> = Vec::new();
        for (_, b) in &others {
            let mut set = HashSet::new();
            for p in &prefixes {
                set.extend(b.list(p)?);
            }
            theirs.push(set);
        }
        let mut copied = 0u64;
        let mut unreadable = 0u64;
        for key in &keys {
            task.advance(1);
            let missing: Vec<usize> = (0..others.len())
                .filter(|i| !theirs[*i].contains(key))
                .collect();
            if missing.is_empty() {
                continue;
            }
            let Ok(Some(bytes)) = source.get(key) else {
                unreadable += 1;
                continue;
            };
            for i in missing {
                others[i].1.put_if_absent(key, &bytes)?;
                copied += 1;
            }
        }
        if unreadable > 0 {
            bail!(
                "{unreadable} record{} could be read only from {name}{}: it is not drained yet",
                if unreadable == 1 { "" } else { "s" },
                if spec.is_cold() {
                    " (cold storage: restore them first)"
                } else {
                    ""
                }
            );
        }
        Ok(copied)
    }

    fn run_summary(r: &DrainRunReport) -> String {
        let mut s = format!(
            "{}: {} block{} moved off ({}), {} copied first ({})",
            r.storage,
            r.blocks_dropped,
            if r.blocks_dropped == 1 { "" } else { "s" },
            fmt_size(r.bytes_dropped),
            r.blocks_copied,
            fmt_size(r.bytes_copied)
        );
        if r.blocks_left_for_later > 0 {
            s += &format!(", {} left for later runs", r.blocks_left_for_later);
        }
        if r.blocks_kept > 0 {
            s += &format!(
                "; {} block{} stay: {}",
                r.blocks_kept,
                if r.blocks_kept == 1 { "" } else { "s" },
                r.kept.join("; ")
            );
        } else if !r.kept.is_empty() {
            s += &format!("; {}", r.kept.join("; "));
        }
        if r.drained {
            s += &format!(
                "; drained: it holds nothing Varsto needs ({} records copied to the other storages)",
                r.records_copied
            );
        }
        if r.removed {
            s += "; removed from this device";
        }
        s
    }

    // ----- status -------------------------------------------------------------------

    /// Every storage being drained or drained, with its progress.
    pub fn drain_statuses(&self) -> Result<Vec<DrainStatus>> {
        let states = self.drain_states();
        let mut out = Vec::new();
        let now = util::now_utc();
        for spec in &self.config.storages {
            let Some(d) = self.storage_settings(spec.name()).drain else {
                continue;
            };
            let (blocks_left, bytes_left) = self.claimed_bytes_on(spec.name())?;
            let st = states.get(spec.name());
            let here = d.driver == self.vault.device_id;
            let start = st.map(|s| s.bytes_at_start).filter(|b| *b > 0);
            let percent = match (bytes_left, start) {
                (0, _) => 100,
                (left, Some(s)) if s > left => ((s - left) as f64 / s as f64 * 100.0) as u32,
                _ => 0,
            };
            let blocked = st.map(|s| s.blocked.clone()).unwrap_or_default();
            let phase = match d.phase {
                DrainPhase::Drained => "drained",
                DrainPhase::Draining if st.is_some_and(|s| s.stalled) => "blocked",
                DrainPhase::Draining => "draining",
            };
            // Finish: at the daily budget, or at the pace so far.
            let eta = (bytes_left > 0)
                .then(|| {
                    let pace = st.and_then(|s| {
                        let secs = (now - s.started_utc).max(1);
                        (s.bytes_moved > 0).then(|| s.bytes_moved as f64 / secs as f64)
                    });
                    let budget = d.budget_bytes_per_day.map(|b| b as f64 / 86_400.0);
                    let rate = match (pace, budget) {
                        (Some(p), Some(b)) => Some(p.min(b)),
                        (p, b) => p.or(b),
                    };
                    rate.filter(|r| *r > 0.0)
                        .map(|r| now + (bytes_left as f64 / r) as i64)
                })
                .flatten();
            let driver = self
                .devices
                .devices
                .get(&d.driver)
                .map(|r| r.name.clone())
                .unwrap_or_else(|| d.driver.short().to_string());
            let mut summary = match phase {
                "drained" => format!("{} is drained: it holds nothing Varsto needs", spec.name()),
                _ => format!(
                    "{} is being drained by {}: {} block{} ({}) left, {percent} % done",
                    spec.name(),
                    if here {
                        "this device".to_string()
                    } else {
                        driver.clone()
                    },
                    blocks_left,
                    if blocks_left == 1 { "" } else { "s" },
                    fmt_size(bytes_left)
                ),
            };
            if !blocked.is_empty() && phase != "drained" {
                summary += &format!("; waiting: {}", blocked.join("; "));
            }
            out.push(DrainStatus {
                storage: spec.name().to_string(),
                phase: phase.to_string(),
                started_utc: d.started_utc,
                driver,
                driven_here: here,
                remove_when_empty: d.remove_when_empty,
                budget_bytes_per_day: d.budget_bytes_per_day,
                confirm_cold_read: d.confirm_cold_read,
                blocks_left,
                bytes_left,
                bytes_at_start: start,
                percent,
                eta_utc: eta,
                bytes_today: st.map(|s| s.bytes_today).unwrap_or(0),
                last_run_utc: st.and_then(|s| s.last_run_utc),
                blocked,
                last_error: st.and_then(|s| s.last_error.clone()),
                summary,
            });
        }
        Ok(out)
    }
}
