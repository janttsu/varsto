// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Draining a storage: emptying it onto the other storages without ever
//! weakening a folder's copies (`docs/spec/alpha-0-format.md` sections 44
//! and 77.9).
//!
//! Starting a drain publishes it with the storage's shared settings
//! (`quotas`), so no device writes new blocks there any more; the storage
//! stays readable. The device that started it (the driver) then works
//! through the packs the ledger shows held on the storage
//! (`storages3::drain`), in runs (the service runs one after every sync),
//! within a daily budget of bytes copied:
//!
//! 1. Packs whose blocks already have the copies they need elsewhere come
//!    first: they only have to be dropped. Then the others.
//! 2. For each pack, the copies its blocks keep without this storage: the
//!    folder's placement says which storages take the folder's blocks
//!    (storages being drained and storages at their quota excepted), and
//!    the copies dropping this one leaves must still meet the folder's
//!    policy as far as the copies met it before (its minimum count and
//!    per-place minimums, capped at what was there). A block is never left
//!    without a copy. Missing copies are whole copies of the pack onto the
//!    folder's other storages, read back and checked against the pack id
//!    (a cold target is checked by name only).
//! 3. Only then is the pack recorded as dropped (`pack_dropped`, sealed and
//!    pushed) and deleted from the storage. A pack whose blocks' policy
//!    cannot be met elsewhere stays, and the drain reports what is missing.
//! 4. When the storage holds no pack, every record, ledger batch, manifest
//!    and thumbnail there is copied to the other storages that hold
//!    records, and the drain is published as finished ("drained"): no device
//!    writes to the storage or reads records from it any more. With
//!    "remove when empty" the driver then removes it.
//!
//! A run that stops halfway is carried on by the next one: copies already
//! made are found on their storages, drops already recorded are not made
//! twice, and packs recorded as dropped are deleted at the end.
use super::placement::fmt_size;
use super::quotas::QuotaGate;
use super::*;
use crate::advice::{add_cost, Costs};
use crate::storage_settings::{DrainPhase, DrainSetting};

/// Packs per ledger batch: their drops are sealed and pushed before any of
/// them is deleted.
const DRAIN_GROUP: usize = 16;
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

/// A drain worked out from the ledger and the folders' block maps: the
/// pack-level plan (with what the quotas and the cold-read rule leave
/// out marked as blocked) and the report of it.
struct DrainWork {
    packs: crate::storages3::DrainPlan,
    plan: DrainPlan,
}

/// The pack-level drain needs of every folder: (needs, tables).
type DrainInputs = (
    HashMap<crate::ledger3::FolderBin, crate::storages3::DrainNeeds>,
    HashMap<
        crate::ledger3::FolderBin,
        std::sync::Arc<std::sync::RwLock<crate::blockmap::MapTable>>,
    >,
);
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

    /// What every folder's blocks need for a drain of `name` (the storages
    /// the packs may go to, the copy rules, the blocks something still
    /// uses), and the folders' block map tables.
    fn drain_inputs(&self, candidates: &[&StorageSpec], replace: bool) -> Result<DrainInputs> {
        let mut needs = HashMap::new();
        let mut tables = HashMap::new();
        for rec in self.keyring.folders.values() {
            let Ok(folder) = members3::bin(&rec.folder_id) else {
                continue;
            };
            if let Some(t) = self.folder_table(rec)? {
                tables.insert(folder, t);
            }
            let all: Vec<String> = candidates.iter().map(|s| s.name().to_string()).collect();
            if rec.is_removed() {
                // Nothing needs a removed folder's blocks any more.
                needs.insert(
                    folder,
                    crate::storages3::DrainNeeds {
                        name: rec.name.clone(),
                        rules: None,
                        targets: all,
                        referenced: Some(HashSet::new()),
                        replace: false,
                    },
                );
                continue;
            }
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
                targets = all;
            }
            // Warm storages first: a cold one is written, rarely read.
            targets.sort_by_key(|n| {
                candidates
                    .iter()
                    .any(|s| s.name() == n.as_str() && s.is_cold())
            });
            // Blocks of current files, of the trash and of the snapshots
            // this device has seen; a folder never synced here: all count.
            let mut referenced: Option<HashSet<crate::ledger3::ObjectBin>> = None;
            if rec.is_backup() {
                let known = self.backup_blocks_known(&rec.folder_id);
                if !known.is_empty() {
                    referenced = Some(
                        known
                            .into_iter()
                            .filter_map(|(_, o)| crate::storages3::object_bin(&o).ok())
                            .collect(),
                    );
                }
            } else if let Ok(state) = self.load_state(&rec.folder_id) {
                if !state.files.is_empty() {
                    let mut refs: HashSet<crate::ledger3::ObjectBin> = HashSet::new();
                    for f in state.files.values().filter(|f| !f.deleted) {
                        for c in &f.chunks {
                            if let Ok(o) = crate::storages3::object_bin(&c.object) {
                                refs.insert(o);
                            }
                        }
                    }
                    for c in self.trash_chunks(&rec.folder_id) {
                        if let Ok(o) = crate::storages3::object_bin(&c.object) {
                            refs.insert(o);
                        }
                    }
                    referenced = Some(refs);
                }
            }
            needs.insert(
                folder,
                crate::storages3::DrainNeeds {
                    name: rec.name.clone(),
                    rules,
                    targets,
                    referenced,
                    replace,
                },
            );
        }
        Ok((needs, tables))
    }

    /// Work out a drain of `name` from the ledger, taking room on the
    /// receiving storages from `gate`.
    fn drain_work(
        &self,
        name: &str,
        confirm_cold_read: bool,
        replace: bool,
        gate: &QuotaGate,
    ) -> Result<DrainWork> {
        let spec = self
            .config
            .storages
            .iter()
            .find(|s| s.name() == name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown storage {name}"))?;
        let view = self.view3()?;
        let closed = self.closed_storages();
        let candidates: Vec<&StorageSpec> = self
            .config
            .storages
            .iter()
            .filter(|s| s.name() != name && !s.is_carrier() && !closed.contains(s.name()))
            .collect();
        let hot: BTreeSet<&str> = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_cold() && !s.is_carrier() && s.name() != name)
            .map(|s| s.name())
            .collect();
        let place_of = |n: &str| -> String {
            if n.starts_with("replica:") {
                return "replica".to_string();
            }
            self.config
                .storages
                .iter()
                .find(|s| s.name() == n && !s.is_carrier())
                .map(|s| s.place())
                .unwrap_or_else(|| "other".to_string())
        };
        let (needs, tables) = self.drain_inputs(&candidates, replace)?;
        let guards: Vec<(
            crate::ledger3::FolderBin,
            std::sync::RwLockReadGuard<'_, crate::blockmap::MapTable>,
        )> = tables
            .iter()
            .map(|(f, t)| (*f, t.read().unwrap_or_else(|e| e.into_inner())))
            .collect();
        let refs: HashMap<crate::ledger3::FolderBin, &crate::blockmap::MapTable> =
            guards.iter().map(|(f, g)| (*f, &**g)).collect();
        let fallback: Vec<String> = candidates.iter().map(|s| s.name().to_string()).collect();
        let mut packs =
            crate::storages3::drain_plan(&view, name, &refs, &needs, &place_of, &fallback)?;
        let price = self.storage_price(name);
        let now = util::now_utc();
        let mut plan = DrainPlan {
            storage: name.to_string(),
            cold: spec.is_cold(),
            ..Default::default()
        };
        let mut early = Costs::new();
        let mut quota_refused: BTreeSet<String> = BTreeSet::new();
        for item in packs.items.iter_mut() {
            let size = crate::ledger3::events::class_bytes(item.class).unwrap_or(0);
            let blocks = item.needed_blocks;
            plan.blocks += blocks;
            plan.bytes += size;
            let other_hot = view
                .holders(&item.pack)
                .iter()
                .any(|h| *h != name && hot.contains(h));
            if item.shortfall.is_none()
                && !item.copy_to.is_empty()
                && spec.is_cold()
                && !confirm_cold_read
                && !other_hot
            {
                item.shortfall = Some(format!(
                    "the only copy to read is on cold storage {name}: confirm the cold read (retrieval fees and restore delays apply)"
                ));
            }
            if item.shortfall.is_none() {
                // Room on the storages that take a copy (their quotas count
                // size classes).
                let mut taken: Vec<String> = Vec::new();
                for t in &item.copy_to {
                    if gate.take_pack(t, size) {
                        taken.push(t.clone());
                    } else {
                        quota_refused.insert(t.clone());
                        item.shortfall = Some(format!(
                            "a pack of {} needs a copy on {t}, which has no room: {}",
                            item.folder
                                .and_then(|f| needs.get(&f))
                                .map(|n| n.name.as_str())
                                .unwrap_or("the vault"),
                            gate.message(t)
                        ));
                        break;
                    }
                }
                if item.shortfall.is_some() {
                    for t in taken {
                        gate.give_back_pack(&t, size);
                    }
                }
            }
            if let Some(why) = &item.shortfall {
                plan.blocks_blocked += blocks.max(1);
                push_reason(&mut plan.blocked, why.clone());
                continue;
            }
            if item.copy_to.is_empty() {
                plan.blocks_drop_only += blocks;
            } else {
                plan.blocks_to_copy += blocks;
                for t in &item.copy_to {
                    plan.bytes_to_copy += size;
                    *plan.targets.entry(t.clone()).or_default() += size;
                }
                if !other_hot {
                    plan.bytes_read_here += size;
                }
            }
            if let (Some(p), Some(c)) = (
                &price,
                view.copies(&item.pack)
                    .into_iter()
                    .find(|c| c.storage == name),
            ) {
                let days = ((now - c.stored_utc).max(0) / 86_400) as u32;
                if let Some(c) = p.early_deletion_cost(size, days).filter(|c| *c > 0.0) {
                    add_cost(&mut early, &p.currency, c);
                }
            }
        }
        // Drops first (no egress), then the copies; blocked ones last.
        packs
            .items
            .sort_by_key(|i| (i.shortfall.is_some(), !i.copy_to.is_empty(), i.pack));
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
        Ok(DrainWork { packs, plan })
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
        let view = self.view3()?;
        let gate = self.quota_gate(&view);
        let current = self.storage_settings(name).drain;
        let confirm =
            opts.confirm_cold_read || current.as_ref().is_some_and(|d| d.confirm_cold_read);
        let mut plan = self.drain_work(name, confirm, true, &gate)?.plan;
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

    /// Packs some claim still places on `name` (under any device's name
    /// for it: the view is localized).
    fn claims_left_on(&self, name: &str) -> Result<u64> {
        Ok(self.view3()?.packs_on(name).count() as u64)
    }

    /// (blocks, bytes) the ledger places on `name`: the live blocks in the
    /// packs held there, and the size classes of those packs.
    fn claimed_bytes_on(&self, name: &str) -> Result<(u64, u64)> {
        let blocks = self.objects_on_storage(name)?.len() as u64;
        let view = self.view3()?;
        Ok((blocks, crate::storages3::storage_usage(&view, name).bytes))
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
        let view = self.view3()?;
        let gate = self.quota_gate(&view);
        let work = self.drain_work(name, setting.confirm_cold_read, true, &gate)?;
        st.blocked = work.plan.blocked.clone();
        report.blocks_kept += work.plan.blocks_blocked;
        report.kept = work.plan.blocked.clone();
        // What this run takes: drops always, copies within the budget.
        let budget_left = setting
            .budget_bytes_per_day
            .map(|b| b.saturating_sub(st.bytes_today));
        let mut planned_copy = 0u64;
        let mut chosen: Vec<crate::storages3::DrainItem> = Vec::new();
        let ready: Vec<crate::storages3::DrainItem> = work
            .packs
            .items
            .iter()
            .filter(|i| i.shortfall.is_none())
            .cloned()
            .collect();
        let total: u64 = ready.iter().map(|i| i.needed_blocks.max(1)).sum();
        for item in ready {
            if limits.max_items.is_some_and(|m| chosen.len() >= m) {
                break;
            }
            let cost = crate::ledger3::events::class_bytes(item.class).unwrap_or(0)
                * item.copy_to.len() as u64;
            if cost > 0 {
                // The first pack of a day goes even when larger than the budget.
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
        let taken: u64 = chosen.iter().map(|i| i.needed_blocks.max(1)).sum();
        report.blocks_left_for_later = total - taken;
        if !chosen.is_empty() {
            let sub = crate::storages3::DrainPlan {
                storage: name.to_string(),
                items: chosen,
                ..Default::default()
            };
            self.drain_packs(&spec, setting.confirm_cold_read, false, &sub, &mut report)?;
        }
        st.bytes_today += report.bytes_copied;
        st.bytes_moved += report.bytes_dropped;
        // Finished with the blocks: the records follow, then the drain ends.
        let left = self.claims_left_on(name)?;
        if left == 0 {
            if let Some(why) = self.records_blocker(name) {
                push_reason(&mut report.kept, why.clone());
                push_reason(&mut st.blocked, why);
            } else {
                report.objects_deleted += self.delete_leftovers(&spec);
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

    /// Copy whole, check, drop and delete the chosen packs, one batch per
    /// group: the copies and drops are sealed and pushed before anything is
    /// deleted. With `keep_source` (a storage being removed) the packs are
    /// copied and checked but neither dropped nor deleted.
    fn drain_packs(
        &mut self,
        spec: &StorageSpec,
        confirm_cold_read: bool,
        keep_source: bool,
        plan: &crate::storages3::DrainPlan,
        report: &mut DrainRunReport,
    ) -> Result<()> {
        let name = spec.name().to_string();
        let source = self.open_spec(spec)?;
        let source_pool: Option<PoolStorage> = spec
            .is_data_only()
            .then(|| self.open_pool(spec))
            .transpose()?;
        // The storages that take copies, pools as themselves (disk group
        // rules count their places).
        let mut dst_specs: BTreeMap<String, StorageSpec> = BTreeMap::new();
        for i in &plan.items {
            for t in &i.copy_to {
                if let Some(s) = self.config.storages.iter().find(|s| s.name() == t.as_str()) {
                    dst_specs.insert(t.clone(), s.clone());
                }
            }
        }
        let mut pools: BTreeMap<String, PoolStorage> = BTreeMap::new();
        let mut boxes: BTreeMap<String, Box<dyn Storage>> = BTreeMap::new();
        for (t, s) in &dst_specs {
            if s.is_data_only() {
                if let Ok(p) = self.open_pool(s) {
                    pools.insert(t.clone(), p);
                }
            } else {
                match self.open_spec(s) {
                    Ok(b) => {
                        boxes.insert(t.clone(), b);
                    }
                    Err(e) => push_reason(&mut report.kept, format!("{t} cannot be opened: {e:#}")),
                }
            }
        }
        let readers: Vec<(String, Box<dyn Storage>)> = self
            .config
            .storages
            .iter()
            .filter(|s| s.name() != name && !s.is_carrier() && !s.is_cold())
            .filter_map(|s| self.open_spec(s).ok().map(|b| (s.name().to_string(), b)))
            .collect();
        let task = activity::start(
            activity::DRAIN,
            &name,
            plan.items
                .iter()
                .map(|i| crate::ledger3::events::class_bytes(i.class).unwrap_or(0))
                .sum(),
            activity::Unit::Bytes,
        );
        task.set_phase("copy");
        let opts = crate::storages3::MoveOptions {
            keep_source,
            ..Default::default()
        };
        let read_source = !spec.is_cold() || confirm_cold_read;
        for group in plan.items.chunks(DRAIN_GROUP) {
            let view = self.view3()?;
            let sub = crate::storages3::DrainPlan {
                storage: name.clone(),
                items: group.to_vec(),
                ..Default::default()
            };
            let run = {
                let pack_source = |p: &crate::ledger3::PackId| -> Option<Vec<u8>> {
                    let key = crate::packs::pack_key(&hex::encode(p));
                    if let Some(b) = self.mailbox_object(&key) {
                        return Some(b);
                    }
                    let holders = view.holders(p);
                    for (n, b) in &readers {
                        if holders.contains(&n.as_str()) {
                            if let Ok(Some(bytes)) = b.get_bounded(&key, crate::storage::MAX_PACK) {
                                if crypto::hash(&bytes) == *p {
                                    return Some(bytes);
                                }
                            }
                        }
                    }
                    None
                };
                let sources = crate::storages3::Sources {
                    pack: &pack_source,
                    member: &|_| None,
                    read_source,
                };
                let src = crate::storages3::Endpoint {
                    name: &name,
                    storage: source.as_ref(),
                    cold: spec.is_cold(),
                    pool: source_pool.as_ref(),
                };
                let dsts: Vec<crate::storages3::Endpoint> = dst_specs
                    .iter()
                    .filter_map(|(t, s)| {
                        let storage: &dyn Storage = match pools.get(t) {
                            Some(p) => p,
                            None => boxes.get(t)?.as_ref(),
                        };
                        Some(crate::storages3::Endpoint {
                            name: t,
                            storage,
                            cold: s.is_cold(),
                            pool: pools.get(t),
                        })
                    })
                    .collect();
                crate::storages3::run_drain_with(&view, &sub, &src, &dsts, &sources, &opts)
            };
            let r = &run.report;
            let blocks_of = |p: &crate::ledger3::PackId| {
                group
                    .iter()
                    .find(|i| i.pack == *p)
                    .map(|i| {
                        (
                            i.needed_blocks,
                            crate::ledger3::events::class_bytes(i.class).unwrap_or(0),
                        )
                    })
                    .unwrap_or((0, 0))
            };
            for i in group {
                task.advance(crate::ledger3::events::class_bytes(i.class).unwrap_or(0));
            }
            for p in &r.copied_packs {
                report.blocks_copied += blocks_of(p).0;
                report.copies_verified += 1;
            }
            report.bytes_copied += r.bytes_written;
            for p in &r.dropped_packs {
                let (n, bytes) = blocks_of(p);
                report.blocks_dropped += n;
                report.bytes_dropped += bytes;
            }
            for p in r
                .corrupt
                .iter()
                .chain(&r.waiting_room)
                .chain(&r.waiting_place)
            {
                report.blocks_kept += blocks_of(p).0;
            }
            if !r.corrupt.is_empty() {
                push_reason(
                    &mut report.kept,
                    format!("a pack on {name} is damaged: the repair fixes it first"),
                );
            }
            if !r.waiting_room.is_empty() {
                push_reason(
                    &mut report.kept,
                    "a storage that takes copies has no room for a pack now".to_string(),
                );
            }
            if !r.waiting_place.is_empty() {
                push_reason(
                    &mut report.kept,
                    "a pool's disk group rule needs a copy on a disk kept in another place"
                        .to_string(),
                );
            }
            for (p, why) in &r.unavailable {
                report.blocks_kept += blocks_of(p).0;
                push_reason(&mut report.kept, why.clone());
            }
            let events = run.events.clone();
            self.f3.pending.extend(events);
            self.commit_now()?;
            let (deleted, failed) = run.delete_dropped_each(source.as_ref());
            report.objects_deleted += deleted;
            for (_, e) in failed {
                push_reason(
                    &mut report.kept,
                    format!("a pack recorded as dropped could not be deleted from {name} ({e}); the next run tries again"),
                );
            }
        }
        drop(boxes);
        for (t, p) in pools {
            let disks = p.disks();
            drop(p);
            self.save_pool_disks(&t, disks)?;
        }
        Ok(())
    }

    /// The packs of a storage to be removed, worked out as a drain would
    /// (a removal reads the storage itself, cold or not).
    pub(super) fn drain_work_for_removal(
        &self,
        name: &str,
        gate: &QuotaGate,
    ) -> Result<crate::storages3::DrainPlan> {
        Ok(self.drain_work(name, true, false, gate)?.packs)
    }

    /// Copy the packs whose blocks need a copy elsewhere off a storage that
    /// is being removed, whole and checked, without dropping anything from
    /// it (it is retired afterwards). Returns (blocks, bytes) copied.
    pub(super) fn copy_off_for_removal(&mut self, name: &str) -> Result<(u64, u64)> {
        let spec = self
            .config
            .storages
            .iter()
            .find(|s| s.name() == name)
            .cloned()
            .ok_or_else(|| anyhow!("unknown storage {name}"))?;
        let view = self.view3()?;
        let gate = self.quota_gate(&view);
        let mut work = self.drain_work_for_removal(name, &gate)?;
        work.items
            .retain(|i| i.shortfall.is_none() && !i.copy_to.is_empty());
        let mut report = DrainRunReport::default();
        let task = activity::start(
            activity::STORAGE_REMOVAL,
            name,
            work.items.len() as u64,
            activity::Unit::Items,
        );
        task.set_phase("copy");
        self.drain_packs(&spec, true, true, &work, &mut report)?;
        Ok((report.blocks_copied, report.bytes_copied))
    }

    /// Delete the packs still on a storage that the ledger shows dropped
    /// from it (drops recorded by a run that stopped before deleting).
    fn delete_leftovers(&self, spec: &StorageSpec) -> u64 {
        let (Ok(source), Ok(view)) = (self.open_spec(spec), self.view3()) else {
            return 0;
        };
        let Ok(left) = crate::storages3::leftovers(&view, spec.name(), source.as_ref()) else {
            return 0;
        };
        let mut n = 0;
        for p in left {
            if source
                .delete(&crate::packs::pack_key(&hex::encode(p)))
                .is_ok()
            {
                n += 1;
            }
        }
        n
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
