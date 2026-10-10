// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Data placement: which storages a folder is written to, and moving blocks
//! from one storage to another (`docs/spec/alpha-0-format.md` section 23).
//!
//! A folder's placement (`crate::placement`) limits the storages a push
//! writes its blocks to; it is published like the folder's policy, so every
//! device writes the folder the same way. A move copies a block to the new
//! storage, records the copy, checks it, records the block as dropped from
//! the old storage (`Event::ChunkDropped`, sealed and pushed before anything
//! is deleted) and then deletes it there. It never drops a copy the
//! folder's copy rules still need, never the last one, and a block dropped
//! from a storage is not written back there by later pushes while another
//! copy exists. A move that stops halfway is carried on by running it again:
//! blocks already on the new storage are not copied twice, and blocks
//! recorded as dropped that are still on the old storage are deleted.

use super::placement::{fmt_size, is_idle};
use super::verify::storage_identity;
use super::*;
use crate::advice::{add_cost, Costs};
use crate::ledger::ChunkRecord;
use crate::placement::{MoveReport, MoveRequest, Placement, PlacementInfo, PlacementRecord};
use crate::policy::{ChunkFacts, PolicyState};

/// Blocks moved per ledger batch: their drops are sealed and pushed before
/// any of them is deleted from the old storage.
const MOVE_GROUP: usize = 64;
/// How many kept blocks a report lists by name.
const KEPT_EXAMPLES: usize = 10;

/// The storages a folder's blocks go to on this device.
pub(super) struct WriteTargets {
    /// `None`: every storage (no placement, or none of its storages here).
    names: Option<BTreeSet<String>>,
    carriers: BTreeSet<String>,
}

impl WriteTargets {
    /// Whether a push writes a block with ledger record `record` to the
    /// storage `name`. Transferrers follow their own rules. A block that was
    /// moved away from a storage is not put back while another copy exists.
    pub(super) fn wants(&self, name: &str, record: Option<&ChunkRecord>) -> bool {
        if self.carriers.contains(name) {
            return true;
        }
        if self.names.as_ref().is_some_and(|n| !n.contains(name)) {
            return false;
        }
        match record {
            Some(r) if r.dropped_from(name) => !r
                .storages
                .iter()
                .any(|(n, l)| n != name && !l.claimed_by.is_empty() && !self.carriers.contains(n)),
            _ => true,
        }
    }
}

/// One block to move.
struct MoveItem {
    chunk: ChunkId,
    object: ObjectName,
    epoch: u32,
    size: u64,
    /// Already claimed on the new storage.
    on_to: bool,
    /// Files of this folder on this device that contain the block.
    files: Vec<PathBuf>,
}

/// A move worked out from the ledger, before anything is changed.
struct MovePlan {
    items: Vec<MoveItem>,
    /// Blocks recorded as dropped from `from` (an earlier run): their
    /// objects may still be there.
    dropped: Vec<ObjectName>,
    report: MoveReport,
}

/// Count a block that stays where it is, naming a few.
fn keep(report: &mut MoveReport, object: &ObjectName, why: String) {
    report.blocks_kept += 1;
    if report.kept.len() < KEPT_EXAMPLES {
        report.kept.push((object.short().to_string(), why));
    }
}

fn fmt_costs(c: &Costs) -> String {
    c.iter()
        .map(|(cur, v)| format!("{v:.2} {cur}"))
        .collect::<Vec<_>>()
        .join(" + ")
}

impl Engine {
    // ----- placement ---------------------------------------------------------

    /// The storages `rec`'s blocks are written to on this device.
    pub(super) fn write_targets(&self, rec: &FolderRecord) -> WriteTargets {
        let carriers: BTreeSet<String> = self
            .config
            .storages
            .iter()
            .filter(|s| s.is_carrier())
            .map(|s| s.name().to_string())
            .collect();
        let names = rec
            .placement
            .as_ref()
            .filter(|p| !p.is_everywhere())
            .map(|p| self.placement_names(p))
            .filter(|n| !n.is_empty());
        WriteTargets { names, carriers }
    }

    /// Local names of the storages a placement takes (transferrers aside).
    fn placement_names(&self, p: &Placement) -> BTreeSet<String> {
        let local: Vec<&str> = self.config.storages.iter().map(|s| s.name()).collect();
        let identities = p.needs_identities(&local);
        self.config
            .storages
            .iter()
            .filter(|s| !s.is_carrier())
            .filter(|s| {
                let id = (identities && !s.is_data_only())
                    .then(|| self.open_spec(s).ok())
                    .flatten()
                    .and_then(|b| storage_identity(b.as_ref()).ok());
                p.includes(s.name(), &s.place(), id.as_deref())
            })
            .map(|s| s.name().to_string())
            .collect()
    }

    /// A folder's placement and what it means on this device.
    pub fn placement(&self, folder: &str) -> Result<PlacementInfo> {
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let targets = self.write_targets(&rec);
        let mut warnings = Vec::new();
        let names: Vec<String> = match &targets.names {
            Some(n) => n.iter().cloned().collect(),
            None => {
                if rec.placement.as_ref().is_some_and(|p| !p.is_everywhere()) {
                    warnings.push("none of the storages or places it names is configured on this device, so this device writes the folder to every storage".to_string());
                }
                self.config
                    .storages
                    .iter()
                    .filter(|s| !s.is_carrier())
                    .map(|s| s.name().to_string())
                    .collect()
            }
        };
        Ok(PlacementInfo {
            folder: rec.name.clone(),
            description: rec
                .placement
                .as_ref()
                .map(|p| p.describe())
                .unwrap_or_else(|| "every storage".to_string()),
            placement: rec.placement.clone(),
            targets: names,
            updated_utc: rec.placement_updated_utc,
            warnings,
        })
    }

    /// Set (or with `None` clear) a folder's placement and publish it so
    /// every device writes the folder the same way. Blocks already stored
    /// stay where they are; `move_data` moves them.
    pub fn set_placement(
        &mut self,
        folder: &str,
        placement: Option<Placement>,
    ) -> Result<PlacementInfo> {
        if self.vault.member {
            bail!("a member device cannot change where the owner's folders are stored");
        }
        self.org_allows(
            |p| p.members_may_set_policies,
            "change where folders are stored",
        )?;
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let placement = match placement.filter(|p| !p.is_everywhere()) {
            None => None,
            Some(mut p) => {
                p.validate()?;
                for name in &p.storages {
                    let Some(spec) = self.config.storages.iter().find(|s| s.name() == name) else {
                        bail!("unknown storage {name}");
                    };
                    if spec.is_carrier() {
                        bail!("{name} is a transferrer: it carries blocks between devices and cannot be a folder's storage");
                    }
                }
                for place in &p.places {
                    if !self
                        .config
                        .storages
                        .iter()
                        .any(|s| !s.is_carrier() && &s.place() == place)
                    {
                        bail!("no storage of this device is in place {place}");
                    }
                }
                // Identities let devices that name the storages differently match them.
                p.storage_ids.clear();
                for name in p.storages.clone() {
                    let spec = self
                        .config
                        .storages
                        .iter()
                        .find(|s| s.name() == name)
                        .cloned()
                        .expect("checked above");
                    if spec.is_data_only() {
                        continue;
                    }
                    if let Some(id) = self
                        .open_spec(&spec)
                        .ok()
                        .and_then(|b| storage_identity(b.as_ref()).ok())
                    {
                        p.storage_ids.insert(name, id);
                    }
                }
                Some(p)
            }
        };
        let now = util::now_utc();
        let f = self
            .keyring
            .folders
            .get_mut(&rec.folder_id)
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        // Strictly newer than what is known, so other devices adopt it.
        let now = now.max(f.placement_updated_utc + 1);
        f.placement = placement.clone();
        f.placement_updated_utc = now;
        self.keyring.save(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )?;
        let prec = PlacementRecord {
            folder_id: rec.folder_id.clone(),
            device: self.vault.device_id.clone(),
            updated_utc: now,
            placement,
        };
        let blob = prec.seal(&self.vault.vault_id, &self.folder_record_key_now())?;
        for (_, backend) in self.metadata_storages(true)? {
            backend.put_if_absent(&prec.storage_key(), &blob)?;
        }
        self.placement(folder)
    }

    /// Adopt the newest placement record of every folder (as for policies).
    /// Returns whether a folder record changed.
    pub(super) fn pull_placement_records(&mut self) -> Result<bool> {
        if self.vault.member {
            return Ok(false);
        }
        let fr_keys = self.folder_record_keys();
        let mut changed = false;
        for (_, backend) in self.metadata_storages(false)? {
            for key in backend.list(PlacementRecord::PREFIX)? {
                let Some(fid) = key
                    .strip_prefix(PlacementRecord::PREFIX)
                    .and_then(|r| r.split('/').next())
                    .and_then(|f| FolderId::from_hex(f).ok())
                else {
                    continue;
                };
                let Some(local) = self.keyring.folders.get(&fid) else {
                    continue;
                };
                // The object name ends with the update time: skip anything not newer.
                let stamp: i64 = key
                    .rsplit('/')
                    .next()
                    .and_then(|n| n.strip_suffix(".enc"))
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0);
                if stamp <= local.placement_updated_utc {
                    continue;
                }
                let Some(blob) = backend.get(&key)? else {
                    continue;
                };
                let Some(rec) = fr_keys
                    .iter()
                    .find_map(|k| PlacementRecord::open(&blob, &self.vault.vault_id, &fid, k).ok())
                else {
                    continue;
                };
                if !self.org_accepts_policy_from(&rec.device) {
                    continue;
                }
                if let Some(f) = self.keyring.folders.get_mut(&fid) {
                    if rec.updated_utc > f.placement_updated_utc {
                        f.placement = rec.placement;
                        f.placement_updated_utc = rec.updated_utc;
                        changed = true;
                    }
                }
            }
        }
        Ok(changed)
    }

    // ----- moving data ---------------------------------------------------------

    /// Move a folder's blocks (with `idle_days`, those of its idle files)
    /// from one storage to another: copy, record, check, record the drop,
    /// delete. With `dry_run`, only report what would happen and what it
    /// costs. Moving a whole folder also changes its placement, so new
    /// blocks go to the new storage.
    pub fn move_data(&mut self, req: &MoveRequest) -> Result<MoveReport> {
        self.ensure_active()?;
        if self.vault.member {
            bail!("a member device cannot move the owner's data");
        }
        if self.forked_self {
            bail!("this device's ledger is forked; it must be re-enrolled as a new device");
        }
        let (rec, _) = self.resolve_folder(&req.folder)?;
        if !req.dry_run {
            // Decide from the newest claims and drops.
            self.pull_ledger_once()?;
        }
        // Moving a whole folder: new blocks go to the new storage too.
        let new_placement = req
            .idle_days
            .is_none()
            .then(|| self.placement_without(&rec, &req.from, &req.to))
            .flatten();
        let mut plan = self.plan_move(&rec, req)?;
        if req.dry_run {
            plan.report.placement_changed = new_placement.map(|p| p.describe());
            plan.report.summary = Self::move_summary(&plan.report, &rec.name);
            return Ok(plan.report);
        }
        let mut report = self.run_move(&rec, req, plan)?;
        // Only once every block has left: a move that kept some is run again.
        if let Some(p) = new_placement.filter(|_| report.blocks_kept == 0) {
            report.placement_changed = Some(p.describe());
            self.set_placement(rec.folder_id.as_str(), Some(p))?;
            report.summary = Self::move_summary(&report, &rec.name);
        }
        Ok(report)
    }

    /// The folder's placement with `from` replaced by `to`, if that changes it.
    fn placement_without(&self, rec: &FolderRecord, from: &str, to: &str) -> Option<Placement> {
        let mut names: BTreeSet<String> = match self.write_targets(rec).names {
            Some(n) => n,
            None => self
                .config
                .storages
                .iter()
                .filter(|s| !s.is_carrier())
                .map(|s| s.name().to_string())
                .collect(),
        };
        (names.remove(from) | names.insert(to.to_string())).then(|| Placement {
            storages: names.into_iter().collect(),
            ..Default::default()
        })
    }

    /// Work out a move from the ledger without changing anything.
    fn plan_move(&self, rec: &FolderRecord, req: &MoveRequest) -> Result<MovePlan> {
        let find = |name: &str| {
            self.config
                .storages
                .iter()
                .find(|s| s.name() == name)
                .cloned()
                .ok_or_else(|| anyhow!("unknown storage {name}"))
        };
        let (from, to) = (find(&req.from)?, find(&req.to)?);
        if from.name() == to.name() {
            bail!("the storages to move from and to are the same");
        }
        if from.is_carrier() || to.is_carrier() {
            bail!("transferrers carry blocks between devices; data is not moved to or from them");
        }
        let state = self.load_state(&rec.folder_id)?;
        let root = self
            .config
            .folders
            .iter()
            .find(|m| m.folder_id == rec.folder_id)
            .map(|m| m.path.clone());
        let now = util::now_utc();
        let idle: Option<HashSet<String>> = match req.idle_days {
            Some(days) => Some(
                self.list_files(rec.folder_id.as_str())?
                    .iter()
                    .filter(|e| is_idle(e, days, now))
                    .map(|e| e.path.clone())
                    .collect(),
            ),
            None => None,
        };
        // Blocks of the files that move, without those other files still use.
        let mut moving: BTreeMap<ChunkId, (ChunkRef, Vec<PathBuf>)> = BTreeMap::new();
        let mut staying: HashSet<ChunkId> = HashSet::new();
        let mut files = 0u64;
        let encrypted_here = self.mount_is_encrypted(&rec.folder_id);
        for f in state.files.values().filter(|f| !f.deleted) {
            let moves = idle.as_ref().is_none_or(|s| s.contains(&f.path));
            if !moves {
                staying.extend(f.chunks.iter().map(|c| c.chunk.clone()));
                continue;
            }
            files += 1;
            let local = match &root {
                Some(r) if !encrypted_here && state.local_index.contains_key(&f.path) => {
                    Some(r.join(&f.path))
                }
                _ => None,
            };
            for c in &f.chunks {
                let e = moving
                    .entry(c.chunk.clone())
                    .or_insert_with(|| (c.clone(), Vec::new()));
                e.1.extend(local.clone());
            }
        }
        moving.retain(|c, _| !staying.contains(c));

        let view = self.view()?;
        let carriers: BTreeSet<String> = self
            .config
            .storages
            .iter()
            .filter(|s| s.is_carrier())
            .map(|s| s.name().to_string())
            .collect();
        let place_of = |name: &str| -> String {
            if name.starts_with("replica:") {
                return "replica".to_string();
            }
            self.config
                .storages
                .iter()
                .find(|s| s.name() == name)
                .map(|s| s.place())
                .unwrap_or_else(|| "other".to_string())
        };
        let hot: BTreeSet<String> = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_cold() && !s.is_carrier())
            .map(|s| s.name().to_string())
            .collect();
        let copy_rules = rec
            .policy
            .as_ref()
            .filter(|p| p.min_copies > 0 || !p.min_per_place.is_empty())
            .map(|p| Policy {
                verified_within_days: None,
                ..p.clone()
            });
        let mut report = MoveReport {
            folder: rec.name.clone(),
            from: from.name().to_string(),
            to: to.name().to_string(),
            dry_run: req.dry_run,
            files,
            ..Default::default()
        };
        let mut items = Vec::new();
        let mut dropped = Vec::new();
        let mut remaining: BTreeSet<String> = BTreeSet::new();
        let (mut new_on_to, mut read_from) = (0u64, 0u64);
        let price_from = self.storage_price(from.name());
        let price_to = self.storage_price(to.name());
        let mut early = Costs::new();
        for (chunk, (cref, paths)) in moving {
            let Some(r) = view
                .locate(&rec.folder_id, &chunk)
                .filter(|r| r.object == cref.object)
            else {
                continue;
            };
            let claimed = |n: &str| r.storages.get(n).is_some_and(|l| !l.claimed_by.is_empty());
            if !claimed(from.name()) {
                if r.dropped_from(from.name()) {
                    report.already_moved += 1;
                    dropped.push(r.object.clone());
                }
                continue;
            }
            let on_to = claimed(to.name());
            // The copies left once this one is gone.
            let after: Vec<(String, String, bool, i64)> = r
                .storages
                .iter()
                .filter(|(n, l)| {
                    !l.claimed_by.is_empty() && *n != from.name() && !carriers.contains(*n)
                })
                .map(|(n, _)| (n.clone(), place_of(n), false, 0))
                .chain((!on_to).then(|| (to.name().to_string(), to.place(), false, 0)))
                .collect();
            let mut reason = None;
            if let Some(rules) = &copy_rules {
                let verdict = crate::policy::evaluate(
                    &rec.name,
                    rules,
                    &[ChunkFacts {
                        copies: after.clone(),
                    }],
                    &BTreeMap::new(),
                    &[],
                    now,
                );
                if verdict.state == PolicyState::Violated {
                    reason = Some(format!(
                        "the folder's policy ({}) needs the copy on {}",
                        rules.describe(),
                        from.name()
                    ));
                }
            }
            let other_hot = r
                .storages
                .iter()
                .any(|(n, l)| !l.claimed_by.is_empty() && n != from.name() && hot.contains(n));
            if reason.is_none()
                && !on_to
                && from.is_cold()
                && !req.confirm_cold_read
                && !other_hot
                && paths.is_empty()
            {
                reason = Some(format!(
                    "the only copy to read is on cold storage {}: confirm the cold read to move it",
                    from.name()
                ));
            }
            if let Some(why) = reason {
                keep(&mut report, &r.object, why);
                continue;
            }
            report.blocks += 1;
            report.bytes += r.size;
            remaining.extend(after.iter().map(|(n, _, _, _)| n.clone()));
            let n = after.len() as u64;
            if report.blocks == 1 || n < report.min_copies_after {
                report.min_copies_after = n;
            }
            if !on_to {
                new_on_to += r.size;
                if paths.is_empty() && !other_hot {
                    read_from += r.size;
                }
            }
            if let (Some(p), Some(loc)) = (&price_from, r.storages.get(from.name())) {
                let days = ((now - loc.claimed_utc).max(0) / 86_400) as u32;
                if let Some(c) = p.early_deletion_cost(r.size, days).filter(|c| *c > 0.0) {
                    add_cost(&mut early, &p.currency, c);
                }
            }
            items.push(MoveItem {
                chunk,
                object: r.object.clone(),
                epoch: cref.epoch,
                size: r.size,
                on_to,
                files: paths,
            });
        }
        // Costs from the price model.
        match price_from
            .as_ref()
            .and_then(|p| Some((p.monthly_cost(report.bytes)?, p)))
        {
            Some((c, p)) => add_cost(&mut report.monthly_cost_from, &p.currency, c),
            None => report.unpriced.push(from.name().to_string()),
        }
        match price_to
            .as_ref()
            .and_then(|p| Some((p.monthly_cost(new_on_to)?, p)))
        {
            Some((c, p)) => add_cost(&mut report.monthly_cost_to, &p.currency, c),
            None => report.unpriced.push(to.name().to_string()),
        }
        let mut saving = report.monthly_cost_from.clone();
        for (cur, v) in &report.monthly_cost_to {
            *saving.entry(cur.clone()).or_default() -= v;
        }
        report.monthly_saving = saving;
        if let Some(p) = &price_from {
            if let Some(c) = p.read_cost(read_from).filter(|c| *c > 0.0) {
                add_cost(&mut report.one_time_cost, &p.currency, c);
            }
        }
        report.early_deletion_cost = early;
        report.remaining_on = remaining.into_iter().collect();
        if to.is_cold() {
            let mut note = format!(
                "{} is cold storage: blocks kept only there are not read without your confirmation; to read those files on a device that does not have them, move them back first (varsto move {} --from {} --to <storage> --confirm-cold-read)",
                to.name(),
                rec.name,
                to.name()
            );
            if let Some(c) = price_to.as_ref().and_then(|p| p.read_cost(report.bytes)) {
                note += &format!(
                    "; reading all of it back costs about {c:.2} {}",
                    price_to.as_ref().map(|p| p.currency.as_str()).unwrap_or("")
                );
            }
            if let Some(d) = price_to.as_ref().and_then(|p| p.minimum_storage_days) {
                note += &format!("; it bills every block for at least {d} days");
            }
            report.cold_notes.push(note);
            if !req.confirm_cold_read {
                report.cold_notes.push(format!(
                    "the copies on {} are checked by name only, without reading them back (a confirmed cold read checks their content)",
                    to.name()
                ));
            }
        }
        if from.is_cold() {
            report.cold_notes.push(format!(
                "{} is cold storage: blocks are read from it only with a confirmed cold read, and from other storages or this device otherwise",
                from.name()
            ));
        }
        Ok(MovePlan {
            items,
            dropped,
            report,
        })
    }

    fn move_summary(r: &MoveReport, folder: &str) -> String {
        let mut s = format!(
            "{} {} block{} ({}) of folder {} from {} to {}",
            if r.dry_run { "Would move" } else { "Moved" },
            if r.dry_run {
                r.blocks
            } else {
                r.blocks_dropped
            },
            if r.blocks == 1 { "" } else { "s" },
            fmt_size(if r.dry_run { r.bytes } else { r.bytes_dropped }),
            folder,
            r.from,
            r.to
        );
        if !r.monthly_saving.is_empty() && r.unpriced.is_empty() {
            s += &format!(
                ": the storage bill changes by {} a month",
                r.monthly_saving
                    .iter()
                    .map(|(cur, v)| format!("{:+.2} {cur}", -v))
                    .collect::<Vec<_>>()
                    .join(" + ")
            );
        } else if !r.unpriced.is_empty() {
            s += &format!(" (no price known for {})", r.unpriced.join(", "));
        }
        s += ".";
        if !r.remaining_on.is_empty() {
            s += &format!(
                " Afterwards every block has at least {} cop{}, on {}.",
                r.min_copies_after,
                if r.min_copies_after == 1 { "y" } else { "ies" },
                r.remaining_on.join(", ")
            );
        }
        if !r.one_time_cost.is_empty() {
            s += &format!(
                " Reading the blocks not on this device from {} costs about {} once.",
                r.from,
                fmt_costs(&r.one_time_cost)
            );
        }
        if !r.early_deletion_cost.is_empty() {
            s += &format!(
                " {} still bills about {} for its minimum storage duration.",
                r.from,
                fmt_costs(&r.early_deletion_cost)
            );
        }
        if r.blocks_kept > 0 {
            s += &format!(
                " {} block{} stay on {}: {}.",
                r.blocks_kept,
                if r.blocks_kept == 1 { "" } else { "s" },
                r.from,
                r.kept.first().map(|(_, w)| w.as_str()).unwrap_or("")
            );
        }
        if r.already_moved > 0 {
            s += &format!(" {} were moved before.", r.already_moved);
        }
        if let Some(p) = &r.placement_changed {
            s += &format!(" New blocks of the folder go to {p}.");
        }
        for n in &r.cold_notes {
            s += &format!(" Note: {n}.");
        }
        s
    }

    /// Carry out a planned move, one group of blocks per ledger batch.
    fn run_move(
        &mut self,
        rec: &FolderRecord,
        req: &MoveRequest,
        plan: MovePlan,
    ) -> Result<MoveReport> {
        let MovePlan {
            items,
            dropped,
            mut report,
        } = plan;
        let find = |name: &str| {
            self.config
                .storages
                .iter()
                .find(|s| s.name() == name)
                .cloned()
                .ok_or_else(|| anyhow!("unknown storage {name}"))
        };
        let (from_spec, to_spec) = (find(&req.from)?, find(&req.to)?);
        let from = self.open_spec(&from_spec)?;
        let to = self.open_spec(&to_spec)?;
        let others: OpenStorages = self
            .open_storages(false)?
            .into_iter()
            .filter(|(s, _)| {
                !s.is_carrier() && s.name() != from_spec.name() && s.name() != to_spec.name()
            })
            .collect();
        let fk = self.folder_keys(rec)?;
        let read_from = !from_spec.is_cold() || req.confirm_cold_read;
        let read_to = !to_spec.is_cold() || req.confirm_cold_read;
        for group in items.chunks(MOVE_GROUP) {
            let mut deletes: Vec<(ObjectName, u64)> = Vec::new();
            let present: Vec<bool> = group
                .iter()
                .map(|i| i.on_to || to.exists(&chunk_storage_key(&i.object)).unwrap_or(false))
                .collect();
            let mut local = self.local_ciphertexts(
                &fk,
                group
                    .iter()
                    .zip(&present)
                    .filter(|(_, p)| !**p)
                    .map(|(i, _)| i),
            );
            for (item, present) in group.iter().zip(present) {
                let key = chunk_storage_key(&item.object);
                let mut size = item.size;
                if !present {
                    let ct = local
                        .remove(&item.object)
                        .or_else(|| self.move_source(item, &others, from.as_ref(), read_from));
                    let Some(ct) = ct else {
                        keep(
                            &mut report,
                            &item.object,
                            "no readable copy of the block was found".to_string(),
                        );
                        continue;
                    };
                    match to.put_if_absent(&key, &ct) {
                        Ok(_) => {
                            report.blocks_copied += 1;
                            report.bytes_copied += ct.len() as u64;
                            size = ct.len() as u64;
                        }
                        Err(e) => {
                            let why = match pool::pool_error(&e) {
                                Some(pe) => pe.to_string(),
                                None => format!("writing to {} failed: {e:#}", to_spec.name()),
                            };
                            keep(&mut report, &item.object, why);
                            continue;
                        }
                    }
                }
                // Check the copy before the old one may go.
                let checked = if read_to {
                    matches!(to.get(&key), Ok(Some(b)) if ObjectName::from_bytes(&crypto::hash(&b)) == item.object)
                } else {
                    to.exists(&key).unwrap_or(false)
                };
                if !checked {
                    keep(
                        &mut report,
                        &item.object,
                        format!("the copy on {} could not be checked", to_spec.name()),
                    );
                    continue;
                }
                report.blocks_verified += 1;
                if !item.on_to {
                    self.pending.push(Event::ChunkStored {
                        folder: rec.folder_id.clone(),
                        chunk: item.chunk.clone(),
                        object: item.object.clone(),
                        storage: to_spec.name().to_string(),
                        size,
                    });
                }
                if read_to {
                    self.pending.push(Event::ChunkVerified {
                        folder: rec.folder_id.clone(),
                        chunk: item.chunk.clone(),
                        object: item.object.clone(),
                        storage: to_spec.name().to_string(),
                    });
                }
                self.pending.push(Event::ChunkDropped {
                    folder: rec.folder_id.clone(),
                    chunk: item.chunk.clone(),
                    object: item.object.clone(),
                    storage: from_spec.name().to_string(),
                });
                deletes.push((item.object.clone(), item.size));
            }
            // The drops are sealed and pushed before anything is deleted.
            self.commit_batch()?;
            let in_use = self.objects_claimed_on(from_spec.name())?;
            for (object, size) in deletes {
                if in_use.contains(&object) {
                    continue;
                }
                match from.delete(&chunk_storage_key(&object)) {
                    Ok(()) => {
                        report.blocks_dropped += 1;
                        report.bytes_dropped += size;
                    }
                    Err(e) => keep(
                        &mut report,
                        &object,
                        format!(
                            "recorded as dropped, but deleting it from {} failed ({e:#}); run the move again",
                            from_spec.name()
                        ),
                    ),
                }
            }
        }
        // An earlier run that stopped after recording its drops.
        if !dropped.is_empty() {
            let in_use = self.objects_claimed_on(from_spec.name())?;
            for object in dropped {
                let key = chunk_storage_key(&object);
                if in_use.contains(&object) || !from.exists(&key).unwrap_or(false) {
                    continue;
                }
                if from.delete(&key).is_ok() {
                    report.leftovers_removed += 1;
                }
            }
        }
        report.summary = Self::move_summary(&report, &rec.name);
        Ok(report)
    }

    /// Objects some ledger record still counts as a copy on `storage` (an
    /// object shared with another record must stay).
    fn objects_claimed_on(&self, storage: &str) -> Result<HashSet<ObjectName>> {
        let view = self.view()?;
        Ok(view
            .chunks
            .values()
            .filter(|r| {
                r.storages
                    .get(storage)
                    .is_some_and(|l| !l.claimed_by.is_empty())
            })
            .map(|r| r.object.clone())
            .collect())
    }

    /// The blocks of `items` re-encrypted from the files on this device
    /// (chunking and encryption are deterministic), each file read once.
    /// Reading for a move does not count as using a file: its access time
    /// is put back, so idle files stay idle.
    fn local_ciphertexts<'a>(
        &self,
        fk: &FolderKeys,
        items: impl Iterator<Item = &'a MoveItem>,
    ) -> HashMap<ObjectName, Vec<u8>> {
        let mut by_file: BTreeMap<&Path, HashMap<&ChunkId, &MoveItem>> = BTreeMap::new();
        for item in items {
            if let Some(path) = item.files.first() {
                by_file.entry(path).or_default().insert(&item.chunk, item);
            }
        }
        let mut out = HashMap::new();
        for (path, wanted) in by_file {
            let accessed = fs::metadata(path).and_then(|m| m.accessed()).ok();
            let Ok(file) = fs::File::open(path) else {
                continue;
            };
            let Ok(chunker) = Chunker::new(std::io::BufReader::new(&file), self.chunker) else {
                continue;
            };
            for piece in chunker {
                let Ok(piece) = piece else { break };
                let id = ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &piece));
                let Some(item) = wanted.get(&id) else {
                    continue;
                };
                let ct = (|| {
                    crypto::encrypt_with_nonce(
                        &fk.chunk_key(item.epoch, &id)?,
                        &fk.chunk_nonce(item.epoch, &id)?,
                        &fk.chunk_aad(&self.vault.vault_id, &id, piece.len() as u64),
                        &crate::pack::pack(&piece),
                    )
                })();
                if let Ok(ct) = ct {
                    if ObjectName::from_bytes(&crypto::hash(&ct)) == item.object {
                        out.insert(item.object.clone(), ct);
                    }
                }
            }
            if let Some(t) = accessed {
                let _ = file.set_times(fs::FileTimes::new().set_accessed(t));
            }
        }
        out
    }

    /// The ciphertext of a block to move that is not re-encrypted from a
    /// local file: from the block cache, another readable storage, or the
    /// old storage itself (only when it may be read). Checked against its
    /// name.
    fn move_source(
        &self,
        item: &MoveItem,
        others: &OpenStorages,
        from: &dyn Storage,
        read_from: bool,
    ) -> Option<Vec<u8>> {
        let good = |ct: &Vec<u8>| ObjectName::from_bytes(&crypto::hash(ct)) == item.object;
        if let Some(ct) = self.cached_object(&item.object) {
            return Some(ct);
        }
        let key = chunk_storage_key(&item.object);
        for (_, b) in others {
            if let Ok(Some(ct)) = b.get(&key) {
                if good(&ct) {
                    return Some(ct);
                }
            }
        }
        if read_from {
            if let Ok(Some(ct)) = from.get(&key) {
                if good(&ct) {
                    return Some(ct);
                }
            }
        }
        None
    }

    // ----- the "move idle files to cold storage" suggestion -------------------

    /// The cheapest-to-keep move of a folder's idle files: from the priced
    /// hot storage that holds most of their cost to a cheaper cold storage.
    /// `None` when no move lowers the bill.
    pub(super) fn cold_idle_move(&self, rec: &FolderRecord, idle_days: i64) -> Option<MoveReport> {
        let colds: Vec<&StorageSpec> = self
            .config
            .storages
            .iter()
            .filter(|s| s.is_cold() && !s.is_carrier())
            .collect();
        if colds.is_empty() {
            return None;
        }
        let mut best: Option<(f64, MoveReport)> = None;
        for from in self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_cold() && !s.is_carrier())
        {
            let Some(pf) = self
                .storage_price(from.name())
                .and_then(|p| p.storage_per_gb_month.map(|v| (v, p.currency)))
            else {
                continue;
            };
            for to in &colds {
                let Some(pt) = self
                    .storage_price(to.name())
                    .and_then(|p| p.storage_per_gb_month.map(|v| (v, p.currency)))
                else {
                    continue;
                };
                if pt.1 != pf.1 || pt.0 >= pf.0 {
                    continue;
                }
                let req = MoveRequest {
                    folder: rec.folder_id.to_string(),
                    from: from.name().to_string(),
                    to: to.name().to_string(),
                    idle_days: Some(idle_days),
                    dry_run: true,
                    confirm_cold_read: false,
                };
                let Ok(plan) = self.plan_move(rec, &req) else {
                    continue;
                };
                let saving = plan
                    .report
                    .monthly_saving
                    .get(&pf.1)
                    .copied()
                    .unwrap_or(0.0);
                if plan.report.blocks == 0 || saving <= 0.0 {
                    continue;
                }
                if best.as_ref().is_none_or(|(s, _)| saving > *s) {
                    let mut report = plan.report;
                    report.summary = Self::move_summary(&report, &rec.name);
                    best = Some((saving, report));
                }
            }
        }
        best.map(|(_, r)| r)
    }

    /// Carry out the cold-storage suggestion for a folder: the same move
    /// `cold_idle_move` proposes, worked out again from the current ledger.
    pub(super) fn apply_cold_idle(&mut self, folder: &str, idle_days: i64) -> Result<MoveReport> {
        let (rec, _) = self.resolve_folder(folder)?;
        let Some(planned) = self.cold_idle_move(&rec, idle_days) else {
            bail!("moving the idle files of {} to cold storage would not lower the bill now; see `varsto advice`", rec.name);
        };
        self.move_data(&MoveRequest {
            folder: rec.folder_id.to_string(),
            from: planned.from,
            to: planned.to,
            idle_days: Some(idle_days),
            dry_run: false,
            confirm_cold_read: false,
        })
    }
}
