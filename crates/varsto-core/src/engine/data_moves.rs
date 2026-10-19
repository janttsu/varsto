// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Data placement: which storages a folder is written to, and moving blocks
//! from one storage to another (`docs/spec/alpha-0-format.md` sections 23
//! and 77.9).
//!
//! A folder's placement (`crate::placement`) limits the storages a push
//! writes its blocks to; it is published like the folder's policy, so every
//! device writes the folder the same way. A move works on packs
//! (`storages3::moves`): a pack whose live blocks all move is copied whole
//! (read from any storage that holds it, checked against its id), claimed,
//! read back, and only then dropped from the old storage; a pack that also
//! holds blocks that stay is rebuilt (the moving blocks into new packs on
//! the new storage, the others into a new pack on the old one). The map
//! record of the new packs and the batch with the drops are pushed before
//! anything is deleted. It never drops a copy the folder's copy rules still
//! need (the plan is checked against the policy over the copies the drops
//! leave), never the last one, reads a cold storage only with a confirmed
//! cold read (the files on this device are re-encrypted instead where they
//! can be), and a block moved away from a storage is not written back there
//! by later pushes while another copy exists. A move that stops halfway is
//! carried on by running it again: packs already on the new storage are not
//! copied twice, and packs recorded as dropped that are still on the old
//! storage are deleted.
use super::placement::{fmt_size, is_idle};
use super::verify::storage_identity;
use super::*;
use crate::advice::{add_cost, Costs};
use crate::placement::{MoveReport, MoveRequest, Placement, PlacementInfo};
use crate::policy::{ChunkFacts, PolicyState};

/// How many kept blocks a report lists by name.
const KEPT_EXAMPLES: usize = 10;
/// Source packs per ledger batch of a move (a staged move's "group").
pub(super) const MOVE_GROUP_PACKS: usize = 64;
/// Bytes (size classes) of the source packs of one group.
const MOVE_GROUP_BYTES: u64 = 16 << 20;

/// The size class of the pack an action works on.
fn action_class(a: &crate::storages3::PackAction) -> u8 {
    match a {
        crate::storages3::PackAction::Whole { class, .. }
        | crate::storages3::PackAction::Rebuild { class, .. } => *class,
    }
}

/// The storages a folder's blocks go to on this device.
pub(super) struct WriteTargets {
    /// `None`: every storage (no placement, or none of its storages here).
    names: Option<BTreeSet<String>>,
    carriers: BTreeSet<String>,
    /// The vault's trash storage here (`trash`): it takes trashed blocks
    /// only, unless the folder's placement names it.
    trash: Option<String>,
    /// Storages being drained or drained: they take nothing new.
    closed: BTreeSet<String>,
    /// With no placement: the fewest storages that keep the folder's policy
    /// (section 23). `None`: every storage.
    minimal: Option<MinimalSet>,
}

/// The default write set of a folder without a placement.
pub(super) struct MinimalSet {
    /// Storages written: every storage except the surplus ones among those
    /// of a place the policy counts copies in.
    chosen: BTreeSet<String>,
}

impl WriteTargets {
    /// Whether a push writes a block whose copies are `standing` to the
    /// storage `name`. Transferrers follow their own rules. A block that was
    /// moved away from a storage is not put back while another copy exists.
    pub(super) fn wants(&self, name: &str, standing: Option<&BlockStanding>) -> bool {
        if self.closed.contains(name) {
            return false;
        }
        if self.carriers.contains(name) {
            return true;
        }
        if self.names.as_ref().is_some_and(|n| !n.contains(name)) {
            return false;
        }
        if self
            .minimal
            .as_ref()
            .is_some_and(|m| !m.chosen.contains(name))
        {
            return false;
        }
        let trash = self.trash.as_deref();
        if trash == Some(name) && self.names.is_none() {
            return false;
        }
        // A copy on the trash storage does not keep a current file's block
        // off the folder's storages (a file restored or created again).
        match standing {
            Some(s) if s.dropped_from.contains(name) => !s
                .copies
                .iter()
                .any(|n| n != name && Some(n.as_str()) != trash && !self.carriers.contains(n)),
            _ => true,
        }
    }
}

/// Where a block is and where it was taken away from, on the pack-level
/// view: the storages holding a live place of it, and the storages a pack
/// with a place of it was dropped from (moved or drained away).
#[derive(Clone, Debug, Default)]
pub(super) struct BlockStanding {
    pub(super) copies: BTreeSet<String>,
    pub(super) dropped_from: BTreeSet<String>,
}

impl BlockStanding {
    pub(super) fn of(
        view: &crate::ledger3::LedgerView,
        table: &crate::blockmap::MapTable,
        object: &ObjectName,
    ) -> BlockStanding {
        let mut out = BlockStanding::default();
        let Ok(obj) = crate::storages3::object_bin(object) else {
            return out;
        };
        out.copies = crate::storages3::block_copies(view, table, &obj);
        for place in crate::ledger3::BlockMapView::places_of(table, &obj) {
            let Some(rec) = view.pack(&place.pack) else {
                continue;
            };
            for (s, _) in rec.places.iter() {
                if let Some(name) = view.tables.storage_name(*s) {
                    if view.dropped_from(&place.pack, name) {
                        out.dropped_from.insert(name.to_string());
                    }
                }
            }
        }
        out
    }
}

/// What a staged move job adds to a move (`engine/staged_moves.rs`).
#[derive(Clone, Default)]
pub(super) struct StagedExtras {
    /// A job run: a full target stops the run instead of keeping blocks.
    pub(super) staged: bool,
    /// Only files at or under these folder paths.
    pub(super) paths: Vec<String>,
    /// Copy and check but do not drop from the old storage.
    pub(super) keep_source: bool,
    /// Stop after this many groups of blocks.
    pub(super) max_groups: Option<usize>,
    /// The job file, updated after every group.
    pub(super) job_id: Option<String>,
    /// Bytes and blocks done before this run.
    pub(super) base_done: u64,
    pub(super) base_blocks: u64,
}

impl StagedExtras {
    /// Whether a file of the folder is in scope.
    fn includes(&self, path: &str) -> bool {
        self.paths.is_empty()
            || self.paths.iter().any(|p| {
                path == p
                    || path
                        .strip_prefix(p.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            })
    }
}

/// One block a move takes off the old storage.
pub(super) struct MoveItem {
    pub(super) chunk: ChunkId,
    pub(super) object: ObjectName,
    pub(super) epoch: u32,
    pub(super) size: u64,
    /// The pack on the old storage that holds it.
    pub(super) pack: crate::ledger3::PackId,
    /// A live place of it on the new storage already, and that place's pack.
    pub(super) on_to: bool,
    pub(super) to_pack: Option<crate::ledger3::PackId>,
    /// Files of this folder on this device that contain the block.
    pub(super) files: Vec<PathBuf>,
}

/// A move worked out from the ledger and the folder's block map, before
/// anything is changed: the pack-level plan (after the policy's veto and
/// the cold-read check) and the blocks it takes.
pub(super) struct MovePlan {
    pub(super) plan: crate::storages3::MovePlan,
    pub(super) items: Vec<MoveItem>,
    pub(super) report: MoveReport,
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
        let closed = self.closed_storages();
        // A placement that names only storages being drained falls back to
        // every storage, so the folder's new blocks still go somewhere.
        let names = rec
            .placement
            .as_ref()
            .filter(|p| !p.is_everywhere())
            .map(|p| {
                let mut n = self.placement_names(p);
                n.retain(|s| !closed.contains(s));
                n
            })
            .filter(|n| !n.is_empty());
        if log::log_enabled!(log::Level::Trace) {
            log::trace!(
                folder = rec.name.as_str(),
                storages:? = names,
                carriers:? = carriers;
                "placement: write targets (none = every storage)"
            );
        }
        let minimal = if names.is_none() {
            self.minimal_set(rec, &closed)
        } else {
            None
        };
        WriteTargets {
            names,
            carriers,
            trash: self.trash_storage_here(),
            closed,
            minimal,
        }
    }

    /// The default placement (section 23): a storage is written unless the
    /// policy counts copies in its place and the place has more storages
    /// than the policy asks for ("home" is never pruned). Of those the best are kept: first a
    /// storage that already holds the folder's blocks, then a warm one over
    /// a cold one, then the cheaper (price per GB-month, unknown last), then
    /// by name. Places the policy does not name (own disks, pools, other
    /// labels) are written in full. More storages join when the policy's
    /// `min_copies` needs them. `None` (every storage) when the folder has
    /// no policy.
    fn minimal_set(&self, rec: &FolderRecord, closed: &BTreeSet<String>) -> Option<MinimalSet> {
        let policy = rec.effective_policy()?;
        let trash = self.trash_storage_here();
        let usable: Vec<&StorageSpec> = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_carrier() && !closed.contains(s.name()))
            .filter(|s| trash.as_deref() != Some(s.name()))
            .collect();
        let mut holds: BTreeSet<String> = BTreeSet::new();
        if let (Ok(view), Ok(folder)) = (self.view3(), members3::bin(&rec.folder_id)) {
            for id in view.packs.keys() {
                if view.pack_folder(id) == Some(folder) {
                    holds.extend(view.holders(id).into_iter().map(str::to_string));
                }
            }
        }
        let rank = |s: &&StorageSpec| {
            (
                !holds.contains(s.name()),
                s.is_cold(),
                self.storage_price(s.name())
                    .and_then(|p| p.storage_per_gb_month)
                    .unwrap_or(f64::MAX)
                    .to_bits(),
                s.name().to_string(),
            )
        };
        let mut chosen: BTreeSet<String> = BTreeSet::new();
        let mut surplus: Vec<&StorageSpec> = Vec::new();
        // "home" (own disks and directories) is never pruned: they cost nothing
        // to keep and a second disk is added to be written.
        for (place, n) in policy
            .min_per_place
            .iter()
            .filter(|(p, n)| **n > 0 && p.as_str() != "home")
        {
            let mut in_place: Vec<&StorageSpec> = usable
                .iter()
                .copied()
                .filter(|s| &s.place() == place)
                .collect();
            in_place.sort_by_key(rank);
            for (i, s) in in_place.into_iter().enumerate() {
                if i < *n as usize {
                    chosen.insert(s.name().to_string());
                } else {
                    surplus.push(s);
                }
            }
        }
        for s in &usable {
            if !surplus.iter().any(|x| x.name() == s.name()) {
                chosen.insert(s.name().to_string());
            }
        }
        // Enough copies in all.
        surplus.sort_by_key(rank);
        for s in surplus {
            if chosen.len() >= policy.min_copies as usize {
                break;
            }
            chosen.insert(s.name().to_string());
        }
        Some(MinimalSet { chosen })
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
            .or_else(|| self.keyring.find_backup(folder))
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
                    .filter(|s| !s.is_carrier() && !targets.closed.contains(s.name()))
                    .filter(|s| {
                        targets
                            .minimal
                            .as_ref()
                            .is_none_or(|m| m.chosen.contains(s.name()))
                    })
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
        crate::logged_op!("set placement", folder, {
            self.set_placement_inner(folder, placement)
        })
    }

    fn set_placement_inner(
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
        let placement = self.checked_placement(placement)?;
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
        // This device's `placement` record of the folder (kind 12): every
        // device takes the newest.
        self.publish_placement3(&rec, placement.as_ref(), now)?;
        self.placement(folder)
    }

    /// A placement checked against this device's storages, with the
    /// identities of the storages it names; `None` for every storage.
    pub(super) fn checked_placement(
        &self,
        placement: Option<Placement>,
    ) -> Result<Option<Placement>> {
        Ok(match placement.filter(|p| !p.is_everywhere()) {
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
                    if self.closed_storages().contains(name) {
                        bail!("{name} is being drained or has been drained: it takes no new blocks, so it cannot be where a folder is written (stop the drain first, or pick another storage)");
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
        })
    }

    // ----- moving data ---------------------------------------------------------

    /// Move a folder's blocks (with `idle_days`, those of its idle files)
    /// from one storage to another: copy, record, check, record the drop,
    /// delete. With `dry_run`, only report what would happen and what it
    /// costs. Moving a whole folder also changes its placement, so new
    /// blocks go to the new storage.
    pub fn move_data(&mut self, req: &MoveRequest) -> Result<MoveReport> {
        crate::logged_op!("move data", "", { self.move_data_inner(req) })
    }

    fn move_data_inner(&mut self, req: &MoveRequest) -> Result<MoveReport> {
        self.ensure_active()?;
        if self.vault.member {
            bail!("a member device cannot move the owner's data");
        }
        self.ensure_ledger_writable()?;
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
        let ex = StagedExtras::default();
        let mut plan = self.plan_move(&rec, req, &ex)?;
        if req.dry_run {
            plan.report.placement_changed = new_placement.map(|p| p.describe());
            plan.report.summary = Self::move_summary(&plan.report, &rec.name);
            return Ok(plan.report);
        }
        let mut report = self.run_move(&rec, req, plan, &ex)?;
        // Only once every block has left: a move that kept some is run again.
        if let Some(p) = new_placement.filter(|_| report.blocks_kept == 0) {
            report.placement_changed = Some(p.describe());
            self.set_placement(rec.folder_id.as_str(), Some(p))?;
            report.summary = Self::move_summary(&report, &rec.name);
        }
        Ok(report)
    }

    /// The folder's placement with `from` replaced by `to`, if that changes it.
    pub(super) fn placement_without(
        &self,
        rec: &FolderRecord,
        from: &str,
        to: &str,
    ) -> Option<Placement> {
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
    pub(super) fn plan_move(
        &self,
        rec: &FolderRecord,
        req: &MoveRequest,
        ex: &StagedExtras,
    ) -> Result<MovePlan> {
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
        if self.storage_settings(to.name()).closed() {
            bail!(
                "{} is being drained (or is drained): it takes no new blocks; stop the drain first (varsto storage drain {} --stop)",
                to.name(),
                to.name()
            );
        }
        let table = self.folder_table3(rec)?.ok_or_else(|| {
            anyhow!(
                "this device holds no key of folder {}: ask for it with `varsto folder request`",
                rec.name
            )
        })?;
        let folder = members3::bin(&rec.folder_id)?;
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
        let mut moving: BTreeMap<ObjectName, (ChunkRef, Vec<PathBuf>)> = BTreeMap::new();
        let mut staying: HashSet<ObjectName> = HashSet::new();
        let mut files = 0u64;
        let encrypted_here = self.mount_is_encrypted(&rec.folder_id);
        for f in state.files.values().filter(|f| !f.deleted) {
            let moves = idle.as_ref().is_none_or(|s| s.contains(&f.path)) && ex.includes(&f.path);
            if !moves {
                staying.extend(f.chunks.iter().map(|c| c.object.clone()));
                continue;
            }
            files += 1;
            let local = match &root {
                Some(r) if !encrypted_here && state.local_index.contains_key(&f.path) => {
                    Some(self.disk_of(r, &state, &f.path))
                }
                _ => None,
            };
            for c in &f.chunks {
                let e = moving
                    .entry(c.object.clone())
                    .or_insert_with(|| (c.clone(), Vec::new()));
                e.1.extend(local.clone());
            }
        }
        // Moving a whole folder takes the blocks of its trash along.
        if idle.is_none() && ex.paths.is_empty() {
            for c in self.trash_chunks(&rec.folder_id) {
                moving
                    .entry(c.object.clone())
                    .or_insert_with(|| (c, Vec::new()));
            }
        }
        moving.retain(|o, _| !staying.contains(o));

        let view = self.view3()?;
        let t = table.read().unwrap_or_else(|e| e.into_inner());
        let in_scope =
            |o: &crate::ledger3::ObjectBin| moving.contains_key(&ObjectName::from_bytes(o));
        let mut plan =
            crate::storages3::plan_move(&view, &t, &folder, from.name(), to.name(), &in_scope)?;
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
            .filter(|s| !s.is_cold() && !s.is_carrier() && s.name() != from.name())
            .map(|s| s.name().to_string())
            .collect();
        let copy_rules = rec
            .effective_policy()
            .as_ref()
            .filter(|p| p.min_copies > 0 || !p.min_per_place.is_empty())
            // Nothing is dropped from the old storage: the rules hold.
            .filter(|_| !ex.keep_source)
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
        // Moved by an earlier run: off the old storage, a pack with a place
        // of it dropped from there.
        for object in moving.keys() {
            let s = BlockStanding::of(&view, &t, object);
            if !s.copies.contains(from.name()) && s.dropped_from.contains(from.name()) {
                report.already_moved += 1;
            }
        }
        let packs: HashSet<crate::ledger3::PackId> =
            plan.actions.iter().map(|a| *a.pack()).collect();
        let live = crate::storages3::members_of_packs(&t, &packs)?;
        let read_cold = !from.is_cold() || req.confirm_cold_read;
        let cached = |o: &crate::ledger3::ObjectBin| self.cache_has(&ObjectName::from_bytes(o));
        let local_of = |o: &crate::ledger3::ObjectBin| {
            moving
                .get(&ObjectName::from_bytes(o))
                .is_some_and(|(_, p)| !p.is_empty())
                || cached(o)
        };
        let mut items = Vec::new();
        let mut remaining: BTreeSet<String> = BTreeSet::new();
        let (mut new_on_to, mut read_from) = (0u64, 0u64);
        let price_from = self.storage_price(from.name());
        let price_to = self.storage_price(to.name());
        let mut early = Costs::new();
        let mut kept_actions = Vec::new();
        for action in std::mem::take(&mut plan.actions) {
            let pack = *action.pack();
            let members = live.get(&pack).cloned().unwrap_or_default();
            let (inside, outside): (Vec<&crate::storages3::PackMember>, Vec<_>) =
                members.iter().partition(|m| in_scope(&m.object));
            // The policy's veto: only what dropping this copy makes worse
            // counts (a requirement the copies did not meet before keeps
            // nothing back).
            let mut vetoed: Vec<crate::storages3::PackMember> = Vec::new();
            let mut afters: Vec<(crate::storages3::PackMember, Vec<(String, String)>)> = Vec::new();
            for m in &inside {
                let before: BTreeSet<String> =
                    crate::storages3::block_copies(&view, &*t, &m.object)
                        .into_iter()
                        .filter(|n| !carriers.contains(n))
                        .collect();
                let after: Vec<(String, String)> = before
                    .iter()
                    .filter(|n| n.as_str() != from.name())
                    .cloned()
                    .chain((!before.contains(to.name())).then(|| to.name().to_string()))
                    .map(|n| {
                        let p = place_of(&n);
                        (n, p)
                    })
                    .collect();
                if let Some(rules) = &copy_rules {
                    let before: Vec<(String, String)> =
                        before.iter().map(|n| (n.clone(), place_of(n))).collect();
                    let mut capped = rules.clone();
                    capped.min_copies = capped.min_copies.min(before.len() as u32);
                    for (place, n) in capped.min_per_place.iter_mut() {
                        let have = before.iter().filter(|(_, p)| p == place).count() as u32;
                        *n = (*n).min(have);
                    }
                    let verdict = crate::policy::evaluate(
                        &rec.name,
                        &capped,
                        &[ChunkFacts {
                            copies: after
                                .iter()
                                .map(|(n, p)| (n.clone(), p.clone(), false, 0))
                                .collect(),
                            stored_utc: 0,
                        }],
                        &BTreeMap::new(),
                        &[],
                        now,
                    );
                    if verdict.state == PolicyState::Violated {
                        keep(
                            &mut report,
                            &ObjectName::from_bytes(&m.object),
                            format!(
                                "the folder's policy ({}) needs the copy on {}",
                                capped.describe(),
                                from.name()
                            ),
                        );
                        vetoed.push(**m);
                        continue;
                    }
                }
                afters.push((**m, after));
            }
            if afters.is_empty() {
                continue;
            }
            // What is left of the action once the vetoed blocks stay.
            let action = match action {
                crate::storages3::PackAction::Whole {
                    pack,
                    class,
                    copy,
                    on_destination,
                    members: all,
                    missing,
                } if vetoed.is_empty() => crate::storages3::PackAction::Whole {
                    pack,
                    class,
                    copy,
                    on_destination,
                    members: all,
                    missing,
                },
                crate::storages3::PackAction::Whole {
                    pack,
                    class,
                    missing,
                    ..
                } => crate::storages3::PackAction::Rebuild {
                    pack,
                    class,
                    moving: missing
                        .into_iter()
                        .filter(|m| !vetoed.iter().any(|v| v.object == m.object))
                        .collect(),
                    staying: vetoed.clone(),
                },
                crate::storages3::PackAction::Rebuild {
                    pack,
                    class,
                    moving,
                    mut staying,
                } => {
                    let moving: Vec<_> = moving
                        .into_iter()
                        .filter(|m| !vetoed.iter().any(|v| v.object == m.object))
                        .collect();
                    staying.extend(vetoed.iter().copied());
                    crate::storages3::PackAction::Rebuild {
                        pack,
                        class,
                        moving,
                        staying,
                    }
                }
            };
            // Reading the pack: from a storage other than a cold source when
            // one holds it, from the source when it may be read, or block by
            // block from this device.
            let needs_read = match &action {
                crate::storages3::PackAction::Whole { copy, .. } => *copy,
                crate::storages3::PackAction::Rebuild { .. } => true,
            };
            let other_hot = view
                .holders(&pack)
                .iter()
                .any(|h| hot.contains(*h) && *h != to.name());
            let local_ok = match &action {
                crate::storages3::PackAction::Whole { missing, .. } => {
                    missing.iter().all(|m| local_of(&m.object))
                }
                crate::storages3::PackAction::Rebuild {
                    moving, staying, ..
                } => moving
                    .iter()
                    .chain(staying.iter())
                    .all(|m| local_of(&m.object)),
            };
            if needs_read && !read_cold && !other_hot && !local_ok {
                for (m, _) in &afters {
                    keep(
                        &mut report,
                        &ObjectName::from_bytes(&m.object),
                        format!(
                            "the only copy to read is on cold storage {}: confirm the cold read to move it",
                            from.name()
                        ),
                    );
                }
                continue;
            }
            let class_bytes =
                crate::ledger3::events::class_bytes(action_class(&action)).unwrap_or(0);
            if needs_read && !other_hot && !local_ok {
                read_from += class_bytes;
            }
            if let (Some(p), Some(c)) = (
                &price_from,
                view.copies(&pack)
                    .into_iter()
                    .find(|c| c.storage == from.name()),
            ) {
                let days = ((now - c.stored_utc).max(0) / 86_400) as u32;
                if let Some(cost) = p
                    .early_deletion_cost(class_bytes, days)
                    .filter(|c| *c > 0.0)
                {
                    add_cost(&mut early, &p.currency, cost);
                }
            }
            let _ = &outside;
            for (m, after) in afters {
                let object = ObjectName::from_bytes(&m.object);
                let s = BlockStanding::of(&view, &t, &object);
                let on_to = s.copies.contains(to.name());
                report.blocks += 1;
                report.bytes += u64::from(m.place.len);
                remaining.extend(after.iter().map(|(n, _)| n.clone()));
                let n = after.len() as u64;
                if report.blocks == 1 || n < report.min_copies_after {
                    report.min_copies_after = n;
                }
                if !on_to {
                    new_on_to += u64::from(m.place.len);
                }
                let to_pack = on_to
                    .then(|| {
                        view.block_places(&m.object, &*t)
                            .into_iter()
                            .find(|p| !p.marked && p.storages.iter().any(|s| s == to.name()))
                            .map(|p| p.place.pack)
                    })
                    .flatten();
                let (chunk, paths) = match moving.get(&object) {
                    Some((c, p)) => (c.chunk.clone(), p.clone()),
                    None => (ChunkId::from_bytes(&m.chunk), Vec::new()),
                };
                items.push(MoveItem {
                    chunk,
                    object,
                    epoch: m.epoch,
                    size: u64::from(m.place.len),
                    pack,
                    on_to,
                    to_pack,
                    files: paths,
                });
            }
            kept_actions.push(action);
        }
        plan.actions = kept_actions;
        drop(t);
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
            plan,
            items,
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

    /// Carry out a planned move, a few packs per ledger batch: each group's
    /// packs are copied (or rebuilt) and checked, the map record of the new
    /// packs and the batch with the claims and drops are pushed, and only
    /// then are the dropped packs deleted from the old storage.
    pub(super) fn run_move(
        &mut self,
        rec: &FolderRecord,
        req: &MoveRequest,
        plan: MovePlan,
        ex: &StagedExtras,
    ) -> Result<MoveReport> {
        let MovePlan {
            plan,
            items,
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
        let folder = members3::bin(&rec.folder_id)?;
        let epoch = self.folder_keys(rec)?.epoch;
        let from = self.open_spec(&from_spec)?;
        // A move to a pool talks to the pool itself: it asks which places
        // hold a pack and adds copies for the disk group rule.
        let to_pool: Option<PoolStorage> = matches!(to_spec, StorageSpec::Pool { .. })
            .then(|| self.open_pool(&to_spec))
            .transpose()?;
        let to_box: Option<Box<dyn Storage>> = match &to_pool {
            Some(_) => None,
            None => Some(self.open_spec(&to_spec)?),
        };
        let to_storage: &dyn Storage = match (&to_pool, &to_box) {
            (Some(p), _) => p,
            (None, Some(b)) => b.as_ref(),
            (None, None) => unreachable!("one of them is set"),
        };
        // A move from a pool: which disk that is away holds a pack.
        let from_pool: Option<PoolStorage> = from_spec
            .is_data_only()
            .then(|| self.open_pool(&from_spec))
            .transpose()?;
        let fk = self.folder_keys(rec)?;
        let view_now = self.view3()?;
        let gate = self.quota_gate(&view_now);
        // Blocks this plan takes, by pack: what a run reports in blocks.
        let mut by_pack: HashMap<crate::ledger3::PackId, Vec<&MoveItem>> = HashMap::new();
        for i in &items {
            by_pack.entry(i.pack).or_default().push(i);
        }
        let blocks_of = |p: &crate::ledger3::PackId| -> (u64, u64) {
            by_pack.get(p).map_or((0, 0), |v| {
                (v.len() as u64, v.iter().map(|i| i.size).sum::<u64>())
            })
        };
        // Room on the new storage first (its quota counts size classes).
        let mut actions: Vec<crate::storages3::PackAction> = Vec::new();
        for a in plan
            .actions
            .iter()
            .filter(|a| by_pack.contains_key(a.pack()))
        {
            let need = match a {
                crate::storages3::PackAction::Whole {
                    copy: true, class, ..
                } => crate::ledger3::events::class_bytes(*class).unwrap_or(0),
                crate::storages3::PackAction::Whole { .. } => 0,
                crate::storages3::PackAction::Rebuild { moving, .. } => {
                    moving.iter().map(|m| u64::from(m.place.len)).sum()
                }
            };
            if need > 0 && !gate.take_pack(to_spec.name(), need) {
                let (n, bytes) = blocks_of(a.pack());
                if ex.staged {
                    report.waiting_room_blocks += n;
                    report.waiting_room_bytes += bytes;
                    report.waiting_note = Some(gate.message(to_spec.name()));
                } else {
                    for i in by_pack.get(a.pack()).into_iter().flatten() {
                        keep(&mut report, &i.object, gate.message(to_spec.name()));
                    }
                }
                continue;
            }
            actions.push(a.clone());
        }
        // Where the packs are read from besides the old storage: the
        // mailbox's outbox, the other storages that hold them (a cold one
        // only with a confirmed cold read), and blocks re-encrypted from the
        // files on this device or taken from the block cache.
        let readers: Vec<(StorageSpec, Box<dyn Storage>)> = self
            .config
            .storages
            .iter()
            .filter(|s| s.name() != from_spec.name() && s.name() != to_spec.name())
            .filter(|s| !s.is_carrier() && (!s.is_cold() || req.confirm_cold_read))
            .filter_map(|s| self.open_spec(s).ok().map(|b| (s.clone(), b)))
            .collect();
        let read_source = !from_spec.is_cold() || req.confirm_cold_read;
        // Blocks re-encrypted from the files here: only when the old storage
        // may not be read (a cold one without a confirmed cold read).
        let local: HashMap<ObjectName, Vec<u8>> = if read_source {
            HashMap::new()
        } else {
            self.local_ciphertexts(&fk, items.iter())
        };
        let opts = crate::storages3::MoveOptions {
            keep_source: ex.keep_source,
            confirm_cold_read: req.confirm_cold_read,
            max_packs: 0,
            split_on_no_room: ex.staged,
        };
        let task = crate::activity::start(
            crate::activity::DATA_MOVE,
            &rec.name,
            items.iter().map(|i| i.size).sum(),
            crate::activity::Unit::Bytes,
        );
        let mut disks_used: BTreeSet<String> = BTreeSet::new();
        let mut min_room: Option<u64> = None;
        let mut runs: Vec<crate::storages3::MoveRun> = Vec::new();
        // Groups of source packs of up to 16 MiB together (at least one
        // pack): one batch each.
        let mut groups: Vec<Vec<crate::storages3::PackAction>> = Vec::new();
        let mut group_bytes = 0u64;
        for a in actions {
            let b = crate::ledger3::events::class_bytes(action_class(&a)).unwrap_or(0);
            match groups.last_mut() {
                Some(g) if group_bytes + b <= MOVE_GROUP_BYTES && g.len() < MOVE_GROUP_PACKS => {
                    group_bytes += b;
                    g.push(a);
                }
                _ => {
                    group_bytes = b;
                    groups.push(vec![a]);
                }
            }
        }
        for (groups_done, group) in groups.iter().enumerate() {
            if ex.max_groups.is_some_and(|m| groups_done >= m) {
                report.stopped_early = true;
                break;
            }
            let sub = crate::storages3::MovePlan {
                actions: group.to_vec(),
                ..plan.clone()
            };
            let run = {
                let pack_source = |p: &crate::ledger3::PackId| -> Option<Vec<u8>> {
                    let key = crate::packs::pack_key(&hex::encode(p));
                    if let Some(b) = self.mailbox_object(&key) {
                        return Some(b);
                    }
                    let holders = view_now.holders(p);
                    for (spec, b) in &readers {
                        if holders.contains(&spec.name()) {
                            if let Ok(Some(bytes)) = b.get_bounded(&key, crate::storage::MAX_PACK) {
                                if crypto::hash(&bytes) == *p {
                                    return Some(bytes);
                                }
                            }
                        }
                    }
                    None
                };
                let member_source = |m: &crate::storages3::PackMember| -> Option<Vec<u8>> {
                    let o = ObjectName::from_bytes(&m.object);
                    local.get(&o).cloned().or_else(|| self.cached_object(&o))
                };
                let sources = crate::storages3::Sources {
                    pack: &pack_source,
                    member: &member_source,
                    read_source,
                };
                let src_ep = crate::storages3::Endpoint {
                    name: from_spec.name(),
                    storage: from.as_ref(),
                    cold: from_spec.is_cold(),
                    pool: from_pool.as_ref(),
                };
                let dst_ep = crate::storages3::Endpoint {
                    name: to_spec.name(),
                    storage: to_storage,
                    cold: to_spec.is_cold(),
                    pool: to_pool.as_ref(),
                };
                crate::storages3::run_move_with(&sub, &src_ep, &dst_ep, &sources, &opts)
            };
            for p in group {
                task.advance(blocks_of(p.pack()).1);
            }
            runs.push(run);
            let run = runs.last().expect("pushed");
            let r = &run.report;
            disks_used.extend(r.disks_used.iter().cloned());
            // Blocks that found no room went into the remainder on the
            // source: not moved.
            let kept: HashSet<crate::ledger3::ObjectBin> = r.kept_back.iter().copied().collect();
            let moved_of = |p: &crate::ledger3::PackId| -> Vec<&MoveItem> {
                by_pack
                    .get(p)
                    .into_iter()
                    .flatten()
                    .copied()
                    .filter(|i| {
                        crate::storages3::object_bin(&i.object).is_ok_and(|o| !kept.contains(&o))
                    })
                    .collect()
            };
            for p in r.copied_packs.iter().chain(&r.rebuilt_packs) {
                let moved = moved_of(p);
                report.blocks_copied += moved.iter().filter(|i| !i.on_to).count() as u64;
                report.blocks_verified += moved.len() as u64;
            }
            report.bytes_copied += r.bytes_written;
            for p in &r.dropped_packs {
                for i in moved_of(p) {
                    report.blocks_dropped += 1;
                    report.bytes_dropped += i.size;
                    report.blocks_done += 1;
                    report.bytes_done += i.size;
                }
            }
            if ex.keep_source {
                // Copied and checked, nothing dropped: done all the same.
                for a in group {
                    let p = a.pack();
                    if r.waiting_room.contains(p)
                        || r.waiting_place.contains(p)
                        || r.corrupt.contains(p)
                        || r.unavailable.iter().any(|(u, _)| u == p)
                    {
                        continue;
                    }
                    for i in moved_of(p) {
                        report.blocks_done += 1;
                        report.bytes_done += i.size;
                    }
                }
            }
            for i in items.iter().filter(|i| {
                crate::storages3::object_bin(&i.object).is_ok_and(|o| kept.contains(&o))
            }) {
                if ex.staged {
                    report.waiting_room_blocks += 1;
                    report.waiting_room_bytes += i.size;
                } else {
                    keep(
                        &mut report,
                        &i.object,
                        format!("{} has no room for it now", to_spec.name()),
                    );
                }
            }
            if !kept.is_empty() {
                min_room =
                    Some(min_room.map_or(r.waiting_min_bytes, |m| m.min(r.waiting_min_bytes)));
            }
            for p in &r.waiting_place {
                let (n, bytes) = blocks_of(p);
                report.waiting_place_blocks += n;
                report.waiting_place_bytes += bytes;
            }
            for p in &r.waiting_room {
                let (n, bytes) = blocks_of(p);
                if ex.staged {
                    report.waiting_room_blocks += n;
                    report.waiting_room_bytes += bytes;
                } else {
                    for i in by_pack.get(p).into_iter().flatten() {
                        keep(
                            &mut report,
                            &i.object,
                            format!("{} has no room for it now", to_spec.name()),
                        );
                    }
                }
            }
            if r.waiting_room_packs > 0 {
                min_room =
                    Some(min_room.map_or(r.waiting_min_bytes, |m| m.min(r.waiting_min_bytes)));
            }
            for p in &r.corrupt {
                for i in by_pack.get(p).into_iter().flatten() {
                    keep(
                        &mut report,
                        &i.object,
                        format!(
                            "the copy on {} is damaged: the repair fixes it first",
                            from_spec.name()
                        ),
                    );
                }
            }
            for (p, why) in &r.unavailable {
                // A pack only on source disks that are away waits for them.
                let away = from_pool.as_ref().and_then(|pool| {
                    let locs = pool.locate_all(&crate::packs::pack_key(&hex::encode(p)));
                    (!locs.is_empty() && !locs.iter().any(|l| l.attached))
                        .then(|| locs[0].label.clone())
                });
                match away {
                    Some(label) if ex.staged => {
                        let (n, bytes) = blocks_of(p);
                        report.waiting_source_blocks += n;
                        report.waiting_source_bytes += bytes;
                        if !report.waiting_source_disks.contains(&label) {
                            report.waiting_source_disks.push(label);
                        }
                    }
                    _ => {
                        for i in by_pack.get(p).into_iter().flatten() {
                            keep(&mut report, &i.object, why.clone());
                        }
                    }
                }
            }
            // The map record of the new packs and the batch with the claims
            // and drops go out before anything is deleted.
            let written = run.new_packs.clone();
            let events = run.events.clone();
            let view = self.view3()?;
            self.publish_map3(&folder, epoch, &written, &view)?;
            self.f3.pending.extend(events);
            self.commit_now3()?;
            let (_, failed) = run.delete_dropped_each(from.as_ref());
            for (p, e) in failed {
                log::warn!(storage = from_spec.name(), pack = hex::encode(p).as_str(); "a dropped pack stays until garbage collection: {e}");
            }
            if ex.job_id.is_some() {
                report.disks_used = disks_used.iter().cloned().collect();
                self.staged_checkpoint(ex, &report);
            }
        }
        report.disks_used = disks_used.into_iter().collect();
        report.waiting_min_bytes = min_room.unwrap_or(0);
        // An earlier run that stopped after recording its drops.
        let view = self.view3()?;
        if !ex.keep_source {
            for p in crate::storages3::leftovers(&view, from_spec.name(), from.as_ref())? {
                if from
                    .delete(&crate::packs::pack_key(&hex::encode(p)))
                    .is_ok()
                {
                    report.leftovers_removed += 1;
                }
            }
        }
        drop(runs);
        drop(to_box);
        if let Some(p) = to_pool {
            // Keep the registry in `config.json` as the pool learned it.
            let disks = p.disks();
            drop(p);
            self.save_pool_disks(to_spec.name(), disks)?;
        }
        report.summary = Self::move_summary(&report, &rec.name);
        Ok(report)
    }
    /// The blocks of `items` re-encrypted from the files on this device
    /// (chunking and encryption are deterministic), each file read once.
    /// Reading for a move does not count as using a file: its access time
    /// is put back, so idle files stay idle.
    pub(super) fn local_ciphertexts<'a>(
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
            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
            for params in [self.chunker_for(size, fk)] {
                if wanted.keys().all(|c| out.contains_key(&wanted[c].object)) {
                    break;
                }
                let Ok(handle) = fs::File::open(path) else {
                    continue;
                };
                let Ok(chunker) = Chunker::new(std::io::BufReader::new(&handle), params) else {
                    continue;
                };
                for piece in chunker {
                    let Ok(piece) = piece else { break };
                    let id = ChunkId::from_bytes(&crypto::keyed_hash(&fk.hash, &piece));
                    let Some(item) = wanted.get(&id) else {
                        continue;
                    };
                    let ct = crate::chunk_seal::seal_chunk(
                        fk,
                        &self.vault.vault_id,
                        &id,
                        item.epoch,
                        &piece,
                    );
                    if let Ok(ct) = ct {
                        if ObjectName::from_bytes(&crypto::hash(&ct)) == item.object {
                            out.insert(item.object.clone(), ct);
                        }
                    }
                }
            }
            if let Some(t) = accessed {
                let _ = file.set_times(fs::FileTimes::new().set_accessed(t));
            }
        }
        out
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
                let Ok(plan) = self.plan_move(rec, &req, &StagedExtras::default()) else {
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
