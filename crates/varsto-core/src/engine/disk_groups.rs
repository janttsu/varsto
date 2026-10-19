// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Disk groups: a placement rule for disk pools. Every disk of a pool has a
//! place (its own, or the pool's), and a pool can ask for `copies` copies of
//! every object on disks in different places ("two copies on disks kept in
//! different places"). A push writes the extra copies when disks of other
//! places are attached; `disk add` and `disk check` fill a disk with what its
//! place still lacks; policies count every disk copy at its disk's place,
//! and a folder whose blocks fall short of the rule is reported.

use super::*;
use crate::policy::{PolicyReport, PolicyState};

/// One pool's disk group rule and how far its objects meet it.
#[derive(Clone, Debug, Serialize)]
pub struct DiskGroupStatus {
    pub pool: String,
    /// Copies of every object on disks in different places (1: no rule).
    pub copies: u32,
    /// Place -> labels of the disks kept there.
    pub places: BTreeMap<String, Vec<String>>,
    /// Objects (and bytes) held in fewer places than `copies`.
    pub objects_short: u64,
    pub bytes_short: u64,
    /// Why the rule cannot be met as configured, if it cannot.
    pub warnings: Vec<String>,
}

impl Engine {
    /// Add to a folder's policy report the blocks that a pool's disk group
    /// rule is not met for: blocks (`objects`, of the folder's current
    /// files) whose packs on the pool are on disks in fewer places than the
    /// rule asks (spec section 77.9, "a disk group rule counts the places
    /// that hold the pack").
    pub(super) fn disk_group_findings(
        &self,
        objects: &BTreeMap<ObjectName, u64>,
        view: &crate::ledger3::LedgerView,
        table: &crate::blockmap::MapTable,
        pools: &BTreeMap<String, PoolStorage>,
        report: &mut PolicyReport,
    ) {
        for (name, pool) in pools.iter().filter(|(_, p)| p.copies() > 1) {
            let mut short = 0u64;
            for object in objects.keys() {
                let Ok(obj) = crate::storages3::object_bin(object) else {
                    continue;
                };
                let packs: Vec<crate::ledger3::PackId> =
                    crate::storages3::block_copy_details(view, table, &obj)
                        .into_iter()
                        .filter(|c| c.storage == *name)
                        .map(|c| c.pack)
                        .collect();
                let Some(pack) = packs.first() else {
                    continue;
                };
                let places = pool
                    .places_of(&crate::packs::pack_key(&hex::encode(pack)))
                    .len() as u32;
                if places < pool.copies() {
                    short += 1;
                }
            }
            if short > 0 {
                report.reasons.push(format!(
                    "{short} chunks have fewer than {} copies on disks of pool {name} in different places (attach a disk kept elsewhere and run `varsto disk check <label>`)",
                    pool.copies()
                ));
                report.state = PolicyState::Violated;
            }
        }
    }

    /// Every pool's disk group rule and standing.
    pub fn disk_groups(&mut self) -> Result<Vec<DiskGroupStatus>> {
        let mut out = Vec::new();
        for spec in self.pool_specs() {
            let pool = self.open_pool(&spec)?;
            let mut places: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for d in pool.disks().iter().filter(|d| !d.retired) {
                places
                    .entry(pool.disk_place(d))
                    .or_default()
                    .push(d.label.clone());
            }
            let (objects_short, bytes_short) = pool.group_shortfall();
            let mut warnings = Vec::new();
            if (places.len() as u32) < pool.copies() {
                warnings.push(format!(
                    "the rule asks for {} places but the pool's disks are kept in {}: add a disk kept elsewhere (varsto disk add <mount> --pool {} --label <label> --place <place>) or set a disk's place (varsto disk place <label> <place>)",
                    pool.copies(),
                    places.len(),
                    spec.name()
                ));
            }
            out.push(DiskGroupStatus {
                pool: spec.name().to_string(),
                copies: pool.copies(),
                places,
                objects_short,
                bytes_short,
                warnings,
            });
        }
        Ok(out)
    }

    /// Set a pool's disk group rule: `copies` copies of every object on
    /// disks in different places (1 turns it off). Disks are filled to it at
    /// the next `disk check`.
    pub fn set_pool_copies(&mut self, pool_name: &str, copies: u32) -> Result<()> {
        if !(1..=16).contains(&copies) {
            bail!("copies must be between 1 and 16");
        }
        let Some(StorageSpec::Pool { copies: c, .. }) = self
            .config
            .storages
            .iter_mut()
            .find(|s| s.name() == pool_name)
        else {
            bail!("no disk pool named {pool_name}");
        };
        *c = copies;
        self.config.save(&self.home)
    }

    /// Set the place a disk is kept at ("" returns it to the pool's place).
    pub fn set_disk_place(&mut self, label: &str, place: &str) -> Result<()> {
        let (spec, pool, disk) = self.find_disk(label)?;
        pool.set_disk_place(&disk.id, place)?;
        let disks = pool.disks();
        drop(pool);
        self.save_pool_disks(spec.name(), disks)
    }

    /// Like `disk_add`, for a disk kept at `place` ("" for the pool's place).
    pub fn disk_add_at(
        &mut self,
        mount: &Path,
        pool_name: &str,
        label: &str,
        place: &str,
    ) -> Result<DiskAddReport> {
        let (report, fill) = self.disk_add_with(mount, pool_name, label, place, &mut |_| {})?;
        if let Some(why) = fill.failed {
            bail!(why);
        }
        Ok(report)
    }
}
