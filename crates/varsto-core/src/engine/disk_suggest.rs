// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Per-disk bookkeeping and the "next disk to dock" suggestion
//! (`crate::disksuggest`). Everything here comes from the pool index, the
//! ledger view, the repair queue, the fetch plan and `disk-checks.json`: no
//! disk is read, so the service recomputes it after every sync.

use super::*;
use crate::diskconf::{self, DiskConf};
use crate::disksuggest::{self, DiskSuggestions, SuggestSettings};

/// `<home>/state/disk-reminder.json`: when the overdue reminder was last shown.
const REMINDER_FILE: &str = "state/disk-reminder.json";

#[derive(Default, Serialize, Deserialize)]
struct ReminderState {
    #[serde(default)]
    last_notified_utc: i64,
}

impl Engine {
    /// Add the last forced file system check of each disk's partition
    /// (`disks.conf` maps pool and label to the partition), and mark a disk
    /// whose check left errors or failed as failing.
    pub(super) fn add_fsck_facts(&self, rows: &mut [DiskStatus]) {
        let Ok(conf) = DiskConf::load(&self.home) else {
            return;
        };
        let checks = diskconf::checks(&self.home);
        for row in rows.iter_mut() {
            let Some(drive) = conf
                .drives()
                .find(|d| d.pool == row.pool && d.label == row.label)
            else {
                continue;
            };
            let Some(c) = checks.get(&drive.partuuid) else {
                continue;
            };
            if !c.verdict.mountable() {
                row.failing = true;
                let why = c.message(&row.label).unwrap_or_else(|| {
                    format!("its last file system check ({}) failed", c.partition)
                });
                row.failing_reason = Some(match row.failing_reason.take() {
                    Some(before) => format!("{why}; {before}"),
                    None => why,
                });
            }
            row.fsck = Some(c.clone());
        }
    }

    /// Every disk of every pool with its full bookkeeping: space as last
    /// measured, what can be freed, the age of its copy checks, what exists
    /// only on it, what the pool lacks that it could take, what a repair or
    /// the fetch plan needs from it, and its last file system check.
    pub fn disk_report(&mut self) -> Result<Vec<DiskStatus>> {
        let specs = self.pool_specs();
        if specs.is_empty() {
            return Ok(Vec::new());
        }
        let view = self.view3()?;
        let repair = self.repair_queue_objects();
        let plan = self.load_fetch_plan();
        let mut out = Vec::new();
        for spec in specs {
            let name = spec.name().to_string();
            let pool = self.open_pool(&spec)?;
            // Blocks of current files placed on this pool: the packs that
            // hold them there, and the bytes of those it holds on no disk.
            let have = pool.objects();
            let mut current_packs: HashSet<crate::ledger3::PackId> = HashSet::new();
            let mut lacking_bytes = 0u64;
            let mut fetch: BTreeMap<String, Vec<String>> = BTreeMap::new();
            let mut pack_of_object: HashMap<String, String> = HashMap::new();
            for (rec, _) in self.folders() {
                let Ok(rec) = self.with_key(&rec) else {
                    continue; // a locked Strongroom
                };
                let Some(table) = self.folder_table(&rec)? else {
                    continue;
                };
                let t = table.read().unwrap_or_else(|e| e.into_inner());
                let targets = self.write_targets(&rec);
                let Ok(state) = self.load_state(&rec.folder_id) else {
                    continue;
                };
                let mut seen: HashSet<&ObjectName> = HashSet::new();
                for f in state.files.values().filter(|f| !f.deleted) {
                    for c in &f.chunks {
                        if !seen.insert(&c.object) {
                            continue;
                        }
                        let standing = super::data_moves::BlockStanding::of(&view, &t, &c.object);
                        if !targets.wants(&name, Some(&standing)) {
                            continue;
                        }
                        let on_pool = crate::storages3::object_bin(&c.object).ok().and_then(|o| {
                            view.block_places(&o, &*t)
                                .into_iter()
                                .filter(|p| !p.marked)
                                .find(|p| p.storages.contains(&name))
                                .map(|p| p.place.pack)
                        });
                        match on_pool {
                            Some(p)
                                if have.contains_key(&crate::packs::pack_key(&hex::encode(p))) =>
                            {
                                pack_of_object.insert(
                                    chunk_storage_key(&c.object),
                                    crate::packs::pack_key(&hex::encode(p)),
                                );
                                current_packs.insert(p);
                            }
                            // Ciphertext is a little larger than the chunk.
                            _ => lacking_bytes += c.size + 64,
                        }
                    }
                }
            }
            // A fetch plan names blocks; the disk holds their packs.
            for step in plan.iter().flat_map(|p| p.steps.iter()) {
                if step.pool == name && step.state == "pending" {
                    let keys = fetch.entry(step.disk_id.clone()).or_default();
                    for k in &step.objects {
                        let k = pack_of_object.get(k).cloned().unwrap_or_else(|| k.clone());
                        if !keys.contains(&k) {
                            keys.push(k);
                        }
                    }
                }
            }
            let mut sets = crate::storages3::book_sets(&view, &name, &[], Some(&current_packs));
            sets.first_copy_bytes = lacking_bytes;
            // A pack is elsewhere only on a storage that keeps it: a
            // transferrer empties itself.
            let carriers: BTreeSet<String> = self
                .config
                .storages
                .iter()
                .filter(|s| s.is_carrier())
                .map(|s| s.name().to_string())
                .collect();
            sets.elsewhere.retain(|p| {
                let mut id = [0u8; 32];
                hex::decode_to_slice(p, &mut id).is_ok()
                    && view
                        .holders(&id)
                        .iter()
                        .any(|h| *h != name && !carriers.contains(*h))
            });
            let input = sets.input(Some(&repair), Some(&fetch));
            out.extend(pool.statuses_with(Some(&input)));
            let disks = pool.disks();
            drop(pool);
            self.save_pool_disks(&name, disks)?;
        }
        self.add_fsck_facts(&mut out);
        Ok(out)
    }

    /// Rank the disks of every pool (or of `pool` alone) for docking next.
    pub fn disk_suggestions(&mut self) -> Result<DiskSuggestions> {
        self.disk_suggestions_for(None)
    }

    /// `disk_suggestions` for one pool, or all with `None`.
    pub fn disk_suggestions_for(&mut self, pool: Option<&str>) -> Result<DiskSuggestions> {
        if let Some(p) = pool {
            if !self.pool_specs().iter().any(|s| s.name() == p) {
                bail!("no disk pool named {p}");
            }
        }
        let rows: Vec<DiskStatus> = self
            .disk_report()?
            .into_iter()
            .filter(|d| pool.is_none_or(|p| d.pool == p))
            .collect();
        Ok(disksuggest::rank_full(
            &rows,
            util::now_utc(),
            &self.move_waits(),
            &self.mailbox_waits(),
        ))
    }

    pub fn disk_suggest_settings(&self) -> SuggestSettings {
        self.config.disk_suggest.clone()
    }

    pub fn set_disk_suggest_settings(&mut self, s: SuggestSettings) -> Result<()> {
        self.config.disk_suggest = s;
        self.config.save(&self.home)
    }

    /// The weekly reminder: when it is on, a disk that is away has copies
    /// past `verify_after_days` and the last reminder is a week old, the
    /// text to show (and the reminder is recorded as shown).
    pub fn disk_overdue_reminder(&self, s: &DiskSuggestions, now: i64) -> Option<String> {
        if !self.config.disk_suggest.notify_overdue || s.overdue.is_empty() {
            return None;
        }
        let path = self.home.join(REMINDER_FILE);
        let mut st: ReminderState = util::read_json_or_default(&path).unwrap_or_default();
        if now - st.last_notified_utc < disksuggest::REMIND_EVERY_SECS {
            return None;
        }
        let next = s
            .top
            .as_ref()
            .filter(|t| s.overdue.contains(&t.label))
            .or_else(|| s.ranked.iter().find(|r| s.overdue.contains(&r.label)))?;
        st.last_notified_utc = now;
        if util::write_json(&path, &st).is_err() {
            return None;
        }
        Some(format!(
            "{} is due for a check. Next time you are near it: {}",
            next.summary, next.command
        ))
    }
}
