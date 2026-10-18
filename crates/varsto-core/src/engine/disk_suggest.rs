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
        let view = self.view()?;
        let repair = self.repair_queue_objects();
        let plan = self.load_fetch_plan();
        let carriers: BTreeSet<String> = self
            .config
            .storages
            .iter()
            .filter(|s| s.is_carrier())
            .map(|s| s.name().to_string())
            .collect();
        let mut out = Vec::new();
        for spec in specs {
            let name = spec.name().to_string();
            let pool = self.open_pool(&spec)?;
            // What the ledger still wants on this pool, and what has a copy elsewhere.
            let mut wanted: HashSet<String> = HashSet::new();
            let mut elsewhere: HashSet<String> = HashSet::new();
            for r in view.chunks.values() {
                let obj = r.object.as_str().to_ascii_lowercase();
                if r.storages
                    .keys()
                    .any(|s| s != &name && !carriers.contains(s))
                {
                    elsewhere.insert(obj.clone());
                }
                if !r.dropped_from(&name) {
                    wanted.insert(obj);
                }
            }
            // The disks hold packs: a pack is wanted when a block in it is,
            // elsewhere when every block in it is.
            super::pack_upkeep::with_pack_ids(&view, &name, &mut wanted, false);
            super::pack_upkeep::with_pack_ids(&view, &name, &mut elsewhere, true);
            let mut repair = repair.clone();
            super::pack_upkeep::with_pack_ids(&view, &name, &mut repair, false);
            // Blocks of current files placed on this pool: the ones it holds
            // on no disk, and every key (further copies under a disk group rule).
            let have = pool.objects();
            let mut current: HashSet<String> = HashSet::new();
            let mut first_copy_bytes = 0u64;
            for (rec, _) in self.folders() {
                let Ok(rec) = self.with_key(&rec) else {
                    continue; // a locked Strongroom
                };
                let targets = self.write_targets(&rec);
                let Ok(state) = self.load_state(&rec.folder_id) else {
                    continue;
                };
                for f in state.files.values().filter(|f| !f.deleted) {
                    for c in &f.chunks {
                        let record = view.locate(&rec.folder_id, &c.chunk);
                        if !targets.wants(&name, record) {
                            continue;
                        }
                        let key = record
                            .map(|r| super::pack_upkeep::held_key(r, &name))
                            .unwrap_or_else(|| chunk_storage_key(&c.object));
                        if !have.contains_key(&key) && !current.contains(&key) {
                            // Ciphertext is a little larger than the chunk.
                            first_copy_bytes += c.size + 64;
                        }
                        current.insert(key);
                    }
                }
            }
            let mut fetch: BTreeMap<String, Vec<String>> = BTreeMap::new();
            // A fetch plan names blocks; the disk holds their packs.
            let mut pack_key_of: HashMap<String, String> = HashMap::new();
            for r in view.chunks.values() {
                if let Some(p) = r.storages.get(&name).and_then(|l| l.pack.as_ref()) {
                    pack_key_of.insert(
                        chunk_storage_key(&r.object),
                        crate::packs::pack_key(&p.pack),
                    );
                }
            }
            for step in plan.iter().flat_map(|p| p.steps.iter()) {
                if step.pool == name && step.state == "pending" {
                    let keys = fetch.entry(step.disk_id.clone()).or_default();
                    for k in &step.objects {
                        let k = pack_key_of.get(k).cloned().unwrap_or_else(|| k.clone());
                        if !keys.contains(&k) {
                            keys.push(k);
                        }
                    }
                }
            }
            let input = pool::BookInput {
                wanted: Some(&wanted),
                elsewhere: Some(&elsewhere),
                repair: Some(&repair),
                fetch: Some(&fetch),
                first_copy_bytes,
                current: Some(&current),
            };
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
