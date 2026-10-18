// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The mailbox for offline pool disks (`docs/spec/alpha-0-format.md`
//! section 78).
//!
//! A pool disk A that is away most of the time may hold the only copy of
//! blocks that another disk B (of another place, or of another pool) or
//! another storage should hold too, and only one disk fits in the dock at a
//! time. The device with the dock is the mailbox: while A is docked it reads
//! the objects that a target which is away needs into a durable outbox
//! (`<home>/outbox`, the ciphertext object exactly as stored, checked
//! against its name), and when B is docked it writes them there, reads them
//! back and records them. A staged object is *in transit*: it is never a
//! copy for a policy, and it is the first thing removed when the device
//! needs its space back.
//!
//! Three kinds of tasks (`crate::mailbox::TaskKind`):
//! - *group*: a pack on a pool whose disk group rule wants a copy in a place
//!   that only away disks are in; delivered with `add_copy_on_disk`;
//! - *storage*: a block whose folder's copy rules are not kept and that a
//!   storage of this device should take, which cannot be written now (a
//!   pool without a docked disk with room); written as packs, read back and
//!   claimed (`chunk_stored`), like forwarding (section 70);
//! - *move*: a block of an open move job (section 59) from a pool whose
//!   target cannot take it now; the job itself reads it from the outbox
//!   later and drops the source copy by its own rules (only once the target
//!   copy is written and checked).
//!
//! Tasks are per-device state (`state/mailbox.json`). Other devices learn
//! what this one holds from its published list,
//! `vault/mailbox/<device>/<utc>.enc` (sealed under the device registry
//! key): they do not stage the same objects again, show "staged on
//! <device>", and a device that can write a storage task's target takes the
//! block from this device over peer-to-peer (the outbox is served like the
//! block cache). While staging, a device holds a lease
//! (`vault/mailbox-leases/<slot>.json`, as forwarding does), so two dock
//! hosts do not stage at the same moment.

use super::*;
use crate::freespace;
use crate::mailbox::{
    Board, BoardEntry, MailboxGroup, MailboxReport, MailboxSettings, MailboxState, MailboxStatus,
    MailboxWait, Outbox, RunLock, Staged, Task, TaskKind, TaskState,
};
use crate::policy::PolicyState;
use crate::staged_move::{self as jobs, JobState};
use std::sync::Arc;

/// Published lists of staged objects, one per device.
const BOARD_PREFIX: &str = "vault/mailbox/";
/// The lease a device holds while it stages.
const LEASE_DIR: &str = "vault/mailbox-leases/";
/// A list older than this belongs to a device that went away: ignored.
const BOARD_TTL_SECS: i64 = 30 * 86_400;
/// A list with staged objects is published again at least this often.
const BOARD_REFRESH_SECS: i64 = 86_400;
/// Blocks collected per target before they are written as a pack.
const DELIVER_BUFFER: u64 = crate::packs::HOT_TARGET as u64;
/// The service's budget per run.
const SERVICE_MAX_BYTES: u64 = 4 << 30;
const SERVICE_MAX_OBJECTS: u64 = 20_000;

/// How much one run may read into the outbox and write to targets.
#[derive(Clone, Debug)]
pub struct MailboxOptions {
    /// Stop staging after this many bytes or objects (the first always goes).
    pub max_bytes: u64,
    pub max_objects: u64,
}

impl MailboxOptions {
    /// `varsto mailbox run`: everything there is.
    pub fn manual() -> Self {
        MailboxOptions {
            max_bytes: u64::MAX,
            max_objects: u64::MAX,
        }
    }
    /// The background service: 4 GiB and 20 000 objects a run; it runs
    /// again at once while work is left.
    pub fn service() -> Self {
        MailboxOptions {
            max_bytes: SERVICE_MAX_BYTES,
            max_objects: SERVICE_MAX_OBJECTS,
        }
    }
}

fn board_aad(vault: &crate::ids::VaultId, device: &DeviceId) -> Vec<u8> {
    crypto::aad(
        "mailbox-board",
        &[vault.as_str().as_bytes(), device.as_str().as_bytes()],
    )
}

/// What a folder's copy rules need, for the storage tasks.
struct FolderNeeds {
    rec: FolderRecord,
    rules: Policy,
    targets: data_moves::WriteTargets,
    /// Blocks of current files (from the folder state on this device).
    current: HashSet<ChunkId>,
}

/// The pools of this device, each opened once for the whole run (two
/// instances of one pool would overwrite each other's index).
type Pools = BTreeMap<String, (StorageSpec, Arc<PoolStorage>)>;

/// Open move jobs from a pool, with the blocks each still has to move.
type JobItems = BTreeMap<String, (jobs::MoveJob, HashSet<(FolderId, ChunkId)>)>;
/// Pack id -> the blocks in it (folder, chunk, object).
type PackBlocks = HashMap<String, Vec<(FolderId, ChunkId, ObjectName)>>;
/// (pool, role, disk ids) of a wait, and (bytes, the other ends, keys counted).
type WaitKey = (String, String, Vec<String>);
type WaitTally = (u64, BTreeSet<String>, BTreeSet<String>);
/// Objects, bytes, target name and target disks held on another device.
type OtherTally = (u64, u64, String, Vec<String>);

/// One block collected for a storage target.
struct Outgoing {
    ids: Vec<String>,
    folder: FolderId,
    chunk: ChunkId,
    object: ObjectName,
    bytes: Vec<u8>,
    from_peer: bool,
}

impl Engine {
    // ----- settings and status -------------------------------------------------

    pub fn mailbox_settings(&self) -> MailboxSettings {
        self.config.mailbox.clone()
    }

    pub fn set_mailbox_settings(&mut self, settings: MailboxSettings) -> Result<()> {
        self.config.mailbox = settings;
        self.config.save(&self.home)
    }

    /// Whether a run would find something new: the docked disks differ from
    /// the last run's, the last run stopped at its budget, or (after a sync)
    /// always, since other devices' lists may have changed.
    pub fn mailbox_due(&self, after_sync: bool) -> bool {
        if !self.config.mailbox.enabled || self.vault.member {
            return false;
        }
        if after_sync {
            return true;
        }
        let st = MailboxState::load(&self.home);
        st.disks_sig != self.mailbox_disks_sig()
            || st.last.as_ref().is_some_and(|r| {
                r.waiting_for_source > 0 && r.room_needed_bytes == 0 && r.staged > 0
            })
    }

    /// The docked pool disks, as a signature.
    fn mailbox_disks_sig(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        for spec in self.pool_specs() {
            if let Ok(p) = self.open_pool(&spec) {
                for d in p.disks() {
                    if p.mount_of(&d.id).is_some() {
                        parts.push(format!("{}:{}", spec.name(), d.id));
                    }
                }
            }
        }
        parts.sort();
        parts.join(",")
    }

    /// The staged object at `key` (`chunks/<xx>/<object>`, `packs/<xx>/<id>`),
    /// checked against its name: a source for move jobs and disk fills.
    pub(super) fn mailbox_object(&self, key: &str) -> Option<Vec<u8>> {
        match Outbox::new(&self.home).get(key) {
            Staged::Good(b) => Some(b),
            _ => None,
        }
    }

    /// Where the device directory's disk stands: (free, bytes the rule keeps).
    fn mailbox_space(&self) -> Option<(u64, u64)> {
        let ob = Outbox::new(&self.home);
        let space = freespace::space_at(ob.root())?;
        Some((space.free, self.config.mailbox.keep_free_bytes(space.total)))
    }

    /// What `varsto mailbox` shows.
    pub fn mailbox_status(&self) -> MailboxStatus {
        let st = MailboxState::load(&self.home);
        let settings = &self.config.mailbox;
        let space = self.mailbox_space();
        let (held_objects, held_bytes) = st.held();
        let waiting_bytes = st
            .tasks
            .values()
            .filter(|t| t.state == TaskState::WaitingForSource)
            .map(|t| t.size)
            .sum();
        MailboxStatus {
            enabled: settings.enabled,
            keep_free: settings.limits().iter().map(|m| m.setting()).collect(),
            keep_free_text: settings.describe_keep_free(),
            free_bytes: space.map(|s| s.0),
            keep_free_bytes: space.map(|s| s.1),
            held_objects,
            held_bytes,
            waiting_bytes,
            groups: self.mailbox_groups(&st),
            last: st.last.clone(),
            last_error: st.last_error.clone(),
            total_delivered: st.total_delivered,
            total_delivered_bytes: st.total_delivered_bytes,
        }
    }

    /// Minutes of reading `bytes` from a docked disk (at the dock speed of
    /// the disk fetch settings, section 34), at least one.
    fn read_minutes(&self, bytes: u64) -> u64 {
        let secs = self.config.disk_fetch.disk_secs(bytes);
        ((secs / 60.0).ceil() as u64).max(1)
    }

    /// Is the disk `disk_id` of `pool` docked now?
    fn disk_docked(&self, pool: &str, disk_id: &str) -> bool {
        self.config
            .storages
            .iter()
            .find(|s| s.name() == pool && s.is_data_only())
            .and_then(|s| self.open_pool(s).ok())
            .is_some_and(|p| p.mount_of(disk_id).is_some())
    }

    /// The status lines: tasks with the same source, target and state
    /// together, then what other devices hold.
    fn mailbox_groups(&self, st: &MailboxState) -> Vec<MailboxGroup> {
        let room_short = st.last.as_ref().is_some_and(|r| r.room_needed_bytes > 0);
        let mut by: BTreeMap<(String, String, String, String, String), MailboxGroup> =
            BTreeMap::new();
        let mut keys: BTreeMap<(String, String, String, String, String), BTreeSet<String>> =
            BTreeMap::new();
        for t in st.tasks.values() {
            let state = match t.state {
                TaskState::Held => "held",
                TaskState::WaitingForSource => "waiting_for_source",
            };
            let k = (
                t.kind.label().to_string(),
                t.pool.clone(),
                t.source_label.clone(),
                t.target_text(),
                state.to_string(),
            );
            let seen = keys.entry(k.clone()).or_default();
            let g = by.entry(k).or_insert_with(|| MailboxGroup {
                kind: t.kind.label().to_string(),
                pool: t.pool.clone(),
                source: t.source_label.clone(),
                target: t.target_text(),
                target_name: t.target.clone(),
                target_disks: t.target_disks.clone(),
                state: state.to_string(),
                held_on: "this device".to_string(),
                here: true,
                source_attached: self.disk_docked(&t.pool, &t.source_disk),
                ..Default::default()
            });
            if seen.insert(t.key.clone()) {
                g.objects += 1;
                g.bytes += t.size;
            }
        }
        let mut out: Vec<MailboxGroup> = by
            .into_values()
            .map(|mut g| {
                let size = util::human_bytes(g.bytes);
                g.text = if g.state == "held" {
                    format!(
                        "{size} from disk «{}» waiting for {} (staged on this device)",
                        g.source, g.target
                    )
                } else if g.source_attached {
                    let mins = self.read_minutes(g.bytes);
                    g.keep_attached_minutes = Some(mins);
                    let mut s = format!(
                        "{size} still to be read from disk «{}» for {}: keep it attached for about {mins} min",
                        g.source, g.target
                    );
                    if room_short {
                        s += " (this device needs more free space for the outbox, or dock the target first)";
                    }
                    s
                } else {
                    format!(
                        "{size} waiting for disk «{}» to be docked (to go to {})",
                        g.source, g.target
                    )
                };
                g
            })
            .collect();
        // Held on other devices, by device and target.
        let mut other: BTreeMap<(String, String, String), OtherTally> = BTreeMap::new();
        for (dev, e) in &st.elsewhere {
            let t = Task {
                kind: e.kind,
                key: e.key.clone(),
                size: e.size,
                pool: e.pool.clone(),
                source_disk: String::new(),
                source_label: e.source_label.clone(),
                target: e.target.clone(),
                places: e.places.clone(),
                target_disks: e.target_disks.clone(),
                folder: None,
                chunk: None,
                object: None,
                job: None,
                state: TaskState::Held,
                created_utc: 0,
                staged_utc: 0,
                updated_utc: 0,
            };
            let g = other
                .entry((dev.clone(), e.source_label.clone(), t.target_text()))
                .or_insert((0, 0, e.target.clone(), e.target_disks.clone()));
            g.0 += 1;
            g.1 += e.size;
        }
        for ((dev, source, target), (objects, bytes, target_name, disks)) in other {
            out.push(MailboxGroup {
                kind: "elsewhere".to_string(),
                pool: String::new(),
                source: source.clone(),
                target: target.clone(),
                target_name,
                target_disks: disks,
                state: "held".to_string(),
                held_on: dev.clone(),
                here: false,
                objects,
                bytes,
                source_attached: false,
                keep_attached_minutes: None,
                text: format!(
                    "{} from disk «{source}» waiting for {target} (staged on {dev})",
                    util::human_bytes(bytes)
                ),
            });
        }
        out
    }

    /// What the disk suggestion (section 40) learns: disks whose docking
    /// writes staged objects, and disks that objects wait to be read from.
    pub fn mailbox_waits(&self) -> Vec<MailboxWait> {
        let st = MailboxState::load(&self.home);
        let mut pools: BTreeMap<String, PoolStorage> = BTreeMap::new();
        for spec in self.pool_specs() {
            if let Ok(p) = self.open_pool(&spec) {
                pools.insert(spec.name().to_string(), p);
            }
        }
        // (pool, role, disks) -> (bytes, sources or targets, keys)
        let mut acc: BTreeMap<WaitKey, WaitTally> = BTreeMap::new();
        let mut add =
            |pool: &str, role: &str, disks: Vec<String>, size: u64, other: String, key: &str| {
                if disks.is_empty() {
                    return;
                }
                let e = acc
                    .entry((pool.to_string(), role.to_string(), disks))
                    .or_default();
                if e.2.insert(key.to_string()) {
                    e.0 += size;
                }
                e.1.insert(other);
            };
        let target_ids = |pool: &str, labels: &[String]| -> Vec<String> {
            let Some(p) = pools.get(pool) else {
                return Vec::new();
            };
            let mut ids: Vec<String> = labels
                .iter()
                .filter_map(|l| p.disk_by_label(l))
                .filter(|d| !d.retired)
                .map(|d| d.id)
                .collect();
            ids.sort();
            ids
        };
        for t in st.tasks.values() {
            let target_pool = match t.kind {
                TaskKind::Group => t.pool.clone(),
                _ => t.target.clone(),
            };
            match t.state {
                TaskState::Held => add(
                    &target_pool,
                    "target",
                    target_ids(&target_pool, &t.target_disks),
                    t.size,
                    format!("«{}»", t.source_label),
                    &t.key,
                ),
                TaskState::WaitingForSource => add(
                    &t.pool,
                    "source",
                    vec![t.source_disk.clone()],
                    t.size,
                    t.target_text(),
                    &t.key,
                ),
            }
        }
        // Blocks another device holds for a storage of this device: docking
        // a disk of that pool here brings them over peer-to-peer.
        for (dev, e) in &st.elsewhere {
            if e.kind == TaskKind::Storage && pools.contains_key(&e.target) {
                add(
                    &e.target,
                    "target",
                    target_ids(&e.target, &e.target_disks),
                    e.size,
                    format!("«{}» (staged on {dev})", e.source_label),
                    &e.key,
                );
            }
        }
        // Move jobs that wait for their source disk.
        for j in jobs::list_active(&self.home) {
            let Some(w) = j.waiting.as_ref().filter(|w| w.kind == "source") else {
                continue;
            };
            let (Some(label), Some(p)) = (w.disk.as_ref(), pools.get(&j.from)) else {
                continue;
            };
            if let Some(d) = p.disk_by_label(label) {
                add(
                    &j.from,
                    "source",
                    vec![d.id],
                    j.bytes_remaining,
                    format!("«{}» (move of {})", j.to, j.folder),
                    &j.id,
                );
            }
        }
        acc.into_iter()
            .map(|((pool, role, disk_ids), (bytes, others, _))| {
                let others: Vec<String> = others.into_iter().collect();
                let minutes = self.read_minutes(bytes);
                let text = if role == "target" {
                    format!(
                        "{} staged from disk {} waits for it: docking it writes them",
                        util::human_bytes(bytes),
                        others.join(", ")
                    )
                } else {
                    format!(
                        "{} to copy from it to {} (about {minutes} min of reading)",
                        util::human_bytes(bytes),
                        others.join(", ")
                    )
                };
                MailboxWait {
                    pool,
                    disk_ids,
                    role,
                    bytes,
                    minutes,
                    text,
                }
            })
            .collect()
    }

    /// Blocks of `folder` (of `chunks`) that are in transit through a
    /// mailbox, here or on another device: (blocks, bytes, sentence).
    pub(super) fn mailbox_in_transit(
        &self,
        view: &LedgerView,
        folder: &FolderId,
        chunks: &BTreeSet<ChunkId>,
    ) -> Option<(u64, u64, String)> {
        let st = MailboxState::load(&self.home);
        if st.tasks.is_empty() && st.elsewhere.is_empty() {
            return None;
        }
        let mut found: BTreeMap<ChunkId, u64> = BTreeMap::new();
        let mut targets: BTreeSet<String> = BTreeSet::new();
        let mut holders: BTreeSet<String> = BTreeSet::new();
        let mut by_pack: BTreeMap<String, PackBlocks> = BTreeMap::new();
        let mut consider = |kind: TaskKind,
                            key: &str,
                            pool: &str,
                            f: Option<&FolderId>,
                            c: Option<&ChunkId>,
                            target: String,
                            holder: String| {
            let mut hit = false;
            match (kind, f, c) {
                (TaskKind::Group, _, _) => {
                    let packs = by_pack
                        .entry(pool.to_string())
                        .or_insert_with(|| super::pack_upkeep::blocks_by_pack(view, pool));
                    let id = key.rsplit('/').next().unwrap_or("");
                    for (bf, bc, _) in packs.get(id).into_iter().flatten() {
                        if bf == folder && chunks.contains(bc) {
                            let size = view.locate(bf, bc).map(|r| r.size).unwrap_or(0);
                            found.insert(bc.clone(), size);
                            hit = true;
                        }
                    }
                }
                (_, Some(f), Some(c)) if f == folder && chunks.contains(c) => {
                    let size = view.locate(f, c).map(|r| r.size).unwrap_or(0);
                    found.insert(c.clone(), size);
                    hit = true;
                }
                _ => {}
            }
            if hit {
                targets.insert(target);
                holders.insert(holder);
            }
        };
        for t in st.tasks.values().filter(|t| t.state == TaskState::Held) {
            consider(
                t.kind,
                &t.key,
                &t.pool,
                t.folder.as_ref(),
                t.chunk.as_ref(),
                t.target_text(),
                "this device".to_string(),
            );
        }
        for (dev, e) in &st.elsewhere {
            let t = BoardEntry::clone(e);
            let text = Task {
                kind: t.kind,
                key: t.key.clone(),
                size: t.size,
                pool: t.pool.clone(),
                source_disk: String::new(),
                source_label: t.source_label.clone(),
                target: t.target.clone(),
                places: t.places.clone(),
                target_disks: t.target_disks.clone(),
                folder: None,
                chunk: None,
                object: None,
                job: None,
                state: TaskState::Held,
                created_utc: 0,
                staged_utc: 0,
                updated_utc: 0,
            }
            .target_text();
            consider(
                t.kind,
                &t.key,
                &t.pool,
                t.folder.as_ref(),
                t.chunk.as_ref(),
                text,
                dev.clone(),
            );
        }
        if found.is_empty() {
            return None;
        }
        let n = found.len() as u64;
        let bytes: u64 = found.values().sum();
        Some((
            n,
            bytes,
            format!(
                "{n} block{} ({}) in transit to {} (staged on {}); staged copies do not count",
                if n == 1 { "" } else { "s" },
                util::human_bytes(bytes),
                targets.into_iter().collect::<Vec<_>>().join(", "),
                holders.into_iter().collect::<Vec<_>>().join(", ")
            ),
        ))
    }

    // ----- free space ----------------------------------------------------------

    /// Give the device its space back: while the device directory's disk is
    /// below the mailbox's free-space rule, or a place on the same disk is
    /// short of space (section 53), staged objects are removed, the last
    /// staged first. Their tasks wait for the source disk again; nothing
    /// else is ever removed for this. Returns (objects, bytes) removed.
    pub fn mailbox_make_room(&mut self) -> (u64, u64) {
        let mut st = MailboxState::load(&self.home);
        let mut report = MailboxReport::default();
        self.mailbox_evict(&mut st, &mut report);
        if report.evicted > 0 {
            let _ = st.save(&self.home);
            log::info!(
                "mailbox: removed {} staged object(s) ({}) to give this device its space back",
                report.evicted,
                util::human_bytes(report.evicted_bytes)
            );
        }
        (report.evicted, report.evicted_bytes)
    }

    fn mailbox_evict(&self, st: &mut MailboxState, report: &mut MailboxReport) {
        let ob = Outbox::new(&self.home);
        let Some(space) = freespace::space_at(ob.root()) else {
            return;
        };
        let keep = self.config.mailbox.keep_free_bytes(space.total);
        // A place on the same disk that stopped writing for lack of space.
        let short: Vec<freespace::LowSpace> = freespace::short_places()
            .into_iter()
            .filter(|l| same_volume(&l.path, ob.root()))
            .collect();
        let mut free = space.free;
        let wanted = |free: u64| -> bool {
            free < keep
                || short
                    .iter()
                    .any(|l| free.saturating_sub(l.needed) < l.limit)
        };
        if !wanted(free) {
            return;
        }
        let mut held: Vec<(i64, String, u64)> = Vec::new();
        let mut seen = BTreeSet::new();
        for t in st.tasks.values().filter(|t| t.state == TaskState::Held) {
            if seen.insert(t.key.clone()) {
                held.push((t.staged_utc, t.key.clone(), t.size));
            }
        }
        held.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        for (_, key, size) in held {
            if !wanted(free) {
                break;
            }
            ob.remove(&key);
            for t in st.tasks.values_mut().filter(|t| t.key == key) {
                t.state = TaskState::WaitingForSource;
                t.staged_utc = 0;
                t.updated_utc = util::now_utc();
            }
            report.evicted += 1;
            report.evicted_bytes += size;
            let measured = freespace::space_at(ob.root()).map(|s| s.free).unwrap_or(0);
            free = (free + size).max(measured);
        }
    }

    // ----- running -------------------------------------------------------------

    /// One mailbox run: finish what is done, stage what the docked disks
    /// hold for targets that are away, write held objects to the targets
    /// that are docked, take blocks other devices hold for storages here,
    /// and publish what this device holds.
    pub fn mailbox_run(&mut self, opts: &MailboxOptions) -> Result<MailboxReport> {
        let out = crate::logged_op!("mailbox", "", { self.mailbox_run_inner(opts) });
        self.finish_storages();
        let mut st = MailboxState::load(&self.home);
        match &out {
            Ok(r) => {
                st.last = Some(r.clone());
                st.last_error = None;
            }
            Err(e) => st.last_error = Some(format!("{e:#}")),
        }
        st.save(&self.home)?;
        out
    }

    fn mailbox_run_inner(&mut self, opts: &MailboxOptions) -> Result<MailboxReport> {
        let mut report = MailboxReport {
            started_utc: util::now_utc(),
            enabled: self.config.mailbox.enabled,
            ..Default::default()
        };
        if !report.enabled || self.vault.member {
            report.finished_utc = util::now_utc();
            return Ok(report);
        }
        self.ensure_active()?;
        self.ensure_ledger_writable()?;
        if self.forked_self {
            bail!("this device's ledger is forked; it must be re-enrolled as a new device");
        }
        let Some(lock) = RunLock::acquire(&self.home) else {
            report
                .notes
                .push("another mailbox run is in progress on this device".to_string());
            report.finished_utc = util::now_utc();
            return Ok(report);
        };
        self.pull_ledger_once()?;
        let mut st = MailboxState::load(&self.home);
        st.disks_sig = self.mailbox_disks_sig();
        let ob = Outbox::new(&self.home);
        let now = util::now_utc();

        // Held tasks whose file is gone wait for their source again; files
        // no task holds are removed.
        let files: BTreeMap<String, u64> = ob.list().into_iter().collect();
        for t in st.tasks.values_mut() {
            if t.state == TaskState::Held && !files.contains_key(&t.key) {
                t.state = TaskState::WaitingForSource;
                t.staged_utc = 0;
            }
        }
        let referenced: BTreeSet<String> = st.tasks.values().map(|t| t.key.clone()).collect();
        for key in files.keys().filter(|k| !referenced.contains(*k)) {
            ob.remove(key);
        }
        self.mailbox_evict(&mut st, &mut report);

        let meta = self.metadata_storages(false).unwrap_or_default();
        st.elsewhere = self.read_mailbox_boards(&meta, now);
        let pools: Pools = self
            .pool_specs()
            .into_iter()
            .filter_map(|s| {
                let p = self.open_pool(&s).ok()?;
                Some((s.name().to_string(), (s, Arc::new(p))))
            })
            .collect();
        let any_docked = pools
            .values()
            .any(|(_, p)| p.disks().iter().any(|d| p.mount_of(&d.id).is_some()));
        if st.tasks.is_empty() && st.elsewhere.is_empty() && !any_docked {
            self.publish_mailbox_board(&mut st, &meta, now);
            st.save(&self.home)?;
            report.finished_utc = util::now_utc();
            return Ok(report);
        }

        let view = self.view()?;
        let mut ctx = self.policy_ctx();
        let needs = self.mailbox_folder_needs();
        // Other storages of this device that a storage task may write.
        let mut stores: BTreeMap<String, Box<dyn Storage>> = BTreeMap::new();
        let mut failed: BTreeSet<String> = BTreeSet::new();
        for spec in self.config.storages.clone() {
            if spec.is_cold() || spec.is_carrier() || spec.is_data_only() {
                continue;
            }
            match self.open_spec(&spec) {
                Ok(b) => {
                    stores.insert(spec.name().to_string(), b);
                }
                Err(_) => {
                    failed.insert(spec.name().to_string());
                }
            }
        }
        let gate = self.quota_gate(&view);
        // Open move jobs from a pool, with the blocks they still have to move.
        let mut job_items: JobItems = BTreeMap::new();
        for j in jobs::list_active(&self.home) {
            if j.state != JobState::Open || !pools.contains_key(&j.from) {
                continue;
            }
            match self.move_job_pending(&j) {
                Ok(items) => {
                    job_items.insert(j.id.clone(), (j, items));
                }
                Err(e) => log::debug!("mailbox: move job {} not planned: {e:#}", j.id),
            }
        }

        // 1. What the docked disks hold that a target needs.
        let fresh = self.mailbox_plan(&view, &mut ctx, &needs, &pools, &job_items);
        let fresh_ids: BTreeSet<String> = fresh.iter().map(|t| t.id()).collect();
        for t in fresh {
            match st.tasks.get_mut(&t.id()) {
                Some(old) => {
                    if old.state == TaskState::WaitingForSource {
                        old.source_disk = t.source_disk.clone();
                        old.source_label = t.source_label.clone();
                    }
                    old.places = t.places.clone();
                    old.target_disks = t.target_disks.clone();
                    old.size = t.size;
                }
                None => {
                    st.tasks.insert(t.id(), t);
                }
            }
        }

        // 2. Finish what is done or no longer needed.
        let ids: Vec<String> = st.tasks.keys().cloned().collect();
        for id in ids {
            let t = &st.tasks[&id];
            if !self.mailbox_task_needed(t, &view, &mut ctx, &needs, &pools, &job_items) {
                st.tasks.remove(&id);
                report.finished += 1;
            }
        }

        // 3. Stage what a target that is away needs, while its disk is docked.
        let elsewhere_keys: HashMap<String, String> = st
            .elsewhere
            .iter()
            .map(|(d, e)| (e.key.clone(), d.clone()))
            .collect();
        let mut candidates: Vec<String> = Vec::new();
        for (id, t) in &st.tasks {
            if t.state != TaskState::WaitingForSource || !fresh_ids.contains(id) {
                continue;
            }
            if self.mailbox_target_ready(t, &pools, &stores, &failed, &gate) {
                continue; // written directly below
            }
            if elsewhere_keys.contains_key(&t.key) {
                report.held_elsewhere += 1;
                continue;
            }
            candidates.push(id.clone());
        }
        if !candidates.is_empty() {
            let on: Vec<usize> = (0..meta.len()).collect();
            match self.take_leases_in(LEASE_DIR, &meta, &on, now) {
                Some(holder) => report.busy = Some(holder),
                None => {
                    self.mailbox_stage(&mut st, &candidates, &pools, opts, &mut report, &lock);
                    // Published before the lease is given back, so a second
                    // dock host sees what is held here.
                    self.publish_mailbox_board(&mut st, &meta, now);
                    self.release_leases_in(LEASE_DIR, &meta, &on);
                }
            }
        }

        // 4. Write to the targets that are docked now.
        self.mailbox_deliver(
            &mut st,
            &view,
            &mut ctx,
            &needs,
            &pools,
            &stores,
            &mut failed,
            &gate,
            &mut report,
        )?;

        // 5. What is left, for the report.
        let mut seen: BTreeSet<(TaskState, String)> = BTreeSet::new();
        for t in st.tasks.values() {
            if !seen.insert((t.state, t.key.clone())) {
                continue;
            }
            match t.state {
                TaskState::Held => {
                    report.waiting_for_target += 1;
                    report.waiting_for_target_bytes += t.size;
                }
                TaskState::WaitingForSource => {
                    report.waiting_for_source += 1;
                    report.waiting_for_source_bytes += t.size;
                }
            }
        }
        // Objects no task needs any more.
        let referenced: BTreeSet<String> = st.tasks.values().map(|t| t.key.clone()).collect();
        for (key, _) in ob.list() {
            if !referenced.contains(&key) {
                ob.remove(&key);
            }
        }
        self.publish_mailbox_board(&mut st, &meta, util::now_utc());
        // Keep the pools' registries in `config.json` as they learned them.
        for (name, (_, p)) in &pools {
            let _ = p.flush();
            let disks = p.disks();
            let _ = self.save_pool_disks(name, disks);
        }
        drop(pools);
        st.save(&self.home)?;
        report.finished_utc = util::now_utc();
        if report.staged + report.delivered + report.evicted + report.rejected > 0 {
            log::info!("mailbox: {}", report.describe());
        }
        drop(lock);
        Ok(report)
    }

    /// The folders with a policy and a file list on this device.
    fn mailbox_folder_needs(&self) -> BTreeMap<FolderId, FolderNeeds> {
        let mut out = BTreeMap::new();
        for (rec, _) in self.folders() {
            if rec.is_backup() {
                continue;
            }
            let Some(p) = rec.effective_policy() else {
                continue;
            };
            let Ok(state) = self.load_state(&rec.folder_id) else {
                continue;
            };
            let current: HashSet<ChunkId> = state
                .files
                .values()
                .filter(|f| !f.deleted)
                .flat_map(|f| f.chunks.iter().map(|c| c.chunk.clone()))
                .collect();
            if current.is_empty() {
                continue;
            }
            let targets = self.write_targets(&rec);
            out.insert(
                rec.folder_id.clone(),
                FolderNeeds {
                    rules: Policy {
                        verified_within_days: None,
                        ..p
                    },
                    rec,
                    targets,
                    current,
                },
            );
        }
        out
    }

    /// The storages of this device (other than `except`) that the folder's
    /// copy rules need block `chunk` on: empty when the rules are kept.
    fn mailbox_storage_targets(
        &self,
        need: &FolderNeeds,
        ctx: &mut PolicyCtx,
        view: &LedgerView,
        record: &crate::ledger::ChunkRecord,
        chunk: &ChunkId,
        except: &str,
    ) -> Vec<String> {
        if !need.current.contains(chunk) {
            return Vec::new();
        }
        let facts = self.chunk_facts(ctx, view, &need.rec.folder_id, chunk);
        let state = crate::policy::evaluate(
            &need.rec.name,
            &need.rules,
            &[facts],
            &BTreeMap::new(),
            &[],
            0,
        )
        .state;
        if state != PolicyState::Violated {
            return Vec::new();
        }
        self.config
            .storages
            .iter()
            .filter(|s| {
                s.name() != except
                    && !s.is_cold()
                    && !s.is_carrier()
                    && need.targets.wants(s.name(), Some(record))
                    && !record
                        .storages
                        .get(s.name())
                        .is_some_and(|l| !l.claimed_by.is_empty())
            })
            .map(|s| s.name().to_string())
            .collect()
    }

    /// Labels of a pool's disks that may take objects (not retired).
    fn pool_disk_labels(
        pools: &Pools,
        pool: &str,
        places: Option<&BTreeSet<String>>,
    ) -> Vec<String> {
        let Some((_, p)) = pools.get(pool) else {
            return Vec::new();
        };
        let mut out: Vec<String> = p
            .disks()
            .iter()
            .filter(|d| !d.retired && d.write_failed_utc == 0)
            .filter(|d| places.is_none_or(|ps| ps.contains(&p.disk_place(d))))
            .map(|d| d.label.clone())
            .collect();
        out.sort();
        out
    }

    /// Tasks for what the docked disks hold and a target needs.
    fn mailbox_plan(
        &self,
        view: &LedgerView,
        ctx: &mut PolicyCtx,
        needs: &BTreeMap<FolderId, FolderNeeds>,
        pools: &Pools,
        job_items: &JobItems,
    ) -> Vec<Task> {
        let now = util::now_utc();
        let mut out = Vec::new();
        for (pname, (_, p)) in pools {
            // Keys on docked disks -> (disk id, label, size).
            let mut docked: HashMap<String, (String, String, u64)> = HashMap::new();
            for d in p.disks() {
                if p.mount_of(&d.id).is_none() {
                    continue;
                }
                for (key, size) in p.objects_on(&d.id) {
                    docked
                        .entry(key)
                        .or_insert_with(|| (d.id.clone(), d.label.clone(), size));
                }
            }
            if docked.is_empty() {
                continue;
            }
            let base = |kind: TaskKind, key: String, size: u64, src: &(String, String, u64)| Task {
                kind,
                key,
                size,
                pool: pname.clone(),
                source_disk: src.0.clone(),
                source_label: src.1.clone(),
                target: String::new(),
                places: Vec::new(),
                target_disks: Vec::new(),
                folder: None,
                chunk: None,
                object: None,
                job: None,
                state: TaskState::WaitingForSource,
                created_utc: now,
                staged_utc: 0,
                updated_utc: now,
            };
            // Disk group rule: packs held in too few places.
            if p.copies() > 1 {
                let wanted = Self::pool_wanted(view, pname);
                let all_places: BTreeSet<String> = p
                    .disks()
                    .iter()
                    .filter(|d| !d.retired)
                    .map(|d| p.disk_place(d))
                    .collect();
                for (key, src) in &docked {
                    let name = key.rsplit('/').next().unwrap_or("");
                    if !wanted.contains(name) {
                        continue;
                    }
                    let have = p.places_of(key);
                    if have.len() >= p.copies() as usize {
                        continue;
                    }
                    let missing: BTreeSet<String> = all_places.difference(&have).cloned().collect();
                    if missing.is_empty() {
                        continue; // no disk of another place exists
                    }
                    let mut t = base(TaskKind::Group, key.clone(), src.2, src);
                    t.target = pname.clone();
                    t.target_disks = Self::pool_disk_labels(pools, pname, Some(&missing));
                    t.places = missing.into_iter().collect();
                    out.push(t);
                }
            }
            // Blocks the folders' copy rules or a move job need elsewhere.
            let jobs_here: Vec<&(jobs::MoveJob, HashSet<(FolderId, ChunkId)>)> = job_items
                .values()
                .filter(|(j, _)| &j.from == pname && j.waiting.is_some())
                .collect();
            for ((folder, chunk), r) in &view.chunks {
                if !r
                    .storages
                    .get(pname)
                    .is_some_and(|l| !l.claimed_by.is_empty())
                {
                    continue;
                }
                let held = super::pack_upkeep::held_key(r, pname);
                let Some(src) = docked.get(&held) else {
                    continue;
                };
                let key = chunk_storage_key(&r.object);
                let block = |kind: TaskKind, target: &str| {
                    let mut t = base(kind, key.clone(), r.size, src);
                    t.target = target.to_string();
                    t.target_disks = Self::pool_disk_labels(pools, target, None);
                    t.folder = Some(folder.clone());
                    t.chunk = Some(chunk.clone());
                    t.object = Some(r.object.clone());
                    t
                };
                if let Some(need) = needs.get(folder) {
                    for target in self.mailbox_storage_targets(need, ctx, view, r, chunk, pname) {
                        out.push(block(TaskKind::Storage, &target));
                    }
                }
                for (j, items) in &jobs_here {
                    if items.contains(&(folder.clone(), chunk.clone())) {
                        let mut t = block(TaskKind::Move, &j.to);
                        t.job = Some(j.id.clone());
                        out.push(t);
                    }
                }
            }
        }
        out
    }

    /// Object names (and the pack ids holding them) the ledger still wants
    /// on pool `pool`.
    fn pool_wanted(view: &LedgerView, pool: &str) -> HashSet<String> {
        let mut wanted: HashSet<String> = view
            .chunks
            .values()
            .filter(|r| !r.dropped_from(pool))
            .map(|r| r.object.as_str().to_ascii_lowercase())
            .collect();
        super::pack_upkeep::with_pack_ids(view, pool, &mut wanted, false);
        wanted
    }

    /// Whether a task still has work: its target lacks the object and the
    /// rule that made it still asks for it.
    fn mailbox_task_needed(
        &self,
        t: &Task,
        view: &LedgerView,
        ctx: &mut PolicyCtx,
        needs: &BTreeMap<FolderId, FolderNeeds>,
        pools: &Pools,
        job_items: &JobItems,
    ) -> bool {
        match t.kind {
            TaskKind::Group => {
                let Some((_, p)) = pools.get(&t.pool) else {
                    return false;
                };
                if p.copies() <= 1 {
                    return false;
                }
                let have = p.places_of(&t.key);
                if have.is_empty() || have.len() >= p.copies() as usize {
                    return false;
                }
                let name = t.key.rsplit('/').next().unwrap_or("");
                Self::pool_wanted(view, &t.pool).contains(name)
            }
            TaskKind::Storage => {
                let (Some(f), Some(c), Some(o)) = (&t.folder, &t.chunk, &t.object) else {
                    return false;
                };
                let Some(r) = view.locate(f, c).filter(|r| &r.object == o) else {
                    return false;
                };
                let Some(need) = needs.get(f) else {
                    return false;
                };
                self.mailbox_storage_targets(need, ctx, view, r, c, &t.pool)
                    .contains(&t.target)
            }
            TaskKind::Move => {
                let (Some(f), Some(c), Some(id)) = (&t.folder, &t.chunk, &t.job) else {
                    return false;
                };
                job_items
                    .get(id)
                    .is_some_and(|(_, items)| items.contains(&(f.clone(), c.clone())))
            }
        }
    }

    /// Whether the task's target can take its object now.
    fn mailbox_target_ready(
        &self,
        t: &Task,
        pools: &Pools,
        stores: &BTreeMap<String, Box<dyn Storage>>,
        failed: &BTreeSet<String>,
        gate: &super::quotas::QuotaGate,
    ) -> bool {
        match t.kind {
            TaskKind::Group => Self::group_target_disk(pools, t).is_some(),
            TaskKind::Storage | TaskKind::Move => {
                Self::storage_ready(&t.target, t.size, pools, stores, failed, gate)
            }
        }
    }

    fn storage_ready(
        name: &str,
        size: u64,
        pools: &Pools,
        stores: &BTreeMap<String, Box<dyn Storage>>,
        failed: &BTreeSet<String>,
        gate: &super::quotas::QuotaGate,
    ) -> bool {
        if failed.contains(name) {
            return false;
        }
        if let Some((_, p)) = pools.get(name) {
            return p
                .disks()
                .iter()
                .any(|d| !d.retired && d.write_failed_utc == 0 && p.has_room(&d.id, size + 64));
        }
        stores.contains_key(name) && gate.fits(name, size + 64)
    }

    /// A docked disk of the task's pool, in a place the rule still needs,
    /// that may take the pack now.
    fn group_target_disk(pools: &Pools, t: &Task) -> Option<String> {
        let (_, p) = pools.get(&t.pool)?;
        p.disks()
            .into_iter()
            .filter(|d| !d.retired && d.write_failed_utc == 0)
            .filter(|d| p.mount_of(&d.id).is_some())
            .find(|d| p.wants_copy(&d.id, &t.key) && p.has_room(&d.id, t.size))
            .map(|d| d.id)
    }

    /// The object of a task read from its docked source disk, checked
    /// against its name. `Err(())` when the disk returned other bytes.
    fn mailbox_read_source(&self, t: &Task, pools: &Pools) -> Result<Option<Vec<u8>>, ()> {
        let Some((spec, p)) = pools.get(&t.pool) else {
            return Ok(None);
        };
        if t.key.starts_with("packs/") || !p.places_of(&t.key).is_empty() {
            // The object as the pool holds it: from any docked disk with a copy.
            let mut bad = false;
            for loc in p.locate_all(&t.key).into_iter().filter(|l| l.attached) {
                match p.read_on_disk(&loc.disk_id, &t.key) {
                    Ok(Some(b)) if crate::mailbox::name_matches(&t.key, &b) => return Ok(Some(b)),
                    Ok(Some(_)) => bad = true,
                    _ => {}
                }
            }
            return if bad { Err(()) } else { Ok(None) };
        }
        // A block inside a pack on the pool.
        let shared: Arc<dyn Storage> = p.clone();
        let store = self.pack_store(spec, Box::new(crate::storage::SharedStorage(shared)));
        match crate::storage::guarded(&t.key, || store.get(&t.key)) {
            Ok(Some(b)) if crate::mailbox::name_matches(&t.key, &b) => Ok(Some(b)),
            Ok(Some(_)) => Err(()),
            _ => Ok(None),
        }
    }

    /// Read the candidates into the outbox, within the budget and the
    /// free-space rule.
    fn mailbox_stage(
        &self,
        st: &mut MailboxState,
        candidates: &[String],
        pools: &Pools,
        opts: &MailboxOptions,
        report: &mut MailboxReport,
        lock: &RunLock,
    ) {
        let ob = Outbox::new(&self.home);
        let space = freespace::space_at(ob.root());
        let keep = space
            .map(|s| self.config.mailbox.keep_free_bytes(s.total))
            .unwrap_or(0);
        // What this run staged counts against the free space measured at
        // its start (a measurement may lag behind the writes).
        let mut free = space.map(|s| s.free);
        let total: u64 = candidates
            .iter()
            .filter_map(|id| st.tasks.get(id))
            .map(|t| t.size)
            .sum();
        let subject = candidates
            .first()
            .and_then(|id| st.tasks.get(id))
            .map(|t| t.source_label.clone())
            .unwrap_or_default();
        let task = activity::start(activity::MAILBOX, &subject, total, activity::Unit::Bytes);
        task.set_phase("stage");
        let mut done_keys: BTreeSet<String> = BTreeSet::new();
        for id in candidates {
            let Some(t) = st.tasks.get(id).cloned() else {
                continue;
            };
            task.advance(t.size);
            if done_keys.contains(&t.key) || ob.has(&t.key) {
                // Another task staged the same object in this run (or earlier).
                if ob.has(&t.key) {
                    let e = st.tasks.get_mut(id).unwrap();
                    e.state = TaskState::Held;
                    e.staged_utc = e.staged_utc.max(util::now_utc());
                }
                continue;
            }
            let over = report.staged > 0
                && (report.staged >= opts.max_objects || report.staged_bytes >= opts.max_bytes);
            if over {
                break;
            }
            if let Some(f) = free {
                if f.saturating_sub(t.size) < keep {
                    report.room_needed_bytes += t.size;
                    continue;
                }
            }
            let bytes = match self.mailbox_read_source(&t, pools) {
                Ok(Some(b)) => b,
                Ok(None) => continue,
                Err(()) => {
                    log::warn!(
                        key = t.key.as_str(),
                        disk = t.source_label.as_str();
                        "mailbox: the disk returned an object that does not match its name; not staged"
                    );
                    report.rejected += 1;
                    continue;
                }
            };
            if let Err(e) = ob.put(&t.key, &bytes) {
                report.notes.push(format!("staging stopped: {e:#}"));
                break;
            }
            done_keys.insert(t.key.clone());
            report.staged += 1;
            report.staged_bytes += bytes.len() as u64;
            free = free.map(|f| f.saturating_sub(bytes.len() as u64));
            let now = util::now_utc();
            for e in st.tasks.values_mut().filter(|e| e.key == t.key) {
                e.state = TaskState::Held;
                e.staged_utc = now;
                e.updated_utc = now;
            }
            lock.touch();
            // Progress survives a crash: the task file says what is held.
            let _ = st.save(&self.home);
        }
        if report.room_needed_bytes > 0 {
            report.notes.push(format!(
                "{} could not be staged: this device keeps {} free ({}); free space here or dock the target disk first",
                util::human_bytes(report.room_needed_bytes),
                util::human_bytes(keep),
                self.config.mailbox.describe_keep_free()
            ));
        }
    }

    /// Write held objects (and objects of docked sources) to the targets
    /// that can take them now, and blocks other devices hold for storages
    /// of this device.
    #[allow(clippy::too_many_arguments)]
    fn mailbox_deliver(
        &mut self,
        st: &mut MailboxState,
        view: &LedgerView,
        ctx: &mut PolicyCtx,
        needs: &BTreeMap<FolderId, FolderNeeds>,
        pools: &Pools,
        stores: &BTreeMap<String, Box<dyn Storage>>,
        failed: &mut BTreeSet<String>,
        gate: &super::quotas::QuotaGate,
        report: &mut MailboxReport,
    ) -> Result<()> {
        let ob = Outbox::new(&self.home);
        let ids: Vec<String> = st.tasks.keys().cloned().collect();
        let task = activity::start(activity::MAILBOX, "", 0, activity::Unit::Bytes);
        task.set_phase("deliver");
        // Storage targets: blocks collected per target, written as packs.
        let mut outgoing: BTreeMap<String, Vec<Outgoing>> = BTreeMap::new();
        let mut finished: BTreeSet<String> = BTreeSet::new();
        for id in ids {
            let Some(t) = st.tasks.get(&id).cloned() else {
                continue;
            };
            if t.kind == TaskKind::Move {
                continue; // the move job writes it
            }
            if !self.mailbox_target_ready(&t, pools, stores, failed, gate) {
                continue;
            }
            // The bytes: staged, else from the docked source (direct).
            let (bytes, direct) = match t.state {
                TaskState::Held => match ob.get(&t.key) {
                    Staged::Good(b) => (b, false),
                    Staged::Bad => {
                        log::warn!(key = t.key.as_str(); "mailbox: a staged object did not match its name; removed");
                        report.rejected += 1;
                        for e in st.tasks.values_mut().filter(|e| e.key == t.key) {
                            e.state = TaskState::WaitingForSource;
                            e.staged_utc = 0;
                        }
                        continue;
                    }
                    Staged::Missing => {
                        st.tasks.get_mut(&id).unwrap().state = TaskState::WaitingForSource;
                        continue;
                    }
                },
                TaskState::WaitingForSource => match self.mailbox_read_source(&t, pools) {
                    Ok(Some(b)) => (b, true),
                    Ok(None) => continue,
                    Err(()) => {
                        report.rejected += 1;
                        continue;
                    }
                },
            };
            task.advance(bytes.len() as u64);
            match t.kind {
                TaskKind::Group => {
                    let Some(disk) = Self::group_target_disk(pools, &t) else {
                        continue;
                    };
                    let (_, p) = &pools[&t.pool];
                    match p.add_copy_on_disk(&disk, &t.key, &bytes) {
                        Ok(_) => {
                            report.delivered += 1;
                            report.delivered_bytes += bytes.len() as u64;
                            report.direct += u64::from(direct);
                            *report.delivered_to.entry(t.pool.clone()).or_default() += 1;
                            st.total_delivered += 1;
                            st.total_delivered_bytes += bytes.len() as u64;
                            if p.places_of(&t.key).len() >= p.copies() as usize {
                                finished.insert(id.clone());
                            }
                        }
                        Err(e) => {
                            report
                                .notes
                                .push(format!("writing to pool {} failed: {e:#}", t.pool));
                        }
                    }
                }
                TaskKind::Storage => {
                    let (Some(f), Some(c), Some(o)) = (&t.folder, &t.chunk, &t.object) else {
                        continue;
                    };
                    let list = outgoing.entry(t.target.clone()).or_default();
                    if let Some(x) = list.iter_mut().find(|x| &x.object == o) {
                        x.ids.push(id.clone());
                    } else {
                        list.push(Outgoing {
                            ids: vec![id.clone()],
                            folder: f.clone(),
                            chunk: c.clone(),
                            object: o.clone(),
                            bytes,
                            from_peer: false,
                        });
                        report.direct += u64::from(direct);
                    }
                    let held: u64 = list.iter().map(|x| x.bytes.len() as u64).sum();
                    if held >= DELIVER_BUFFER {
                        let batch = outgoing.remove(&t.target).unwrap_or_default();
                        finished.extend(self.mailbox_write_blocks(
                            &t.target, batch, pools, stores, failed, report, st,
                        )?);
                    }
                }
                TaskKind::Move => {}
            }
        }
        // Blocks other devices hold for a storage of this device.
        if self.peers.as_ref().is_some_and(|p| !p.is_empty()) {
            let held_here: BTreeSet<String> = st.tasks.values().map(|t| t.key.clone()).collect();
            let entries: Vec<BoardEntry> = st.elsewhere.iter().map(|(_, e)| e.clone()).collect();
            for e in entries {
                let (TaskKind::Storage, Some(f), Some(c), Some(o)) =
                    (e.kind, &e.folder, &e.chunk, &e.object)
                else {
                    continue;
                };
                if held_here.contains(&e.key) {
                    continue;
                }
                let Some(r) = view.locate(f, c).filter(|r| &r.object == o) else {
                    continue;
                };
                let Some(need) = needs.get(f) else { continue };
                let targets: Vec<String> = self
                    .mailbox_storage_targets(need, ctx, view, r, c, &e.pool)
                    .into_iter()
                    .filter(|n| Self::storage_ready(n, e.size, pools, stores, failed, gate))
                    .collect();
                let Some(target) = targets.first() else {
                    continue;
                };
                if outgoing
                    .get(target)
                    .is_some_and(|l| l.iter().any(|x| &x.object == o))
                {
                    continue;
                }
                let Some((_, bytes)) = self.peers.as_ref().and_then(|p| p.get(o)) else {
                    continue;
                };
                if !crate::mailbox::name_matches(&e.key, &bytes) {
                    report.rejected += 1;
                    continue;
                }
                outgoing.entry(target.clone()).or_default().push(Outgoing {
                    ids: Vec::new(),
                    folder: f.clone(),
                    chunk: c.clone(),
                    object: o.clone(),
                    bytes,
                    from_peer: true,
                });
            }
        }
        for (target, batch) in std::mem::take(&mut outgoing) {
            finished.extend(
                self.mailbox_write_blocks(&target, batch, pools, stores, failed, report, st)?,
            );
        }
        drop(task);
        for id in &finished {
            if st.tasks.remove(id).is_some() {
                report.finished += 1;
            }
        }
        let referenced: BTreeSet<String> = st.tasks.values().map(|t| t.key.clone()).collect();
        for (key, _) in ob.list() {
            if !referenced.contains(&key) {
                ob.remove(&key);
            }
        }
        Ok(())
    }

    /// Write blocks to a storage target as a pack, read each back and
    /// record it (`chunk_stored`); the batch is sealed and pushed. Returns
    /// the tasks finished.
    #[allow(clippy::too_many_arguments)]
    fn mailbox_write_blocks(
        &mut self,
        target: &str,
        batch: Vec<Outgoing>,
        pools: &Pools,
        stores: &BTreeMap<String, Box<dyn Storage>>,
        failed: &mut BTreeSet<String>,
        report: &mut MailboxReport,
        st: &mut MailboxState,
    ) -> Result<Vec<String>> {
        if batch.is_empty() {
            return Ok(Vec::new());
        }
        let pool_store;
        let store: &dyn Storage = match pools.get(target) {
            Some((spec, p)) => {
                let shared: Arc<dyn Storage> = p.clone();
                pool_store = self.pack_store(spec, Box::new(crate::storage::SharedStorage(shared)));
                &pool_store
            }
            None => match stores.get(target) {
                Some(s) => s.as_ref(),
                None => return Ok(Vec::new()),
            },
        };
        let members: Vec<(String, &[u8])> = batch
            .iter()
            .map(|x| (x.object.as_str().to_string(), x.bytes.as_slice()))
            .collect();
        if let Err(e) = store.put_pack(&members) {
            report
                .notes
                .push(format!("writing to {target} failed: {e:#}"));
            failed.insert(target.to_string());
            return Ok(Vec::new());
        }
        let mut done = Vec::new();
        for x in &batch {
            let key = chunk_storage_key(&x.object);
            let back = crate::storage::guarded(&key, || store.get(&key));
            if !matches!(&back, Ok(Some(b)) if crate::mailbox::name_matches(&key, b)) {
                log::warn!(
                    storage = target,
                    object = x.object.short();
                    "mailbox: the storage did not return the block intact; not recorded"
                );
                continue;
            }
            self.pending.push(Event::ChunkStored {
                folder: x.folder.clone(),
                chunk: x.chunk.clone(),
                object: x.object.clone(),
                storage: target.to_string(),
                size: x.bytes.len() as u64,
                pack: None,
            });
            report.delivered += 1;
            report.delivered_bytes += x.bytes.len() as u64;
            report.pulled_from_peers += u64::from(x.from_peer);
            *report.delivered_to.entry(target.to_string()).or_default() += 1;
            st.total_delivered += 1;
            st.total_delivered_bytes += x.bytes.len() as u64;
            done.extend(x.ids.iter().cloned());
        }
        // Sealed and pushed now: other devices see the copies (and the
        // device holding them staged lets them go).
        self.commit_batch()?;
        Ok(done)
    }

    // ----- the published list --------------------------------------------------

    /// Every other device's newest list that is not older than 30 days:
    /// (device name, entry).
    fn read_mailbox_boards(&self, meta: &OpenStorages, now: i64) -> Vec<(String, BoardEntry)> {
        let reg_keys: Vec<SecretKey> = self.registry_keys().into_iter().map(|(_, k)| k).collect();
        let vault = &self.vault.vault_id;
        let me = &self.vault.device_id;
        let mut newest: BTreeMap<DeviceId, Board> = BTreeMap::new();
        for (_, backend) in meta {
            let Ok(keys) = backend.list(BOARD_PREFIX) else {
                continue;
            };
            let mut last: BTreeMap<&str, &String> = BTreeMap::new();
            for k in &keys {
                if let Some((dev, _)) = k[BOARD_PREFIX.len()..].split_once('/') {
                    last.insert(dev, k);
                }
            }
            for (dev, k) in last {
                let Ok(dev) = DeviceId::from_hex(dev) else {
                    continue;
                };
                if &dev == me || self.devices.revoked.contains_key(&dev) {
                    continue;
                }
                let board = backend
                    .get_bounded(k, 64 << 20)
                    .ok()
                    .flatten()
                    .and_then(|blob| {
                        reg_keys.iter().find_map(|key| {
                            crypto::decrypt(key, &board_aad(vault, &dev), &blob).ok()
                        })
                    })
                    .and_then(|plain| serde_json::from_slice::<Board>(&plain).ok())
                    .filter(|b| b.device == dev && now - b.updated_utc <= BOARD_TTL_SECS);
                let Some(board) = board else { continue };
                if newest
                    .get(&dev)
                    .is_none_or(|b| b.updated_utc < board.updated_utc)
                {
                    newest.insert(dev, board);
                }
            }
        }
        let mut out = Vec::new();
        for (dev, board) in newest {
            let name = self.device_name(&dev);
            for e in board.held {
                out.push((name.clone(), e));
            }
        }
        out
    }

    /// Publish what this device holds staged when it changed (and daily
    /// while it holds something); older lists of this device are deleted.
    fn publish_mailbox_board(&self, st: &mut MailboxState, meta: &OpenStorages, now: i64) {
        let mut held: Vec<BoardEntry> = Vec::new();
        let mut seen = BTreeSet::new();
        for t in st.tasks.values().filter(|t| t.state == TaskState::Held) {
            if seen.insert((t.kind, t.target.clone(), t.key.clone())) {
                held.push(BoardEntry::of(t));
            }
        }
        let sig = hex::encode(crypto::hash(
            serde_json::to_vec(&held).unwrap_or_default().as_slice(),
        ));
        let stale = !held.is_empty() && now - st.board_utc >= BOARD_REFRESH_SECS;
        if sig == st.board_sig && !stale {
            return;
        }
        if st.board_sig.is_empty() && held.is_empty() {
            st.board_sig = sig;
            return; // never published anything: nothing to take back
        }
        let me = self.vault.device_id.clone();
        let board = Board {
            device: me.clone(),
            updated_utc: now.max(st.board_utc + 1),
            held,
        };
        let key = self.registry_key_now();
        let Some(blob) = serde_json::to_vec(&board)
            .ok()
            .and_then(|p| crypto::encrypt(&key, &board_aad(&self.vault.vault_id, &me), &p).ok())
        else {
            return;
        };
        let name = format!("{BOARD_PREFIX}{me}/{:020}.enc", board.updated_utc);
        let mut ok = false;
        for (_, backend) in meta {
            if backend.put_if_absent(&name, &blob).is_ok() {
                ok = true;
                for old in backend
                    .list(&format!("{BOARD_PREFIX}{me}/"))
                    .unwrap_or_default()
                {
                    if old != name {
                        let _ = backend.delete(&old);
                    }
                }
            }
        }
        if ok {
            st.board_sig = sig;
            st.board_utc = board.updated_utc;
        }
    }
}

/// Whether two paths are on the same volume.
fn same_volume(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let dev = |p: &Path| {
            let mut here = Some(p);
            while let Some(h) = here {
                if let Ok(m) = fs::metadata(h) {
                    return Some(m.dev());
                }
                here = h.parent();
            }
            None
        };
        matches!((dev(a), dev(b)), (Some(x), Some(y)) if x == y)
    }
    #[cfg(not(unix))]
    {
        let _ = (a, b);
        false
    }
}
