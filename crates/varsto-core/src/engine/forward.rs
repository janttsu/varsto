// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Forwarding (`docs/spec/alpha-0-format.md` section 70): a device attached
//! to a folder carries blocks that other devices wrote to the storages the
//! folder's policy wants them on, without keeping the files.
//!
//! A phone sends its camera folder, but only the laptop has the bucket's
//! credentials, and the laptop keeps the folder selective (placeholders).
//! A push writes only the blocks of files this device holds; forwarding takes
//! what is left: for every block of a current file that a push from here
//! would write to a storage that does not hold it yet, and whose copies do
//! not keep the folder's copy rules, it fetches the ciphertext (block cache,
//! another storage of this device, or a peer), checks it against its name
//! and under the folder key, writes it as packs, reads them back, lists
//! their places in a block-map record of its own and claims the packs
//! (`pack_stored`) for the storage (format 3, spec section 77.9). The bytes
//! stay in memory and are dropped after every group, which is sealed and
//! pushed before the next one.
//!
//! Two devices that could forward the same folder take a lease on the
//! storages first (`vault/forward-leases/<folder>/<slot>.json`, put-if-
//! absent): only the holder forwards, so no block is written twice.

use super::*;
use crate::policy::{Policy, PolicyState};

/// Where the last run is kept.
const FORWARD_FILE: &str = "state/forward.json";
/// Lease objects on the storages.
const LEASE_PREFIX: &str = "vault/forward-leases";
/// A lease is taken for one slot of this many seconds and honoured by the
/// other devices in that slot and the next.
pub const LEASE_SLOT_SECS: i64 = 600;
/// The holder of a lease stops starting new blocks this long after taking it.
pub const LEASE_WORK_SECS: i64 = 480;
/// Peers that lacked this many blocks in a row are not asked again in the
/// same run (the device that wrote them is offline, or deleted them).
const PEER_MISSES_PER_RUN: u32 = 32;
/// The service's budget per run.
const SERVICE_MAX_BLOCKS: u64 = 4096;
const SERVICE_MAX_MIB_DESKTOP: u64 = 1024;
const SERVICE_MAX_MIB_PHONE: u64 = 256;

fn yes() -> bool {
    true
}

/// `config.json` `forward`: whether this device forwards, and its limits.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ForwardSettings {
    #[serde(default = "yes")]
    pub enabled: bool,
    /// Bytes forwarded per service run, in MiB (absent: 1024, 256 on phones).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_mib: Option<u64>,
    /// Blocks held in memory before they are written, in MiB (absent: 64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffer_mib: Option<u64>,
}

impl Default for ForwardSettings {
    fn default() -> Self {
        ForwardSettings {
            enabled: true,
            max_mib: None,
            buffer_mib: None,
        }
    }
}

impl ForwardSettings {
    pub fn is_default(&self) -> bool {
        *self == ForwardSettings::default()
    }
}

/// How one forwarding run behaves.
#[derive(Clone, Debug)]
pub struct ForwardOptions {
    /// Stop taking new blocks once this many bytes were forwarded (the first
    /// block is always taken).
    pub max_bytes: u64,
    pub max_blocks: u64,
    /// Bytes collected in memory before a group is written and recorded.
    pub buffer_bytes: u64,
}

impl ForwardOptions {
    /// `varsto forward run`: everything there is, in groups of the default buffer.
    pub fn manual() -> Self {
        ForwardOptions {
            max_bytes: u64::MAX,
            max_blocks: u64::MAX,
            buffer_bytes: crate::packs::HOT_TARGET as u64,
        }
    }
}

/// What one run did for one folder.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ForwardFolder {
    pub folder: String,
    /// Blocks written to at least one storage, and their bytes (once per block).
    pub blocks: u64,
    pub bytes: u64,
    /// Blocks written, by storage (local names).
    pub to_storages: BTreeMap<String, u64>,
    /// Blocks by where they came from: `block cache`, `storage <name>`, `peer <name>`.
    pub sources: BTreeMap<String, u64>,
    /// Names of the devices that hold the blocks carried (from the ledger).
    pub for_devices: Vec<String>,
    /// Blocks no source had now (no peer online, no other copy).
    pub unavailable: u64,
    /// Blocks no target could take now (quotas, failed writes).
    pub waiting_for_target: u64,
    /// Objects that did not pass the checks (hash, or the folder key).
    pub rejected: u64,
    /// Another device holds the folder's lease: nothing was done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub busy: Option<String>,
    /// Blocks still to forward after this run (budget or time limit).
    pub left: u64,
}

/// What one forwarding run did.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ForwardReport {
    pub started_utc: i64,
    pub finished_utc: i64,
    pub enabled: bool,
    pub folders: Vec<ForwardFolder>,
    /// Folders attached here whose key this device does not hold now.
    pub no_key: Vec<String>,
    /// Storages that could not be opened or written in this run.
    pub storages_failed: Vec<String>,
    /// Storages at their quota.
    pub storages_full: Vec<String>,
    pub blocks: u64,
    pub bytes: u64,
    pub work_left: bool,
}

impl ForwardReport {
    /// One line: "12 blocks (48.0 MiB) of camera for phone".
    pub fn describe(&self) -> String {
        if !self.enabled {
            return "off".to_string();
        }
        let mut parts: Vec<String> = Vec::new();
        for f in &self.folders {
            if f.blocks > 0 {
                let mut s = format!(
                    "{} block{} ({}) of {}",
                    f.blocks,
                    if f.blocks == 1 { "" } else { "s" },
                    super::placement::fmt_size(f.bytes),
                    f.folder
                );
                if !f.for_devices.is_empty() {
                    s.push_str(&format!(" for {}", f.for_devices.join(", ")));
                }
                parts.push(s);
            }
            if let Some(h) = &f.busy {
                parts.push(format!("{} is being forwarded by {h}", f.folder));
            }
            if f.unavailable > 0 {
                parts.push(format!(
                    "{} block{} of {} waiting for a device that has {}",
                    f.unavailable,
                    if f.unavailable == 1 { "" } else { "s" },
                    f.folder,
                    if f.unavailable == 1 { "it" } else { "them" }
                ));
            }
        }
        if parts.is_empty() {
            "nothing to forward".to_string()
        } else {
            parts.join("; ")
        }
    }
}

/// `state/forward.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ForwardState {
    #[serde(default)]
    last: Option<ForwardReport>,
    #[serde(default)]
    last_error: Option<String>,
    #[serde(default)]
    total_blocks: u64,
    #[serde(default)]
    total_bytes: u64,
}

/// What `varsto forward` and `/api/forward` show.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ForwardStatus {
    pub enabled: bool,
    pub last: Option<ForwardReport>,
    pub last_error: Option<String>,
    pub total_blocks: u64,
    pub total_bytes: u64,
}

impl ForwardStatus {
    pub fn describe(&self) -> String {
        if !self.enabled {
            return "forwarding: off".to_string();
        }
        match (&self.last, &self.last_error) {
            (_, Some(e)) => format!("forwarding: the last run failed: {e}"),
            (Some(r), None) => format!(
                "forwarding: last run {}: {}",
                util::format_date(r.finished_utc),
                r.describe()
            ),
            (None, None) => "forwarding: on, not run yet".to_string(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Lease {
    device: String,
    taken_utc: i64,
}

fn lease_dir(folder: &FolderId) -> String {
    format!("{LEASE_PREFIX}/{folder}/")
}

#[cfg(test)]
fn lease_key(folder: &FolderId, slot: i64) -> String {
    slot_key(&lease_dir(folder), slot)
}

/// The lease object of `slot` in the lease directory `dir` (`.../`).
fn slot_key(dir: &str, slot: i64) -> String {
    format!("{dir}{slot:012}.json")
}

/// The slot of a lease object's key.
fn lease_slot(key: &str) -> Option<i64> {
    key.rsplit('/').next()?.strip_suffix(".json")?.parse().ok()
}

/// Where a transfer reads a block from. Copying is by ciphertext object,
/// named by its hash, so any storage can be an endpoint, a pool disk that is
/// attached only sometimes included (the mailbox, section 78 and
/// `engine::mailbox`, builds on this: its tasks wait for their source or
/// their target to be docked).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Endpoint {
    /// This device's block cache.
    BlockCache,
    /// Another device, over peer-to-peer.
    Peer(DeviceId),
    /// A storage of this device (local name).
    Storage(String),
}

impl Endpoint {
    fn label(&self, e: &Engine) -> String {
        match self {
            Endpoint::BlockCache => "block cache".to_string(),
            Endpoint::Peer(d) => format!("peer {}", e.device_name(d)),
            Endpoint::Storage(n) => format!("storage {n}"),
        }
    }
}

/// Where the bytes of a transfer are while it is in flight. Forwarding holds
/// them in memory only; the durable outbox is the mailbox's (section 78).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeldAt {
    Memory,
}

/// The state of one transfer. Staging never counts as a copy: only
/// `Recorded` (written, read back, claimed in the ledger) does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransferState {
    /// No source has the block now (the peer is offline, a disk is away).
    WaitingForSource,
    /// No target can take it now (quota, a failed write, a disk away).
    WaitingForTarget,
    /// Read and checked against its name; held until it is written.
    Held(HeldAt),
    /// Written, read back and recorded.
    Recorded,
}

/// One block on its way from a source to the storages that should hold it.
struct Transfer {
    chunk: ChunkRef,
    /// Indexes into the opened storages.
    targets: Vec<usize>,
    source: Option<Endpoint>,
    state: TransferState,
    /// The ciphertext while `Held(Memory)`.
    bytes: Vec<u8>,
}

impl Engine {
    fn forward_path(&self) -> PathBuf {
        self.home.join(FORWARD_FILE)
    }

    fn load_forward_state(&self) -> ForwardState {
        util::read_json_or_default(&self.forward_path()).unwrap_or_default()
    }

    /// The forwarding settings of this device.
    pub fn forward_settings(&self) -> ForwardSettings {
        self.config.forward.clone()
    }

    /// Turn forwarding on or off on this device.
    pub fn set_forwarding(&mut self, enabled: bool) -> Result<()> {
        let mut s = self.config.forward.clone();
        s.enabled = enabled;
        self.set_forward_settings(s)
    }

    /// Replace the forwarding settings of this device.
    pub fn set_forward_settings(&mut self, settings: ForwardSettings) -> Result<()> {
        if settings.max_mib == Some(0) || settings.buffer_mib == Some(0) {
            bail!("forwarding limits must be more than zero");
        }
        self.config.forward = settings;
        self.config.save(&self.home)
    }

    /// The budget of one service run: the settings of `config.json`, else
    /// 1 GiB (256 MiB on a phone) and 4096 blocks.
    pub fn forward_service_options(&self, phone: bool) -> ForwardOptions {
        let s = &self.config.forward;
        let mib = s.max_mib.unwrap_or(if phone {
            SERVICE_MAX_MIB_PHONE
        } else {
            SERVICE_MAX_MIB_DESKTOP
        });
        ForwardOptions {
            max_bytes: mib.saturating_mul(1 << 20),
            max_blocks: SERVICE_MAX_BLOCKS,
            buffer_bytes: s
                .buffer_mib
                .map(|m| m.max(1).saturating_mul(1 << 20))
                .unwrap_or(crate::packs::HOT_TARGET as u64),
        }
    }

    pub fn forward_status(&self) -> ForwardStatus {
        let st = self.load_forward_state();
        ForwardStatus {
            enabled: self.config.forward.enabled,
            last: st.last,
            last_error: st.last_error,
            total_blocks: st.total_blocks,
            total_bytes: st.total_bytes,
        }
    }

    /// Carry blocks of attached folders that other devices wrote to the
    /// storages a push from here would write them to (section 70).
    pub fn forward(&mut self, opts: &ForwardOptions) -> Result<ForwardReport> {
        let out = crate::logged_op!("forward", "", { self.forward_inner(opts) });
        self.finish_storages();
        let mut st = self.load_forward_state();
        match &out {
            Ok(r) => {
                st.total_blocks += r.blocks;
                st.total_bytes += r.bytes;
                st.last = Some(r.clone());
                st.last_error = None;
            }
            Err(e) => st.last_error = Some(format!("{e:#}")),
        }
        util::write_json(&self.forward_path(), &st)?;
        out
    }

    fn forward_inner(&mut self, opts: &ForwardOptions) -> Result<ForwardReport> {
        let mut report = ForwardReport {
            started_utc: util::now_utc(),
            enabled: self.config.forward.enabled,
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
        self.pull_ledger_once()?;

        // Hot storages that are not transferrers: the only ones forwarding
        // reads or writes. Cold ones are neither read nor written here.
        let mut opened: Vec<(StorageSpec, Box<dyn Storage>)> = Vec::new();
        for spec in self.config.storages.clone() {
            if spec.is_cold() || spec.is_carrier() {
                continue;
            }
            match self.open_spec(&spec) {
                Ok(b) => opened.push((spec, b)),
                Err(e) => report
                    .storages_failed
                    .push(format!("{} ({e:#})", spec.name())),
            }
        }
        if opened.is_empty() {
            report.finished_utc = util::now_utc();
            return Ok(report);
        }
        let mut failed: BTreeSet<usize> = BTreeSet::new();
        let (mut blocks, mut bytes) = (0u64, 0u64);
        let me = self.vault.device_id.clone();
        for (rec, mount) in self.folders() {
            if mount.is_none() || rec.is_backup() {
                continue;
            }
            let Some((rec, fk)) = self
                .with_key(&rec)
                .ok()
                .and_then(|r| self.folder_keys(&r).ok().map(|k| (r, k)))
            else {
                report.no_key.push(rec.name.clone());
                continue;
            };
            if !self.state_path(&rec.folder_id).exists() {
                continue; // not synced here yet: no file list to work from
            }
            let view = self.view3()?;
            let Some(table) = self.folder_table3(&rec)? else {
                report.no_key.push(rec.name.clone());
                continue;
            };
            // The map records the ledger announced: other forwarders' places.
            self.pull_folder_records3(&members3::bin(&rec.folder_id)?, &view)?;
            let candidates = {
                let t = table.read().unwrap_or_else(|e| e.into_inner());
                self.forward_candidates(&rec, &view, &t, &opened)?
            };
            if candidates.is_empty() {
                continue;
            }
            let mut folder = ForwardFolder {
                folder: rec.name.clone(),
                ..Default::default()
            };
            // Whose blocks these are (they hold them, by the `held` flags of
            // their manifests), for the report and the activity line.
            let held = self
                .load_manifests3(&members3::bin(&rec.folder_id)?)
                .held_index();
            let me3 = self.me3();
            let mut holders: BTreeSet<String> = BTreeSet::new();
            for c in &candidates {
                if let Ok(o) = crate::storages3::object_bin(&c.chunk.object) {
                    for d in held.holders(&o).iter().filter(|d| **d != me3) {
                        holders.insert(self.device_name(&DeviceId::from_bytes(d)));
                    }
                }
            }
            folder.for_devices = holders.into_iter().collect();
            let _ = &me;
            let now = util::now_utc();
            let lease_on: Vec<usize> = (0..opened.len())
                .filter(|i| !opened[*i].0.is_data_only() && !failed.contains(i))
                .collect();
            if let Some(holder) = self.take_forward_leases(&rec.folder_id, &opened, &lease_on, now)
            {
                folder.busy = Some(holder);
                folder.left = candidates.len() as u64;
                report.work_left = true;
                report.folders.push(folder);
                continue;
            }
            let deadline = now + LEASE_WORK_SECS;
            let total: u64 = candidates.iter().map(|c| c.chunk.size).sum();
            let subject = if folder.for_devices.is_empty() {
                rec.name.clone()
            } else {
                format!("{}: {}", folder.for_devices.join(", "), rec.name)
            };
            let task = activity::start(activity::FORWARD, &subject, total, activity::Unit::Bytes);
            let gate = self.quota_gate(&view);
            let mut held: Vec<Transfer> = Vec::new();
            let mut held_bytes = 0u64;
            let mut stopped = 0u64;
            let mut peer_misses = 0u32;
            let n = candidates.len();
            for (i, mut c) in candidates.into_iter().enumerate() {
                let over_budget =
                    blocks > 0 && (blocks >= opts.max_blocks || bytes >= opts.max_bytes);
                if over_budget || util::now_utc() >= deadline {
                    stopped = (n - i) as u64;
                    break;
                }
                task.advance(c.chunk.size);
                // Room is taken before anything is fetched (by the block's
                // size, which its object hardly passes): a block no target
                // can take is not asked of the phone at all.
                let size = c.chunk.size + 64;
                c.targets
                    .retain(|t| !failed.contains(t) && gate.take(opened[*t].0.name(), size));
                if c.targets.is_empty() {
                    c.state = TransferState::WaitingForTarget;
                    folder.waiting_for_target += 1;
                    continue;
                }
                let standing = {
                    let t = table.read().unwrap_or_else(|e| e.into_inner());
                    super::data_moves::BlockStanding::of(&view, &t, &c.chunk.object)
                };
                let Some((source, ct)) =
                    self.forward_source(&c.chunk, &standing, &opened, &mut peer_misses)
                else {
                    debug_assert_eq!(c.state, TransferState::WaitingForSource);
                    folder.unavailable += 1;
                    continue;
                };
                let label = source.label(self);
                // The bytes are this very block of this folder: named by
                // their hash, and opening under the folder key.
                let sound = ObjectName::from_bytes(&crypto::hash(&ct)) == c.chunk.object
                    && crate::chunk_seal::open_chunk(
                        &fk,
                        &self.vault.vault_id,
                        &c.chunk.chunk,
                        c.chunk.epoch,
                        c.chunk.size,
                        &ct,
                    )
                    .is_ok();
                if !sound {
                    log::warn!(
                        folder = rec.name.as_str(),
                        object = c.chunk.object.short(),
                        source = label.as_str();
                        "forward: refused an object that does not check"
                    );
                    folder.rejected += 1;
                    continue;
                }
                *folder.sources.entry(label).or_default() += 1;
                blocks += 1;
                bytes += ct.len() as u64;
                held_bytes += ct.len() as u64;
                c.source = Some(source);
                c.state = TransferState::Held(HeldAt::Memory);
                c.bytes = ct;
                held.push(c);
                if held_bytes >= opts.buffer_bytes {
                    self.write_forwarded(
                        &rec,
                        &opened,
                        std::mem::take(&mut held),
                        &mut failed,
                        &mut folder,
                        &mut report,
                    )?;
                    held_bytes = 0;
                }
            }
            self.write_forwarded(&rec, &opened, held, &mut failed, &mut folder, &mut report)?;
            drop(task);
            folder.left = stopped + folder.unavailable + folder.waiting_for_target;
            if stopped > 0 {
                report.work_left = true;
            } else {
                // Done with the folder: the others may take it from here.
                self.release_forward_leases(&rec.folder_id, &opened, &lease_on);
            }
            report.blocks += folder.blocks;
            report.bytes += folder.bytes;
            for msg in gate.refusals() {
                if !report.storages_full.contains(&msg) {
                    report.storages_full.push(msg);
                }
            }
            report.folders.push(folder);
        }
        report.finished_utc = util::now_utc();
        if report.blocks > 0 {
            log::info!("forward: {}", report.describe());
        }
        Ok(report)
    }

    /// The blocks of `rec`'s current files that a push from here would write
    /// to a storage that does not hold them, and that the folder's copy
    /// rules still need (no storage copy at all, without a policy).
    fn forward_candidates(
        &self,
        rec: &FolderRecord,
        view: &crate::ledger3::LedgerView,
        table: &crate::blockmap::MapTable,
        opened: &[(StorageSpec, Box<dyn Storage>)],
    ) -> Result<Vec<Transfer>> {
        let state = self.load_state(&rec.folder_id)?;
        let targets = self.write_targets(rec);
        let rules = rec.effective_policy().map(|p| Policy {
            verified_within_days: None,
            ..p
        });
        let mut ctx = self.policy_ctx();
        let mut seen: HashSet<ObjectName> = HashSet::new();
        let mut out = Vec::new();
        // Newest files first, as downloads go (section 47).
        let mut files: Vec<&FileState> = state.files.values().filter(|f| !f.deleted).collect();
        files.sort_by(|a, b| b.mtime.cmp(&a.mtime).then(a.path.cmp(&b.path)));
        for f in files {
            for c in &f.chunks {
                if !seen.insert(c.object.clone()) {
                    continue;
                }
                let standing = super::data_moves::BlockStanding::of(view, table, &c.object);
                let to: Vec<usize> = opened
                    .iter()
                    .enumerate()
                    .filter(|(_, (spec, _))| {
                        !standing.copies.contains(spec.name())
                            && targets.wants(spec.name(), Some(&standing))
                    })
                    .map(|(i, _)| i)
                    .collect();
                if to.is_empty() {
                    continue;
                }
                let needed = match &rules {
                    Some(p) => {
                        let facts = self.chunk_facts(&mut ctx, view, table, &c.object);
                        crate::policy::evaluate(&rec.name, p, &[facts], &BTreeMap::new(), &[], 0)
                            .state
                            == PolicyState::Violated
                    }
                    None => !standing.copies.iter().any(|n| !ctx.carriers.contains(n)),
                };
                if needed {
                    out.push(Transfer {
                        chunk: c.clone(),
                        targets: to,
                        source: None,
                        state: TransferState::WaitingForSource,
                        bytes: Vec::new(),
                    });
                }
            }
        }
        Ok(out)
    }

    /// The ciphertext of `c` from the block cache, a peer (free per
    /// gigabyte, usually the device that wrote it), or another storage of
    /// this device that holds it, with where it came from. Peers that lacked
    /// `PEER_MISSES_PER_RUN` blocks in a row are not asked again this run.
    fn forward_source(
        &self,
        c: &ChunkRef,
        standing: &super::data_moves::BlockStanding,
        opened: &[(StorageSpec, Box<dyn Storage>)],
        peer_misses: &mut u32,
    ) -> Option<(Endpoint, Vec<u8>)> {
        if let Some(ct) = self.cached_object(&c.object) {
            return Some((Endpoint::BlockCache, ct));
        }
        if let Some(peers) = self.peers.as_ref().filter(|p| !p.is_empty()) {
            if *peer_misses < PEER_MISSES_PER_RUN {
                match peers.get(&c.object) {
                    Some((dev, ct)) => {
                        *peer_misses = 0;
                        return Some((Endpoint::Peer(dev), ct));
                    }
                    None => *peer_misses += 1,
                }
            }
        }
        // A storage that holds a live place of it: read at its place (the
        // pack layer finds it through the folder's map).
        let key = chunk_storage_key(&c.object);
        for (spec, backend) in opened {
            if !standing.copies.contains(spec.name()) {
                continue;
            }
            if let Ok(Some(ct)) = crate::storage::guarded(&key, || {
                backend.get_bounded(&key, crate::storage::MAX_BLOCK_OBJECT)
            }) {
                if ObjectName::from_bytes(&crypto::hash(&ct)) == c.object {
                    return Some((Endpoint::Storage(spec.name().to_string()), ct));
                }
            }
        }
        None
    }

    /// Write a group of fetched blocks as packs to each target, read each
    /// pack back, list their places in this device's map record of the
    /// folder, claim them and seal it all into a batch.
    fn write_forwarded(
        &mut self,
        rec: &FolderRecord,
        opened: &[(StorageSpec, Box<dyn Storage>)],
        mut held: Vec<Transfer>,
        failed: &mut BTreeSet<usize>,
        folder: &mut ForwardFolder,
        report: &mut ForwardReport,
    ) -> Result<()> {
        if held.is_empty() {
            return Ok(());
        }
        debug_assert!(held
            .iter()
            .all(|t| t.state == TransferState::Held(HeldAt::Memory) && t.source.is_some()));
        let info: HashMap<crate::ledger3::ObjectBin, crate::blockmap::ChunkInfo> = held
            .iter()
            .filter_map(|t| {
                let o = crate::storages3::object_bin(&t.chunk.object).ok()?;
                let c = crate::storages3::object_bin(&ObjectName::from_bytes(
                    &t.chunk.chunk.as_bytes(),
                ))
                .ok()?;
                Some((o, (c, t.chunk.size as u32, t.chunk.epoch)))
            })
            .collect();
        let mut per_storage: Vec<(String, Vec<crate::packs::NewPack>)> = Vec::new();
        for (i, (spec, backend)) in opened.iter().enumerate() {
            if failed.contains(&i) {
                continue;
            }
            let mine: Vec<usize> = (0..held.len())
                .filter(|k| held[*k].targets.contains(&i))
                .collect();
            if mine.is_empty() {
                continue;
            }
            let members: Vec<(String, &[u8])> = mine
                .iter()
                .map(|k| {
                    let t = &held[*k];
                    (t.chunk.object.as_str().to_string(), t.bytes.as_slice())
                })
                .collect();
            // Packs written earlier in this process by anything else stay
            // out of this record.
            let _ = backend.take_new_packs();
            if let Err(e) = backend.put_pack(&members) {
                report
                    .storages_failed
                    .push(format!("{} ({e:#})", spec.name()));
                failed.insert(i);
                continue;
            }
            // Each new pack read back whole and checked against its id
            // before it is claimed.
            let mut good = Vec::new();
            for p in backend.take_new_packs() {
                let mut id = [0u8; 32];
                let intact = hex::decode_to_slice(&p.pack, &mut id).is_ok()
                    && backend
                        .get_bounded(&crate::packs::pack_key(&p.pack), crate::storage::MAX_PACK)
                        .ok()
                        .flatten()
                        .is_some_and(|b| crypto::hash(&b) == id);
                if !intact {
                    log::warn!(
                        storage = spec.name(),
                        pack = p.pack.as_str();
                        "forward: the storage did not return the pack intact; not recorded"
                    );
                    continue;
                }
                for (o, _) in &p.members {
                    let Some(k) = mine
                        .iter()
                        .copied()
                        .find(|k| held[*k].chunk.object.as_str() == o.as_str())
                    else {
                        continue;
                    };
                    *folder
                        .to_storages
                        .entry(spec.name().to_string())
                        .or_default() += 1;
                    let t = &mut held[k];
                    if t.state != TransferState::Recorded {
                        t.state = TransferState::Recorded;
                        folder.blocks += 1;
                        folder.bytes += t.bytes.len() as u64;
                    }
                }
                good.push(p);
            }
            if !good.is_empty() {
                per_storage.push((spec.name().to_string(), good));
            }
        }
        let written = crate::blockmap::written_packs(&per_storage, &|o| info.get(o).copied())?;
        let view = self.view3()?;
        let epoch = self.folder_keys(rec)?.epoch;
        self.publish_map3(&members3::bin(&rec.folder_id)?, epoch, &written, &view)?;
        // Sealed and pushed now: a run that stops later keeps this group,
        // and other devices see the copies.
        self.commit_batch()?;
        Ok(())
    }

    /// Take the folder's lease on the storages `on`. `None`: this device
    /// holds them all now; otherwise the name of the device holding one
    /// (the leases taken in this attempt are given back).
    fn take_forward_leases(
        &self,
        folder: &FolderId,
        opened: &[(StorageSpec, Box<dyn Storage>)],
        on: &[usize],
        now: i64,
    ) -> Option<String> {
        self.take_leases_in(&lease_dir(folder), opened, on, now)
    }

    /// Take the lease of the directory `dir` (`.../`) on the storages `on`:
    /// forwarding takes one per folder, the mailbox one for the vault
    /// (section 78). `None`: this device holds them all now; otherwise the
    /// name of the device holding one (the leases taken in this attempt are
    /// given back).
    pub(super) fn take_leases_in(
        &self,
        dir: &str,
        opened: &[(StorageSpec, Box<dyn Storage>)],
        on: &[usize],
        now: i64,
    ) -> Option<String> {
        let me = self.vault.device_id.as_str().to_string();
        let slot = now.div_euclid(LEASE_SLOT_SECS);
        let body = serde_json::to_vec(&Lease {
            device: me.clone(),
            taken_utc: now,
        })
        .unwrap_or_default();
        let mut taken: Vec<usize> = Vec::new();
        let mut busy: Option<String> = None;
        let holder_of = |backend: &dyn Storage, key: &str| -> Option<String> {
            // The device named in a lease; junk counts as someone else's.
            match backend.get_bounded(key, 4096) {
                Ok(Some(b)) => Some(
                    serde_json::from_slice::<Lease>(&b)
                        .map(|l| l.device)
                        .unwrap_or_else(|_| "?".to_string()),
                ),
                _ => None,
            }
        };
        for &i in on {
            let backend = opened[i].1.as_ref();
            let keys = backend.list(dir).unwrap_or_default();
            for key in &keys {
                let Some(s) = lease_slot(key) else { continue };
                if s < slot - 1 {
                    let _ = backend.delete(key); // lapsed
                    continue;
                }
                if let Some(dev) = holder_of(backend, key) {
                    if dev != me {
                        busy = Some(dev);
                    }
                }
            }
            if busy.is_some() {
                break;
            }
            let key = slot_key(dir, slot);
            match backend.put_if_absent(&key, &body) {
                Ok(true) => taken.push(i),
                Ok(false) => match holder_of(backend, &key) {
                    Some(dev) if dev == me => {}
                    Some(dev) => {
                        busy = Some(dev);
                        break;
                    }
                    None => {}
                },
                // A storage that cannot take the lease cannot take blocks
                // either; the writes will tell.
                Err(_) => {}
            }
        }
        let dev = busy?;
        for i in taken {
            let _ = opened[i].1.delete(&slot_key(dir, slot));
        }
        Some(
            DeviceId::from_hex(&dev)
                .map(|d| self.device_name(&d))
                .unwrap_or_else(|_| "another device".to_string()),
        )
    }

    /// Give the folder's leases of this device back.
    fn release_forward_leases(
        &self,
        folder: &FolderId,
        opened: &[(StorageSpec, Box<dyn Storage>)],
        on: &[usize],
    ) {
        self.release_leases_in(&lease_dir(folder), opened, on)
    }

    /// Give this device's leases of the directory `dir` back.
    pub(super) fn release_leases_in(
        &self,
        dir: &str,
        opened: &[(StorageSpec, Box<dyn Storage>)],
        on: &[usize],
    ) {
        let me = self.vault.device_id.as_str();
        for &i in on {
            let backend = opened[i].1.as_ref();
            for key in backend.list(dir).unwrap_or_default() {
                let ours = backend
                    .get_bounded(&key, 4096)
                    .ok()
                    .flatten()
                    .and_then(|b| serde_json::from_slice::<Lease>(&b).ok())
                    .is_some_and(|l| l.device == me);
                if ours {
                    let _ = backend.delete(&key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_keys_carry_their_slot() {
        let f = FolderId::random();
        let k = lease_key(&f, 2_917_000);
        assert!(k.starts_with(&lease_dir(&f)));
        assert_eq!(lease_slot(&k), Some(2_917_000));
        assert_eq!(lease_slot("vault/forward-leases/x/junk"), None);
    }

    #[test]
    fn settings_default_to_on_and_are_left_out_of_the_config() {
        let s: ForwardSettings = serde_json::from_str("{}").unwrap();
        assert!(s.enabled && s.is_default());
        let off: ForwardSettings = serde_json::from_str(r#"{"enabled": false}"#).unwrap();
        assert!(!off.enabled);
    }
}
