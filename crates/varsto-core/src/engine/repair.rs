// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Automatic repair (`docs/spec/alpha-0-format.md` section 24).
//!
//! `fsck` (objects missing from a storage that the ledger says holds them,
//! blocks of current files on no storage, and with `--verify` corrupt
//! objects) and automatic verification (missing or corrupt copies another
//! device wrote) put what they find in a queue, `state/repair.json`. A
//! repair run takes the queue, oldest damage on the fewest copies first and
//! within a budget, and for each damaged copy on a storage of this device:
//!
//! 1. reads the copy again: a copy that is intact by now (another device
//!    repaired it, a pool disk came back) is recorded as verified;
//! 2. finds the same ciphertext elsewhere, in this order: the encrypted
//!    block cache, the other hot storages, this device's plain files (chunk
//!    encryption is deterministic, so re-encrypting the plaintext gives the
//!    very object), and peers; a cold storage only when the user asked for it
//!    (`varsto repair --from-cold`), because reading one costs a retrieval;
//!    every candidate is checked against the object name before use;
//! 3. deletes a corrupt copy, writes the object, reads it back, checks the
//!    hash and records `chunk_stored` for the storage in the ledger.
//!
//! Transferrers are never written (they only ever take what another device
//! lacks), cold storages are never read without that confirmation, and a
//! storage that is no longer configured here is gone for good: nothing is
//! done for it (removing a storage is its own action). Copies that cannot be
//! repaired stay in the queue with the reason, are tried again a day later
//! (a peer may come online, a disk may be attached), and raise a desktop
//! notification once in the service.

use super::*;

const REPAIR_FILE: &str = "state/repair.json";

/// Retry an unrepairable copy after this long.
const RETRY_UNREPAIRABLE_SECS: i64 = 24 * 3600;
/// Retry a copy whose storage could not be reached after this long.
const RETRY_UNREACHABLE_SECS: i64 = 3600;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum DamageKind {
    /// The storage does not have the object.
    Missing,
    /// The storage returned bytes whose hash is not the object name.
    Corrupt,
}

/// One damaged copy: `object` should be on this device's storage `storage`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Damage {
    pub folder: FolderId,
    pub chunk: ChunkId,
    pub object: ObjectName,
    /// Local name of the storage.
    pub storage: String,
    pub kind: DamageKind,
    /// "fsck" or "verify".
    pub found_by: String,
    pub found_utc: i64,
    /// Not tried again before this time (UTC seconds; 0: at once).
    #[serde(default)]
    pub retry_utc: i64,
    /// Why the last attempt did not repair it.
    #[serde(default)]
    pub reason: Option<String>,
}

impl Damage {
    fn key(&self) -> (ObjectName, String) {
        (self.object.clone(), self.storage.clone())
    }
}

/// How one repair run behaves.
#[derive(Clone, Debug)]
pub struct RepairOptions {
    /// Report what would be done; write and record nothing.
    pub dry_run: bool,
    /// Read cold storages as a source (the user confirmed the retrieval).
    pub from_cold: bool,
    /// Compare the ledger with the hot storages first (an `fsck` without
    /// downloading), instead of working on the queue alone.
    pub scan: bool,
    /// Also take copies whose retry time has not come yet.
    pub retry_all: bool,
    pub max_blocks: u64,
    pub max_bytes: u64,
}

impl RepairOptions {
    /// What the background service runs after verification and fsck.
    pub fn service() -> Self {
        RepairOptions {
            dry_run: false,
            from_cold: false,
            scan: false,
            retry_all: false,
            max_blocks: 500,
            max_bytes: 256 * 1024 * 1024,
        }
    }

    /// `varsto repair`: scan, then everything, without a budget.
    pub fn manual() -> Self {
        RepairOptions {
            dry_run: false,
            from_cold: false,
            scan: true,
            retry_all: true,
            max_blocks: u64::MAX,
            max_bytes: u64::MAX,
        }
    }
}

/// A copy written again (or, in a dry run, that would be).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RepairedCopy {
    pub folder: String,
    pub storage: String,
    pub object: String,
    pub kind: DamageKind,
    /// "block cache", "storage <name>", "local file", "peer <device>" or "cold storage <name>".
    pub source: String,
    pub bytes: u64,
}

/// A copy that could not be repaired, and why.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Unrepairable {
    pub folder: String,
    pub storage: String,
    pub object: String,
    pub kind: DamageKind,
    pub reason: String,
}

/// What one run did.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct RepairReport {
    pub started_utc: i64,
    pub finished_utc: i64,
    pub dry_run: bool,
    /// Damaged copies considered.
    pub found: u64,
    pub repaired: Vec<RepairedCopy>,
    pub unrepairable: Vec<Unrepairable>,
    /// Copies that were intact when read again.
    pub already_intact: u64,
    /// Copies no current file uses any more, or on a storage that is gone.
    pub not_needed: u64,
    /// Storages that could not be reached (tried again later).
    pub unreachable: Vec<String>,
    /// Copies left for the next run because the budget ran out or their
    /// retry time has not come.
    pub left_for_next_run: u64,
    pub bytes_written: u64,
    /// Unrepairable copies not reported before (the service notifies them).
    pub new_losses: u64,
}

/// Kept in `state/repair.json`.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct RepairState {
    #[serde(default)]
    queue: Vec<Damage>,
    #[serde(default)]
    last_run_utc: Option<i64>,
    #[serde(default)]
    last: Option<RepairReport>,
    #[serde(default)]
    last_error: Option<String>,
    #[serde(default)]
    total_repaired: u64,
    /// Unrepairable copies already notified ("object@storage").
    #[serde(default)]
    notified: BTreeSet<String>,
}

/// Queue, last run and open losses, for the API, the CLI and the interface.
#[derive(Clone, Debug, Serialize)]
pub struct RepairStatus {
    pub last_run_utc: Option<i64>,
    pub last: Option<RepairReport>,
    pub last_error: Option<String>,
    /// Damaged copies waiting for a run.
    pub queued: u64,
    pub total_repaired: u64,
    /// Copies that could not be repaired so far, with the reason.
    pub open_losses: Vec<Unrepairable>,
}

impl RepairStatus {
    /// "3 copies repaired, 1 could not be repaired: <why>".
    pub fn describe(&self) -> String {
        let mut s = match (&self.last, self.last_run_utc) {
            (Some(r), Some(t)) => format!(
                "automatic repair: last run {}: {} cop{} repaired",
                crate::util::format_date(t),
                r.repaired.len(),
                if r.repaired.len() == 1 { "y" } else { "ies" }
            ),
            _ => "automatic repair: nothing repaired yet".to_string(),
        };
        if self.total_repaired > 0 {
            s += &format!(" ({} in all)", self.total_repaired);
        }
        if !self.open_losses.is_empty() {
            let mut why: Vec<&str> = self.open_losses.iter().map(|l| l.reason.as_str()).collect();
            why.sort();
            why.dedup();
            s += &format!(
                ", {} could not be repaired: {}",
                self.open_losses.len(),
                why.join("; ")
            );
        }
        let waiting = self.queued - self.open_losses.len() as u64;
        if waiting > 0 {
            s += &format!(", {waiting} waiting");
        }
        if let Some(e) = &self.last_error {
            s += &format!("; last error: {e}");
        }
        s
    }
}

/// Where the plaintext of an object may be on this device.
struct PlainSource {
    epoch: u32,
    files: Vec<PathBuf>,
}

impl Engine {
    fn repair_path(&self) -> PathBuf {
        self.home.join(REPAIR_FILE)
    }

    fn load_repair_state(&self) -> RepairState {
        util::read_json_or_default(&self.repair_path()).unwrap_or_default()
    }

    fn save_repair_state(&self, st: &RepairState) -> Result<()> {
        if !self.home.join("state").is_dir() {
            return Ok(());
        }
        util::write_json(&self.repair_path(), st)
    }

    /// Add damage found by fsck or verification to the queue. A copy found
    /// again is due at once. Returns how many copies the queue holds.
    pub(super) fn queue_damage(&self, found: Vec<Damage>) -> Result<u64> {
        let mut st = self.load_repair_state();
        if found.is_empty() {
            return Ok(st.queue.len() as u64);
        }
        merge_damage(&mut st.queue, found);
        self.save_repair_state(&st)?;
        Ok(st.queue.len() as u64)
    }

    pub fn repair_status(&self) -> RepairStatus {
        let st = self.load_repair_state();
        RepairStatus {
            last_run_utc: st.last_run_utc,
            last: st.last,
            last_error: st.last_error,
            queued: st.queue.len() as u64,
            total_repaired: st.total_repaired,
            open_losses: st
                .queue
                .iter()
                .filter(|d| d.reason.is_some())
                .map(|d| self.unrepairable(d, d.reason.clone().unwrap_or_default()))
                .collect(),
        }
    }

    /// Whether a damaged copy is waiting and due.
    pub fn repair_due(&self, now_utc: i64) -> bool {
        self.load_repair_state()
            .queue
            .iter()
            .any(|d| d.retry_utc <= now_utc)
    }

    /// One repair run (see the module documentation).
    pub fn repair(&mut self, opts: &RepairOptions) -> Result<RepairReport> {
        self.ensure_active()?;
        if self.forked_self {
            bail!("this device's ledger is forked; it must be re-enrolled as a new device");
        }
        let result = self.one_batch(|e| e.run_repair(opts));
        if opts.dry_run {
            return result.map(|(r, _)| r);
        }
        let mut st = self.load_repair_state();
        st.last_run_utc = Some(util::now_utc());
        match result {
            Ok((mut report, queue)) => {
                // Notify each loss once; forget those no longer open.
                let open: BTreeSet<String> = queue
                    .iter()
                    .filter(|d| d.reason.is_some())
                    .map(|d| format!("{}@{}", d.object, d.storage))
                    .collect();
                report.new_losses = open.difference(&st.notified).count() as u64;
                st.notified = open;
                st.queue = queue;
                st.total_repaired += report.repaired.len() as u64;
                st.last = Some(report.clone());
                st.last_error = None;
                self.save_repair_state(&st)?;
                Ok(report)
            }
            Err(e) => {
                st.last_error = Some(format!("{e:#}"));
                self.save_repair_state(&st)?;
                Err(e)
            }
        }
    }

    fn unrepairable(&self, d: &Damage, reason: String) -> Unrepairable {
        Unrepairable {
            folder: self.folder_label(&d.folder),
            storage: d.storage.clone(),
            object: d.object.short().to_string(),
            kind: d.kind,
            reason,
        }
    }

    fn folder_label(&self, folder: &FolderId) -> String {
        self.keyring
            .folders
            .get(folder)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| folder.short().to_string())
    }

    /// The run itself; returns the report and the queue to keep.
    fn run_repair(&mut self, opts: &RepairOptions) -> Result<(RepairReport, Vec<Damage>)> {
        let now = util::now_utc();
        let mut report = RepairReport {
            started_utc: now,
            dry_run: opts.dry_run,
            ..Default::default()
        };
        let mut queue = self.load_repair_state().queue;
        if opts.scan {
            let (_, found) = self.fsck_scan(false)?;
            merge_damage(&mut queue, found);
        } else {
            self.pull_ledger_once()?;
        }
        let view = self.view()?;

        // Objects of current files in folders attached here, and where
        // their plaintext is on this device.
        let mut attached: BTreeSet<FolderId> = BTreeSet::new();
        let mut current: HashMap<ObjectName, PlainSource> = HashMap::new();
        let mut keys: BTreeMap<FolderId, FolderKeys> = BTreeMap::new();
        for (rec, mount) in self.folders() {
            let Some(mount) = mount else { continue };
            if !self.state_path(&rec.folder_id).exists() {
                continue;
            }
            attached.insert(rec.folder_id.clone());
            let state = self.load_state(&rec.folder_id)?;
            let plain = !self.mount_is_encrypted(&rec.folder_id) && !state.block_cache;
            for f in state.files.values().filter(|f| !f.deleted) {
                let on_disk = plain
                    && state
                        .local_index
                        .get(&f.path)
                        .is_some_and(|l| l.content_hash == f.content_hash);
                for c in &f.chunks {
                    let e = current.entry(c.object.clone()).or_insert(PlainSource {
                        epoch: c.epoch,
                        files: Vec::new(),
                    });
                    if on_disk {
                        e.files.push(mount.join(&f.path));
                    }
                }
            }
            if let Ok(r) = self.with_key(&rec) {
                if let Ok(k) = self.folder_keys(&r) {
                    keys.insert(rec.folder_id.clone(), k);
                }
            }
        }

        // Fewest other copies first, then oldest.
        let copies = |d: &Damage| {
            view.locate(&d.folder, &d.chunk)
                .filter(|r| r.object == d.object)
                .map(|r| r.storages.keys().filter(|s| **s != d.storage).count())
                .unwrap_or(0)
        };
        queue.sort_by(|a, b| {
            copies(a)
                .cmp(&copies(b))
                .then(a.found_utc.cmp(&b.found_utc))
                .then(a.key().cmp(&b.key()))
        });

        let specs: BTreeMap<String, StorageSpec> = self
            .config
            .storages
            .iter()
            .map(|s| (s.name().to_string(), s.clone()))
            .collect();
        let mut opened: BTreeMap<String, Box<dyn Storage>> = BTreeMap::new();
        let mut unreachable: BTreeSet<String> = BTreeSet::new();
        let mut keep: Vec<Damage> = Vec::new();
        let (mut blocks, mut bytes) = (0u64, 0u64);
        for mut d in queue {
            if !opts.retry_all && d.retry_utc > now {
                report.left_for_next_run += 1;
                keep.push(d);
                continue;
            }
            report.found += 1;
            let Some(spec) = specs.get(&d.storage) else {
                report.not_needed += 1; // the storage is gone
                continue;
            };
            if spec.is_carrier() || spec.is_cold() {
                report.not_needed += 1; // never written by repair
                continue;
            }
            if attached.contains(&d.folder) && !current.contains_key(&d.object) {
                report.not_needed += 1; // no current file uses it any more
                continue;
            }
            if blocks > 0 && (blocks >= opts.max_blocks || bytes >= opts.max_bytes) {
                report.left_for_next_run += 1;
                keep.push(d);
                continue;
            }
            if unreachable.contains(&d.storage) {
                d.retry_utc = now + RETRY_UNREACHABLE_SECS;
                report.left_for_next_run += 1;
                keep.push(d);
                continue;
            }
            if !opened.contains_key(&d.storage) {
                match self.open_spec(spec) {
                    Ok(b) => {
                        opened.insert(d.storage.clone(), b);
                    }
                    Err(e) => {
                        report.unreachable.push(format!("{} ({e:#})", d.storage));
                        unreachable.insert(d.storage.clone());
                        d.retry_utc = now + RETRY_UNREACHABLE_SECS;
                        report.left_for_next_run += 1;
                        keep.push(d);
                        continue;
                    }
                }
            }
            let key = chunk_storage_key(&d.object);
            // 1. The copy as it is now.
            let corrupt = match opened[&d.storage].get(&key) {
                Ok(Some(ct)) if ObjectName::from_bytes(&crypto::hash(&ct)) == d.object => {
                    report.already_intact += 1;
                    if !opts.dry_run {
                        self.pending.push(Event::ChunkVerified {
                            folder: d.folder.clone(),
                            chunk: d.chunk.clone(),
                            object: d.object.clone(),
                            storage: d.storage.clone(),
                        });
                    }
                    continue;
                }
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(e) => {
                    let why = match pool::pool_error(&e) {
                        Some(PoolError::NeedsDisk { .. }) => {
                            format!("{} (the disk that holds it is away)", d.storage)
                        }
                        _ => format!("{} ({e:#})", d.storage),
                    };
                    report.unreachable.push(why);
                    unreachable.insert(d.storage.clone());
                    d.retry_utc = now + RETRY_UNREACHABLE_SECS;
                    report.left_for_next_run += 1;
                    keep.push(d);
                    continue;
                }
            };
            d.kind = if corrupt {
                DamageKind::Corrupt
            } else {
                DamageKind::Missing
            };
            // 2. A good copy from somewhere else.
            let plain = current.get(&d.object);
            let found = self.repair_source(&d, &specs, &mut opened, plain, &keys, opts)?;
            let (source, ct) = match found {
                Ok(x) => x,
                Err(reason) => {
                    report
                        .unrepairable
                        .push(self.unrepairable(&d, reason.clone()));
                    d.reason = Some(reason);
                    d.retry_utc = now + RETRY_UNREPAIRABLE_SECS;
                    keep.push(d);
                    continue;
                }
            };
            blocks += 1;
            bytes += ct.len() as u64;
            let done = RepairedCopy {
                folder: self.folder_label(&d.folder),
                storage: d.storage.clone(),
                object: d.object.short().to_string(),
                kind: d.kind,
                source,
                bytes: ct.len() as u64,
            };
            if opts.dry_run {
                report.repaired.push(done);
                continue;
            }
            // 3. Write, read back, record.
            let target = &opened[&d.storage];
            let written = (|| -> Result<bool> {
                if corrupt {
                    target.delete(&key)?;
                }
                target.put_if_absent(&key, &ct)?;
                Ok(target
                    .get(&key)?
                    .is_some_and(|back| ObjectName::from_bytes(&crypto::hash(&back)) == d.object))
            })();
            match written {
                Ok(true) => {
                    report.bytes_written += ct.len() as u64;
                    report.repaired.push(done);
                    self.pending.push(Event::ChunkStored {
                        folder: d.folder.clone(),
                        chunk: d.chunk.clone(),
                        object: d.object.clone(),
                        storage: d.storage.clone(),
                        size: ct.len() as u64,
                    });
                }
                Ok(false) => {
                    let reason = format!(
                        "{} did not return the object intact after it was written again",
                        d.storage
                    );
                    report
                        .unrepairable
                        .push(self.unrepairable(&d, reason.clone()));
                    d.reason = Some(reason);
                    d.retry_utc = now + RETRY_UNREPAIRABLE_SECS;
                    keep.push(d);
                }
                Err(e) => {
                    let why = match pool::pool_error(&e) {
                        Some(PoolError::NoDiskAttached { .. }) => {
                            format!("{} (no disk attached)", d.storage)
                        }
                        Some(PoolError::NoRoom { .. }) => {
                            format!("{} (no room on the attached disks)", d.storage)
                        }
                        _ => format!("{} ({e:#})", d.storage),
                    };
                    report.unreachable.push(why);
                    unreachable.insert(d.storage.clone());
                    d.retry_utc = now + RETRY_UNREACHABLE_SECS;
                    report.left_for_next_run += 1;
                    keep.push(d);
                }
            }
        }
        report.finished_utc = util::now_utc();
        Ok((report, keep))
    }

    /// The intact ciphertext of `d.object` from somewhere other than the
    /// damaged copy, and where it came from; or why there is none.
    #[allow(clippy::type_complexity)]
    fn repair_source(
        &self,
        d: &Damage,
        specs: &BTreeMap<String, StorageSpec>,
        opened: &mut BTreeMap<String, Box<dyn Storage>>,
        plain: Option<&PlainSource>,
        keys: &BTreeMap<FolderId, FolderKeys>,
        opts: &RepairOptions,
    ) -> Result<std::result::Result<(String, Vec<u8>), String>> {
        let intact = |ct: &[u8]| ObjectName::from_bytes(&crypto::hash(ct)) == d.object;
        let key = chunk_storage_key(&d.object);
        if let Some(ct) = self.cached_object(&d.object) {
            return Ok(Ok(("block cache".to_string(), ct)));
        }
        let mut away: Vec<String> = Vec::new();
        let mut get_from =
            |name: &str, opened: &mut BTreeMap<String, Box<dyn Storage>>| -> Option<Vec<u8>> {
                if !opened.contains_key(name) {
                    let b = self.open_spec(&specs[name]).ok()?;
                    opened.insert(name.to_string(), b);
                }
                match opened[name].get(&key) {
                    Ok(Some(ct)) if intact(&ct) => Some(ct),
                    Ok(_) => None,
                    Err(e) => {
                        if matches!(pool::pool_error(&e), Some(PoolError::NeedsDisk { .. })) {
                            away.push(name.to_string());
                        }
                        None
                    }
                }
            };
        for (name, spec) in specs {
            if name == &d.storage || spec.is_cold() {
                continue;
            }
            if let Some(ct) = get_from(name, opened) {
                return Ok(Ok((format!("storage {name}"), ct)));
            }
        }
        if let (Some(p), Some(fk)) = (plain, keys.get(&d.folder)) {
            for path in &p.files {
                if let Ok(ct) = self.chunk_ciphertext_from_file(fk, path, &d.chunk, p.epoch) {
                    if intact(&ct) {
                        return Ok(Ok(("local file".to_string(), ct)));
                    }
                }
            }
        }
        if let Some((dev, ct)) = self.peers.as_ref().and_then(|p| p.get(&d.object)) {
            if intact(&ct) {
                return Ok(Ok((format!("peer {}", dev.short()), ct)));
            }
        }
        let cold: Vec<&String> = specs
            .iter()
            .filter(|(n, s)| s.is_cold() && *n != &d.storage)
            .map(|(n, _)| n)
            .collect();
        if opts.from_cold {
            for name in &cold {
                if let Some(ct) = get_from(name, opened) {
                    return Ok(Ok((format!("cold storage {name}"), ct)));
                }
            }
        }
        let view = self.view()?;
        let claimed_cold: Vec<&String> = view
            .locate(&d.folder, &d.chunk)
            .filter(|r| r.object == d.object)
            .map(|r| {
                cold.iter()
                    .filter(|c| r.storages.contains_key(c.as_str()))
                    .copied()
                    .collect()
            })
            .unwrap_or_default();
        let locked = self
            .keyring
            .folders
            .get(&d.folder)
            .is_some_and(|r| r.is_strongroom() && !self.is_unlocked(&d.folder));
        Ok(Err(if !away.is_empty() {
            format!(
                "the other copy is on a disk of {} that is not attached",
                away.join(", ")
            )
        } else if !claimed_cold.is_empty() && !opts.from_cold {
            format!(
                "a copy is on cold storage {}; run `varsto repair --from-cold` to read it (retrieval fees may apply)",
                claimed_cold
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else if locked {
            "no other copy can be read, and the Strongroom is locked (unlock it so its files can be re-encrypted)".to_string()
        } else {
            "no intact copy anywhere this device can read: not on another storage, not in this device's files or block cache, and no peer had it".to_string()
        }))
    }
}

/// Add `found` to `queue`, one entry per (object, storage); a copy found
/// again keeps its first finding time and is due at once.
pub(super) fn merge_damage(queue: &mut Vec<Damage>, found: Vec<Damage>) {
    for f in found {
        match queue.iter_mut().find(|q| q.key() == f.key()) {
            Some(q) => {
                q.kind = q.kind.max(f.kind);
                q.retry_utc = 0;
            }
            None => queue.push(f),
        }
    }
}
