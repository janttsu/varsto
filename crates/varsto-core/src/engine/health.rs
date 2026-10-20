// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Storage health: one storage that cannot be reached never fails a whole
//! run (`docs/spec/alpha-0-format.md` section 79.1).
//!
//! - **Per run.** The first network error of a storage (refused or reset
//!   connection, timeout, unknown host, an HTTP 502/503/504, an rclone
//!   remote that cannot be dialled) marks it down for the rest of the
//!   operation: `open_storages` leaves it out, and a backend opened before
//!   answers every later call at once with `StorageDown` instead of waiting
//!   for the network again. The marks end with the operation
//!   (`finish_storages`) and are set afresh when a sync starts.
//! - **Across runs.** A storage that failed rests: `state/storage-health.json`
//!   keeps when it last failed and when it is tried next (30 s, doubling
//!   up to 10 minutes). A sync that starts while it rests leaves it out
//!   from the start; the first call that succeeds clears the entry.
//!   `Engine::retry_storages_now` ends every rest (a "Retry" button).
//! - **Partial writes heal.** A record or organization object that reached
//!   only some storages is queued for the others (`heal`), and
//!   `heal_partial_writes` copies it there once they answer again.
//! - **Report.** `Engine::storage_health` lists the storages that are
//!   down or resting, for `status` and the UI.

use super::*;
use std::sync::{Arc, Mutex};

const HEALTH_FILE: &str = "storage-health.json";
/// The first rest after a failure, doubled per failure in a row up to
/// `MAX_REST_SECS`.
const FIRST_REST_SECS: i64 = 30;
const MAX_REST_SECS: i64 = 600;
/// At most this many objects wait per storage to be copied there later;
/// beyond it, the oldest are dropped (`replicate_records3` and the
/// readers' merging over all storages cover them too).
const HEAL_MAX: usize = 10_000;

/// A storage that failed with a network error, as `state/storage-health.json`
/// keeps it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct Rest {
    /// When the failures in a row began (UTC seconds).
    since_utc: i64,
    last_failure_utc: i64,
    /// Not tried by a sync before this time.
    next_try_utc: i64,
    failures: u32,
    error: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct HealthFile {
    #[serde(default)]
    down: BTreeMap<String, Rest>,
    /// Storage identities (`verify::storage_identity`) by name, so a pull
    /// can report an unreachable storage to the rollback judge.
    #[serde(default)]
    ids: BTreeMap<String, String>,
    /// Objects written to some storages but not to these (by storage name),
    /// copied there by `heal_partial_writes`.
    #[serde(default)]
    heal: BTreeMap<String, BTreeSet<String>>,
    /// The highest seq this device wrote of a record stream while one of
    /// its storages was down (`records3_io::write_record3`): a storage
    /// that holds that record may be the one that is down now.
    #[serde(default)]
    written: BTreeMap<String, u64>,
}

#[derive(Default)]
struct Inner {
    /// Storages marked down in this run: name -> why.
    dead: BTreeMap<String, String>,
    file: Option<HealthFile>,
    /// Tests: storages that fail every call as if unreachable.
    simulated: BTreeSet<String>,
    /// `Some` while a sync round runs (`Engine::sync_round`): the forks
    /// the round's ledger pull found, once it pulled.
    round: Option<Option<Vec<DeviceId>>>,
}

/// The health of the storages of one engine; cheap to clone (shared).
#[derive(Clone)]
pub(super) struct Health {
    path: PathBuf,
    inner: Arc<Mutex<Inner>>,
}

/// The error a storage marked down answers with, without asking it again.
#[derive(Debug, Clone)]
pub struct StorageDown {
    pub storage: String,
    pub reason: String,
}

impl std::fmt::Display for StorageDown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.storage.is_empty() {
            write!(f, "storage unreachable: {}", self.reason)
        } else {
            write!(
                f,
                "storage {} is unreachable ({}); skipped until it answers again",
                self.storage, self.reason
            )
        }
    }
}

impl std::error::Error for StorageDown {}

/// One storage that is down or resting, for `status` and the UI.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct StorageHealth {
    pub storage: String,
    /// Marked down during the current or last operation.
    pub down_now: bool,
    /// Failing since (UTC seconds); 0 when only this run saw it fail.
    pub since_utc: i64,
    pub last_failure_utc: i64,
    /// A sync does not try it before this time (UTC seconds).
    pub next_try_utc: i64,
    pub failures: u32,
    pub error: String,
    /// Objects waiting to be copied there once it answers.
    pub pending_writes: usize,
}

/// Whether `e` says that a storage could not be reached (as opposed to an
/// answer that was wrong: a refused key, a damaged object, a full disk).
/// Network trouble is tolerated per storage; anything else stops as before.
/// One classifier for all of Varsto: `storage::is_network_error`.
pub use crate::storage::is_network_error;

/// The rest after `failures` failures in a row.
fn rest_secs(failures: u32) -> i64 {
    let shift = failures.saturating_sub(1).min(10);
    (FIRST_REST_SECS << shift).min(MAX_REST_SECS)
}

impl Health {
    pub(super) fn new(home: &Path) -> Health {
        Health {
            path: home.join("state").join(HEALTH_FILE),
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn file<'a>(&self, inner: &'a mut Inner) -> &'a mut HealthFile {
        inner
            .file
            .get_or_insert_with(|| util::read_json_or_default(&self.path).unwrap_or_default())
    }

    fn save(&self, inner: &mut Inner) {
        let f = self.file(inner).clone();
        if let Some(dir) = self.path.parent() {
            if !dir.is_dir() {
                return; // a wiped device directory: nothing to keep
            }
        }
        if let Err(e) = util::write_json(&self.path, &f) {
            log::debug!("{}: {e:#}", self.path.display());
        }
    }

    /// Why `storage` is down in this run, if it is.
    pub(super) fn dead(&self, storage: &str) -> Option<String> {
        self.lock().dead.get(storage).cloned()
    }

    /// Note a failed call of `storage`. A network error marks it down for
    /// this run (once) and makes it rest; true when it was one.
    pub(super) fn failed(&self, storage: &str, e: &anyhow::Error) -> bool {
        if !is_network_error(e) {
            return false;
        }
        let mut inner = self.lock();
        if inner.dead.contains_key(storage) {
            return true;
        }
        let why = format!("{e:#}");
        log::warn!(storage = storage; "storage unreachable, skipped for the rest of this run: {why}");
        inner.dead.insert(storage.to_string(), why.clone());
        let now = util::now_utc();
        let f = self.file(&mut inner);
        let r = f.down.entry(storage.to_string()).or_default();
        if r.failures == 0 {
            r.since_utc = now;
        }
        r.failures = r.failures.saturating_add(1);
        r.last_failure_utc = now;
        r.next_try_utc = now + rest_secs(r.failures);
        r.error = why;
        self.save(&mut inner);
        true
    }

    /// Note a call of `storage` that succeeded: a rest it was in ends.
    pub(super) fn succeeded(&self, storage: &str) {
        let mut inner = self.lock();
        if self.file(&mut inner).down.remove(storage).is_some() {
            log::info!(storage = storage; "storage answers again");
            self.save(&mut inner);
        }
    }

    /// A new run: forget this run's marks, read what another process of
    /// this device learned, and mark the storages that still rest.
    pub(super) fn begin_run(&self) {
        let mut inner = self.lock();
        inner.dead.clear();
        inner.file = None;
        let now = util::now_utc();
        let resting: Vec<(String, String)> = self
            .file(&mut inner)
            .down
            .iter()
            .filter(|(_, r)| r.next_try_utc > now)
            .map(|(n, r)| (n.clone(), format!("resting after: {}", r.error)))
            .collect();
        for (name, why) in resting {
            log::debug!(storage = name.as_str(); "storage skipped by this sync: {why}");
            inner.dead.insert(name, why);
        }
    }

    /// The end of an operation: its marks go (the rests stay).
    pub(super) fn end_run(&self) {
        self.lock().dead.clear();
    }

    /// End every rest and mark: every storage is tried again at once.
    pub(super) fn clear(&self) {
        let mut inner = self.lock();
        inner.dead.clear();
        self.file(&mut inner).down.clear();
        self.save(&mut inner);
    }

    pub(super) fn simulate_down(&self, storage: &str, down: bool) {
        let mut inner = self.lock();
        if down {
            inner.simulated.insert(storage.to_string());
        } else {
            inner.simulated.remove(storage);
        }
    }

    fn simulated(&self, storage: &str) -> bool {
        self.lock().simulated.contains(storage)
    }

    pub(super) fn remember_id(&self, storage: &str, id: &str) {
        let mut inner = self.lock();
        let f = self.file(&mut inner);
        if f.ids.get(storage).map(String::as_str) != Some(id) {
            f.ids.insert(storage.to_string(), id.to_string());
            self.save(&mut inner);
        }
    }

    pub(super) fn known_id(&self, storage: &str) -> Option<String> {
        let mut inner = self.lock();
        self.file(&mut inner).ids.get(storage).cloned()
    }

    /// Queue `names` to be copied to `storage` once it answers.
    pub(super) fn queue_heal(&self, storage: &str, names: impl IntoIterator<Item = String>) {
        let mut inner = self.lock();
        let q = self
            .file(&mut inner)
            .heal
            .entry(storage.to_string())
            .or_default();
        q.extend(names);
        while q.len() > HEAL_MAX {
            let first = q.iter().next().cloned();
            match first {
                Some(n) => q.remove(&n),
                None => break,
            };
        }
        self.save(&mut inner);
    }

    fn heal_queue(&self) -> BTreeMap<String, BTreeSet<String>> {
        let mut inner = self.lock();
        self.file(&mut inner).heal.clone()
    }

    fn healed(&self, storage: &str, done: &BTreeSet<String>) {
        if done.is_empty() {
            return;
        }
        let mut inner = self.lock();
        let f = self.file(&mut inner);
        if let Some(q) = f.heal.get_mut(storage) {
            q.retain(|n| !done.contains(n));
            if q.is_empty() {
                f.heal.remove(storage);
            }
        }
        self.save(&mut inner);
    }

    pub(super) fn written_seq(&self, stream: &str) -> u64 {
        let mut inner = self.lock();
        self.file(&mut inner)
            .written
            .get(stream)
            .copied()
            .unwrap_or(0)
    }

    pub(super) fn note_written_seq(&self, stream: &str, seq: u64) {
        let mut inner = self.lock();
        let f = self.file(&mut inner);
        let e = f.written.entry(stream.to_string()).or_insert(0);
        if *e < seq {
            *e = seq;
            self.save(&mut inner);
        }
    }

    fn report(&self, configured: &[String]) -> Vec<StorageHealth> {
        let mut inner = self.lock();
        let dead = inner.dead.clone();
        let f = self.file(&mut inner).clone();
        let mut out = Vec::new();
        for name in configured {
            let rest = f.down.get(name);
            let now_dead = dead.get(name);
            if rest.is_none() && now_dead.is_none() {
                continue;
            }
            let r = rest.cloned().unwrap_or_default();
            out.push(StorageHealth {
                storage: name.clone(),
                down_now: now_dead.is_some(),
                since_utc: r.since_utc,
                last_failure_utc: r.last_failure_utc,
                next_try_utc: r.next_try_utc,
                failures: r.failures,
                error: if r.error.is_empty() {
                    now_dead.cloned().unwrap_or_default()
                } else {
                    r.error
                },
                pending_writes: f.heal.get(name).map_or(0, |q| q.len()),
            });
        }
        out
    }

    /// Start a sync round (`Engine::sync_round`); false when one runs.
    fn begin_round(&self) -> bool {
        let mut inner = self.lock();
        if inner.round.is_some() {
            return false;
        }
        inner.round = Some(None);
        true
    }

    fn end_round(&self) {
        self.lock().round = None;
    }

    /// The forks the current round's ledger pull found, once it pulled.
    pub(super) fn round_forks(&self) -> Option<Vec<DeviceId>> {
        self.lock().round.clone().flatten()
    }

    pub(super) fn set_round_forks(&self, forks: &[DeviceId]) {
        let mut inner = self.lock();
        if let Some(r) = inner.round.as_mut() {
            *r = Some(forks.to_vec());
        }
    }
}

/// A storage seen through the health layer: every call of a storage marked
/// down fails at once with `StorageDown`; a network error marks it down;
/// a call that succeeds ends its rest.
pub(super) struct HealthStorage {
    inner: Box<dyn Storage>,
    health: Health,
    name: String,
}

impl HealthStorage {
    pub(super) fn new(inner: Box<dyn Storage>, health: Health) -> HealthStorage {
        let name = inner.name().to_string();
        HealthStorage {
            inner,
            health,
            name,
        }
    }

    fn call<T>(&self, f: impl FnOnce(&dyn Storage) -> Result<T>) -> Result<T> {
        if let Some(reason) = self.health.dead(&self.name) {
            return Err(anyhow::Error::new(StorageDown {
                storage: self.name.clone(),
                reason,
            }));
        }
        if self.health.simulated(&self.name) {
            let e = anyhow::Error::new(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "simulated outage",
            ))
            .context(format!("storage {}", self.name));
            self.health.failed(&self.name, &e);
            return Err(e);
        }
        match f(self.inner.as_ref()) {
            Ok(v) => {
                self.health.succeeded(&self.name);
                Ok(v)
            }
            Err(e) => {
                self.health.failed(&self.name, &e);
                Err(e)
            }
        }
    }
}

impl Storage for HealthStorage {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        self.call(|s| s.put_if_absent(key, data))
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.call(|s| s.get(key))
    }
    fn get_bounded(&self, key: &str, max: u64) -> Result<Option<Vec<u8>>> {
        self.call(|s| s.get_bounded(key, max))
    }
    fn exists(&self, key: &str) -> Result<bool> {
        self.call(|s| s.exists(key))
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.call(|s| s.list(prefix))
    }
    fn list_after(&self, prefix: &str, start_after: &str) -> Result<Vec<String>> {
        self.call(|s| s.list_after(prefix, start_after))
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.call(|s| s.delete(key))
    }
    fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Option<Vec<u8>>> {
        self.call(|s| s.get_range(key, offset, len))
    }
    fn put_pack(&self, members: &[(String, &[u8])]) -> Result<Vec<bool>> {
        self.call(|s| s.put_pack(members))
    }
    fn put_built_pack(
        &self,
        id: &str,
        data: &[u8],
        members: &[(String, crate::packs::PackLoc)],
    ) -> Result<Option<Vec<bool>>> {
        self.call(|s| s.put_built_pack(id, data, members))
    }
    fn pack_target(&self) -> usize {
        self.inner.pack_target()
    }
    fn pack_location(&self, object: &str) -> Option<crate::packs::PackLoc> {
        self.inner.pack_location(object)
    }
    fn take_new_packs(&self) -> Vec<crate::packs::NewPack> {
        self.inner.take_new_packs()
    }
    fn conditional_writes(&self) -> Option<bool> {
        self.inner.conditional_writes()
    }
}

impl Engine {
    /// `Ok(Some(v))`, or `Ok(None)` when `storage` failed with a network
    /// error (it is then down for the rest of this run); other errors stay
    /// errors.
    pub(super) fn tolerate<T>(&self, storage: &str, r: Result<T>) -> Result<Option<T>> {
        match r {
            Ok(v) => Ok(Some(v)),
            Err(e) if self.health.failed(storage, &e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Whether `storage` is marked down in this run.
    pub(super) fn storage_down(&self, storage: &str) -> bool {
        self.health.dead(storage).is_some()
    }

    /// The storages that are down in this run or resting after failures,
    /// with why and when they are tried next.
    pub fn storage_health(&self) -> Vec<StorageHealth> {
        let names: Vec<String> = self
            .config
            .storages
            .iter()
            .map(|s| s.name().to_string())
            .collect();
        self.health.report(&names)
    }

    /// Try every storage again now: ends every rest (the user pressed
    /// "Retry", or the network came back).
    pub fn retry_storages_now(&mut self) {
        self.health.clear();
    }

    /// Tests: make `storage` fail every call as if it could not be reached
    /// (`down`), or answer again.
    #[doc(hidden)]
    pub fn set_storage_down_for_tests(&mut self, storage: &str, down: bool) {
        self.health.simulate_down(storage, down);
    }

    /// Run `f` as one sync round: every step in it that pulls the ledger
    /// once (`pull_ledger_once`) reuses the round's first pull instead of
    /// listing every storage again. Nested rounds join the outer one.
    pub fn sync_round<T>(&mut self, f: impl FnOnce(&mut Engine) -> Result<T>) -> Result<T> {
        if !self.health.begin_round() {
            return f(self);
        }
        let out = f(self);
        self.health.end_round();
        out
    }

    /// Copy the objects queued for storages that were down
    /// (`Health::queue_heal`) from a storage that holds them, now that they
    /// may answer. Best effort: what fails stays queued.
    pub(super) fn heal_partial_writes(&self) -> Result<usize> {
        let queue = self.health.heal_queue();
        if queue.is_empty() {
            return Ok(0);
        }
        let storages = self.metadata_storages(true)?;
        let mut copied = 0;
        for (target, names) in queue {
            let Some((_, to)) = storages.iter().find(|(s, _)| s.name() == target) else {
                if !self.config.storages.iter().any(|s| s.name() == target) {
                    // A storage removed meanwhile.
                    self.health.healed(&target, &names);
                }
                continue;
            };
            let mut done = BTreeSet::new();
            'names: for name in names {
                // Hot storages first: a cold one is read only when no hot
                // one has the object.
                let mut sources: Vec<&(StorageSpec, Box<dyn Storage>)> = storages
                    .iter()
                    .filter(|(s, _)| s.name() != target && !self.storage_down(s.name()))
                    .collect();
                sources.sort_by_key(|(s, _)| s.is_cold());
                for (spec, from) in sources {
                    let got = match self.tolerate(
                        spec.name(),
                        from.get_bounded(&name, crate::record::MAX_PART_READ),
                    ) {
                        Ok(Some(Some(b))) => b,
                        Ok(_) => continue,
                        Err(e) => {
                            log::debug!("heal {name}: {e:#}");
                            continue;
                        }
                    };
                    match self.tolerate(&target, to.put_if_absent(&name, &got)) {
                        Ok(Some(w)) => {
                            copied += usize::from(w);
                            done.insert(name);
                            continue 'names;
                        }
                        // The target is down again: the rest waits.
                        Ok(None) => break 'names,
                        Err(e) => {
                            log::warn!(storage = target.as_str(); "{name} not copied: {e:#}");
                            continue 'names;
                        }
                    }
                }
                // No reachable storage holds it any more (pruned, or only
                // on a storage that is down): kept while a source is down.
                if storages.iter().all(|(s, _)| !self.storage_down(s.name())) {
                    done.insert(name);
                }
            }
            self.health.healed(&target, &done);
        }
        Ok(copied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_errors_are_told_apart() {
        let refused = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "x",
        ))
        .context("GET s3");
        assert!(is_network_error(&refused));
        let down = anyhow::Error::new(StorageDown {
            storage: "a".into(),
            reason: "r".into(),
        });
        assert!(is_network_error(&down));
        assert!(is_network_error(&anyhow!(
            "rclone lsf ledger/: dial tcp 10.0.0.1:443: i/o timeout"
        )));
        assert!(is_network_error(&anyhow!(
            "The storage asked to slow down (storage s: GET k: HTTP 503 SlowDown)"
        )));
        assert!(!is_network_error(&anyhow!("ledger batch is not a record")));
        assert!(!is_network_error(&anyhow!(
            "The storage refused access (storage s: GET k: HTTP 403 AccessDenied)"
        )));
        let missing = anyhow::Error::new(std::io::Error::new(std::io::ErrorKind::NotFound, "x"));
        assert!(!is_network_error(&missing));
    }

    #[test]
    fn rests_double_up_to_ten_minutes() {
        assert_eq!(rest_secs(1), 30);
        assert_eq!(rest_secs(2), 60);
        assert_eq!(rest_secs(5), 480);
        assert_eq!(rest_secs(6), 600);
        assert_eq!(rest_secs(60), 600);
    }

    #[test]
    fn a_failure_marks_the_run_and_rests_across_runs() {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir_all(t.path().join("state")).unwrap();
        let h = Health::new(t.path());
        let e = anyhow::Error::new(std::io::Error::new(std::io::ErrorKind::TimedOut, "slow"));
        assert!(h.failed("s3", &e));
        assert!(h.dead("s3").is_some());
        // Not a network error: no mark.
        assert!(!h.failed("box", &anyhow!("bad record")));
        assert!(h.dead("box").is_none());
        h.end_run();
        assert!(h.dead("s3").is_none());
        // Another engine of the device (a new process) sees the rest.
        let h2 = Health::new(t.path());
        h2.begin_run();
        assert!(h2.dead("s3").is_some());
        let r = h2.report(&["s3".into(), "box".into()]);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].failures, 1);
        // An answer ends the rest.
        h2.succeeded("s3");
        let h3 = Health::new(t.path());
        h3.begin_run();
        assert!(h3.dead("s3").is_none());
    }

    #[test]
    fn a_marked_storage_answers_at_once() {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir_all(t.path().join("state")).unwrap();
        let h = Health::new(t.path());
        let dir = tempfile::tempdir().unwrap();
        let inner =
            crate::storage::LocalDirStorage::new("box".into(), dir.path().to_path_buf()).unwrap();
        let s = HealthStorage::new(Box::new(inner), h.clone());
        s.put_if_absent("a", b"1").unwrap();
        h.simulate_down("box", true);
        assert!(is_network_error(&s.get("a").unwrap_err()));
        h.simulate_down("box", false);
        // Still down for this run, without touching the storage.
        let e = s.get("a").unwrap_err();
        assert!(e.downcast_ref::<StorageDown>().is_some(), "{e:#}");
        h.end_run();
        assert_eq!(s.get("a").unwrap().unwrap(), b"1");
    }
}
