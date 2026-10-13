// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! What this device is doing right now, and what the other devices of the
//! vault said they are doing (`docs/spec/alpha-0-format.md`, section
//! "Live activity between devices").
//!
//! A process-wide, in-memory list of the long operations running now:
//! checking the blocks of a disk, uploading a folder, restoring a backup.
//! Nothing here is written anywhere: not to the ledger, not to a log, not
//! to disk. A task lives as long as its [`Guard`]:
//!
//! ```ignore
//! let task = activity::start(activity::DISK_CHECK, &disk.label, 0, Unit::Bytes);
//! // ... deep inside, without the guard at hand:
//! activity::set_current_total(total_bytes);
//! activity::advance_current(object_size);
//! ```
//!
//! Each task is counted with atomics: `advance` is one atomic add, and a
//! rate sample is taken at most twice a second (one compare-and-swap
//! decides which caller takes it). The rate is measured over the last
//! twenty seconds, so a disk that slows down shows a later finish soon.
//!
//! The running transfers of `progress` (the file being uploaded or
//! downloaded) feed the task of the same thread: `progress::Transfer::advance`
//! calls [`advance_bytes`], so an upload, a download or a restore needs only
//! its guard. Their current file name (the last path component only, never
//! the folder path) is shown as the task's `detail`.
//!
//! What is shared with the other devices of the vault (`/p2p/activity`): the
//! kind of each task, its step, the display name of the folder, disk,
//! backup or storage it works on, the current file's name for transfers,
//! the counts, the rate and the estimated finish. Never file contents,
//! never paths. In an organization only the devices of the same user ask
//! (and are answered); see `Engine::activity_audience`.

use crate::ids::DeviceId;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Kinds of tasks (the wire carries the string; a newer device may send a
/// kind an older one does not know, which it shows by its key).
pub const SYNC_SCAN: &str = "sync_scan";
pub const UPLOAD: &str = "upload";
pub const DOWNLOAD: &str = "download";
pub const DISK_CHECK: &str = "disk_check";
pub const DISK_FILL: &str = "disk_fill";
pub const BACKUP_SNAPSHOT: &str = "backup_snapshot";
pub const RESTORE: &str = "restore";
pub const REPAIR: &str = "repair";
pub const VERIFY: &str = "verify";
pub const FSCK: &str = "fsck";
pub const DATA_MOVE: &str = "data_move";
pub const STORAGE_REMOVAL: &str = "storage_removal";
/// Bit-rot check; steps "storage", "disk", "files" and "cache".
pub const SCRUB: &str = "scrub";
/// Rebuilding the ledger (`engine::ledger_recovery`); steps "local",
/// "own", "others", "manifests", "list", "verify" and "seal".
pub const LEDGER_REBUILD: &str = "ledger_rebuild";

/// What `done` and `total` count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    Bytes,
    Items,
}

/// A task younger than this is not listed: most syncs of a folder with no
/// changes are over in milliseconds and would only flicker on the screen.
pub const QUIET: Duration = Duration::from_secs(2);
/// A rate sample at most this often per task.
const SAMPLE_MS: u64 = 500;
/// The rate is measured over this much of the recent past.
const WINDOW_MS: u64 = 20_000;

fn base() -> Instant {
    static B: OnceLock<Instant> = OnceLock::new();
    *B.get_or_init(Instant::now)
}

fn now_ms() -> u64 {
    base().elapsed().as_millis() as u64
}

struct Meta {
    kind: &'static str,
    phase: &'static str,
    subject: String,
    unit: Unit,
}

struct Task {
    id: u64,
    meta: Mutex<Meta>,
    done: AtomicU64,
    total: AtomicU64,
    started: Instant,
    started_utc: i64,
    /// Milliseconds since `base()` of the last change, and of the last rate sample.
    updated_ms: AtomicU64,
    sampled_ms: AtomicU64,
    /// (milliseconds since `base()`, done) pairs within `WINDOW_MS`.
    samples: Mutex<VecDeque<(u64, u64)>>,
}

impl Task {
    fn add(&self, n: u64) {
        let done = self.done.fetch_add(n, Ordering::Relaxed) + n;
        let now = now_ms();
        self.updated_ms.store(now, Ordering::Relaxed);
        let last = self.sampled_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) >= SAMPLE_MS
            && self
                .sampled_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let mut s = self.samples.lock().unwrap_or_else(|e| e.into_inner());
            s.push_back((now, done));
            while s
                .front()
                .is_some_and(|(t, _)| now.saturating_sub(*t) > WINDOW_MS)
            {
                s.pop_front();
            }
        }
        test_delay();
    }

    fn view(&self, now_utc: i64) -> TaskView {
        let meta = self.meta.lock().unwrap_or_else(|e| e.into_inner());
        let done = self.done.load(Ordering::Relaxed);
        let total = self.total.load(Ordering::Relaxed);
        let now = now_ms();
        let rate = {
            let s = self.samples.lock().unwrap_or_else(|e| e.into_inner());
            rate_from(s.front().copied(), now, done)
        };
        let updated = self.updated_ms.load(Ordering::Relaxed);
        TaskView {
            id: self.id,
            kind: meta.kind.to_string(),
            phase: meta.phase.to_string(),
            subject: meta.subject.clone(),
            detail: None,
            done,
            total,
            unit: meta.unit,
            percent: percent(done, total),
            started_utc: self.started_utc,
            updated_utc: now_utc - (now.saturating_sub(updated) / 1000) as i64,
            rate,
            eta_utc: eta(now_utc, done, total, rate),
        }
    }
}

/// Units per second over the sampling window (from its oldest sample to
/// now); 0 while the window spans less than a second.
fn rate_from(oldest: Option<(u64, u64)>, now_ms: u64, done: u64) -> u64 {
    match oldest {
        Some((t, d)) if now_ms.saturating_sub(t) >= 1000 => {
            (done.saturating_sub(d) as f64 * 1000.0 / now_ms.saturating_sub(t) as f64) as u64
        }
        _ => 0,
    }
}

fn percent(done: u64, total: u64) -> Option<u32> {
    (total > 0).then(|| ((done as u128 * 100 / total as u128).min(100)) as u32)
}

fn eta(now_utc: i64, done: u64, total: u64, rate: u64) -> Option<i64> {
    (total > done && rate > 0).then(|| now_utc + (total - done).div_ceil(rate) as i64)
}

static TASKS: Mutex<Vec<Arc<Task>>> = Mutex::new(Vec::new());
static NEXT: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// The tasks this thread started and has not finished, innermost last.
    static STACK: RefCell<Vec<Arc<Task>>> = const { RefCell::new(Vec::new()) };
}

/// One task for its lifetime: listed from `start` until dropped (also when
/// the operation fails). Not `Send`: the task belongs to the thread that
/// runs it, whose deeper code reaches it through `advance_current`.
pub struct Guard {
    task: Arc<Task>,
    _thread: std::marker::PhantomData<*const ()>,
}

/// Start a task: `kind` is one of the constants above, `subject` the display
/// name of what it works on ("" for the whole vault), `total` 0 when unknown.
pub fn start(kind: &'static str, subject: &str, total: u64, unit: Unit) -> Guard {
    let started = Instant::now();
    let _ = base();
    let at = now_ms();
    let task = Arc::new(Task {
        id: NEXT.fetch_add(1, Ordering::Relaxed),
        meta: Mutex::new(Meta {
            kind,
            phase: "",
            subject: subject.to_string(),
            unit,
        }),
        done: AtomicU64::new(0),
        total: AtomicU64::new(total),
        started,
        started_utc: crate::util::now_utc(),
        updated_ms: AtomicU64::new(at),
        sampled_ms: AtomicU64::new(at),
        samples: Mutex::new(VecDeque::from([(at, 0)])),
    });
    TASKS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(task.clone());
    STACK.with(|s| s.borrow_mut().push(task.clone()));
    Guard {
        task,
        _thread: std::marker::PhantomData,
    }
}

impl Guard {
    pub fn advance(&self, n: u64) {
        self.task.add(n);
    }
    pub fn set_total(&self, total: u64) {
        self.task.total.store(total, Ordering::Relaxed);
    }
    /// Name the step running now (`verify`, `fill`, `scan`, `upload`, ...).
    pub fn set_phase(&self, phase: &'static str) {
        self.task
            .meta
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .phase = phase;
    }
    /// A new step with its own counts: `done` starts again from zero.
    pub fn step(&self, phase: &'static str, total: u64, unit: Unit) {
        {
            let mut m = self.task.meta.lock().unwrap_or_else(|e| e.into_inner());
            m.phase = phase;
            m.unit = unit;
        }
        self.task.done.store(0, Ordering::Relaxed);
        self.task.total.store(total, Ordering::Relaxed);
        let now = now_ms();
        self.task.sampled_ms.store(now, Ordering::Relaxed);
        *self.task.samples.lock().unwrap_or_else(|e| e.into_inner()) = VecDeque::from([(now, 0)]);
    }
    pub fn id(&self) -> u64 {
        self.task.id
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let id = self.task.id;
        TASKS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|t| t.id != id);
        let _ = STACK.try_with(|s| s.borrow_mut().retain(|t| t.id != id));
    }
}

fn current() -> Option<Arc<Task>> {
    STACK
        .try_with(|s| s.borrow().last().cloned())
        .ok()
        .flatten()
}

/// Count `n` on this thread's innermost task, if any.
pub fn advance_current(n: u64) {
    if let Some(t) = current() {
        t.add(n);
    }
}

/// Count `n` bytes on this thread's innermost task when it counts bytes:
/// how file transfers (`progress`) feed uploads, downloads and restores.
pub fn advance_bytes(n: u64) {
    if let Some(t) = current() {
        if t.meta.lock().unwrap_or_else(|e| e.into_inner()).unit == Unit::Bytes {
            t.add(n);
        }
    }
}

/// Set the total of this thread's innermost task (code that learns the
/// amount of work deeper than where the task started).
pub fn set_current_total(total: u64) {
    if let Some(t) = current() {
        t.total.store(total, Ordering::Relaxed);
    }
}

/// Slow every counted step down by this many milliseconds: for tests that
/// watch a long operation from another device. `VARSTO_ACTIVITY_TEST_DELAY_MS`
/// sets it for a whole process (the lab's services).
static DELAY_MS: AtomicU64 = AtomicU64::new(0);
static DELAY_ENV: OnceLock<u64> = OnceLock::new();

#[doc(hidden)]
pub fn set_test_delay_ms(ms: u64) {
    DELAY_MS.store(ms, Ordering::Relaxed);
}

fn test_delay() {
    let env = *DELAY_ENV.get_or_init(|| {
        std::env::var("VARSTO_ACTIVITY_TEST_DELAY_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    });
    let ms = DELAY_MS.load(Ordering::Relaxed).max(env);
    if ms > 0 {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

/// One task as shown to the user and sent to the other devices.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TaskView {
    pub id: u64,
    pub kind: String,
    /// The step running now; "" when the task has one step.
    #[serde(default)]
    pub phase: String,
    /// Display name of the folder, disk, backup or storage; "" for the vault.
    #[serde(default)]
    pub subject: String,
    /// The file being transferred now: its name only, never its path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub done: u64,
    /// 0: not known (yet).
    pub total: u64,
    pub unit: Unit,
    #[serde(default)]
    pub percent: Option<u32>,
    pub started_utc: i64,
    pub updated_utc: i64,
    /// Units per second over the last twenty seconds; 0 when not known yet.
    #[serde(default)]
    pub rate: u64,
    #[serde(default)]
    pub eta_utc: Option<i64>,
}

/// Every task running now that is older than `quiet`, oldest first.
fn tasks_older_than(quiet: Duration) -> Vec<TaskView> {
    let now = crate::util::now_utc();
    let list: Vec<Arc<Task>> = TASKS.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let transfers = crate::progress::all();
    list.iter()
        .filter(|t| t.started.elapsed() >= quiet)
        .map(|t| {
            let mut v = t.view(now);
            if matches!(v.kind.as_str(), UPLOAD | DOWNLOAD | RESTORE) {
                let want = if v.kind == UPLOAD {
                    "upload"
                } else {
                    "download"
                };
                v.detail = transfers
                    .iter()
                    .rev()
                    .find(|p| p.kind == want && p.folder == v.subject)
                    .and_then(|p| p.path.rsplit('/').next().map(str::to_string))
                    .filter(|n| !n.is_empty());
            }
            v
        })
        .collect()
}

/// The tasks worth showing now (running for at least `QUIET`): this
/// process's, and those other processes of this device reported
/// (`merge_external`).
pub fn tasks() -> Vec<TaskView> {
    let mut out = tasks_older_than(QUIET);
    let mut ext = EXTERNAL.lock().unwrap_or_else(|e| e.into_inner());
    ext.retain(|_, (at, _)| at.elapsed() < EXTERNAL_TTL);
    for (_, list) in ext.values() {
        out.extend(list.iter().cloned());
    }
    out.sort_by_key(|t| t.started_utc);
    out
}

/// Tasks of other processes of this device (a command run in a terminal
/// while the service runs), by process id, with when they were reported.
/// Forgotten when a process stops reporting for `EXTERNAL_TTL`.
type External = BTreeMap<u32, (Instant, Vec<TaskView>)>;
static EXTERNAL: Mutex<External> = Mutex::new(BTreeMap::new());
const EXTERNAL_TTL: Duration = Duration::from_secs(5);
/// What one report may carry.
const EXTERNAL_MAX: usize = 64;

/// The service takes the tasks a command of this device runs: they are
/// part of this device's activity. An empty list removes the process.
pub fn merge_external(pid: u32, mut tasks: Vec<TaskView>) {
    let mut ext = EXTERNAL.lock().unwrap_or_else(|e| e.into_inner());
    if tasks.is_empty() {
        ext.remove(&pid);
        return;
    }
    tasks.truncate(EXTERNAL_MAX);
    for t in &mut tasks {
        // Unique beside the service's own task numbers.
        t.id = (u64::from(pid) << 32) | (t.id & 0xffff_ffff);
    }
    ext.insert(pid, (Instant::now(), tasks));
}

/// In a command that is not the service: hand this process's tasks to
/// `send` every second while there are any (and once more when the last
/// one ended), so the service shows and tells them as this device's.
pub fn spawn_reporter<F>(send: F)
where
    F: Fn(&[TaskView]) + Send + 'static,
{
    let _ = std::thread::Builder::new()
        .name("activity-report".into())
        .spawn(move || {
            let mut had = false;
            loop {
                std::thread::sleep(Duration::from_secs(1));
                let now = tasks_older_than(QUIET);
                if !now.is_empty() || had {
                    send(&now);
                }
                had = !now.is_empty();
            }
        });
}

/// The English sentence for a task, without its counts: "checking the
/// blocks of disk «Blue 4TB»". The interface builds its own from the
/// translated templates of the same kinds and steps.
pub fn describe(t: &TaskView) -> String {
    let s = &t.subject;
    let mut out = match (t.kind.as_str(), t.phase.as_str()) {
        (SYNC_SCAN, _) => format!("looking for changes in folder «{s}»"),
        (UPLOAD, _) => format!("uploading folder «{s}»"),
        (DOWNLOAD, _) => format!("fetching changes to folder «{s}»"),
        (DISK_CHECK, "fill") | (DISK_FILL, _) => format!("filling disk «{s}»"),
        (DISK_CHECK, "verify") => format!("checking the blocks of disk «{s}»"),
        (DISK_CHECK, _) => format!("checking disk «{s}»"),
        (BACKUP_SNAPSHOT, _) => format!("taking a snapshot of backup «{s}»"),
        (RESTORE, _) => format!("restoring backup «{s}»"),
        (REPAIR, _) => "repairing damaged block copies".to_string(),
        (VERIFY, _) => "verifying stored blocks".to_string(),
        (FSCK, "verify") => "verifying every block of the vault".to_string(),
        (FSCK, _) => "checking the vault".to_string(),
        (DATA_MOVE, _) => format!("moving the data of folder «{s}»"),
        (STORAGE_REMOVAL, "delete") => format!("deleting the data on storage «{s}»"),
        (STORAGE_REMOVAL, _) => format!("copying blocks off storage «{s}»"),
        (SCRUB, "disk") => format!("checking disk «{s}» for bit rot"),
        (SCRUB, "files") => format!("checking the files of folder «{s}» for bit rot"),
        (SCRUB, "cache") => "checking the block cache for bit rot".to_string(),
        (SCRUB, _) => format!("checking storage «{s}» for bit rot"),
        (k, _) if s.is_empty() => k.replace('_', " "),
        (k, _) => format!("{} «{s}»", k.replace('_', " ")),
    };
    if let Some(d) = &t.detail {
        out.push_str(&format!(" ({d})"));
    }
    out
}

/// What the items of a task are, for counts: "120 of 400 files".
pub fn item_noun(kind: &str) -> &'static str {
    match kind {
        SYNC_SCAN => "files",
        REPAIR => "copies",
        _ => "blocks",
    }
}

/// What one device says it is doing.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DeviceActivity {
    pub device: String,
    pub name: String,
    /// `idle` or `busy`.
    pub state: String,
    pub tasks: Vec<TaskView>,
    #[serde(default)]
    pub service_version: String,
    pub updated_utc: i64,
}

static ME: Mutex<Option<(DeviceId, String)>> = Mutex::new(None);

/// The device this process runs as (set when the vault opens).
pub fn set_identity(device: &DeviceId, name: &str) {
    *ME.lock().unwrap_or_else(|e| e.into_inner()) = Some((device.clone(), name.to_string()));
}

fn report(device: &DeviceId, name: &str, tasks: Vec<TaskView>) -> DeviceActivity {
    DeviceActivity {
        device: device.to_string(),
        name: name.to_string(),
        state: if tasks.is_empty() { "idle" } else { "busy" }.into(),
        tasks,
        service_version: env!("CARGO_PKG_VERSION").to_string(),
        updated_utc: crate::util::now_utc(),
    }
}

/// This device's activity, as `/p2p/activity` answers it.
pub fn local(device: &DeviceId) -> DeviceActivity {
    let name = ME
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .filter(|(d, _)| d == device)
        .map(|(_, n)| n.clone())
        .unwrap_or_default();
    report(device, &name, tasks())
}

/// This device's activity for the local interface (no device id known
/// while locked: empty id).
pub fn local_here() -> DeviceActivity {
    let me = ME.lock().unwrap_or_else(|e| e.into_inner()).clone();
    match me {
        Some((d, n)) => report(&d, &n, tasks()),
        None => {
            let mut r = report(&DeviceId::from_bytes(&[0u8; 16]), "", tasks());
            r.device.clear();
            r
        }
    }
}

// ----- the other devices' activity ------------------------------------------

/// The local interface or the command line asked within this long: the
/// service keeps asking the peers.
pub const WATCH_FOR: Duration = Duration::from_secs(15);
/// A peer is asked at most this often.
pub const PEER_EVERY: Duration = Duration::from_millis(2500);
/// An answer older than this is shown as stale.
pub const STALE_AFTER: Duration = Duration::from_secs(10);

/// What we last heard from one peer.
#[derive(Clone, Debug)]
struct Heard {
    name: String,
    activity: Option<DeviceActivity>,
    asked: Option<Instant>,
    answered: Option<Instant>,
    /// `ok`, `unreachable`, `unsupported` (an older version), `refused`, `pending`.
    status: &'static str,
}

/// One peer for the local interface.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PeerActivity {
    pub device: String,
    pub name: String,
    /// `ok`, `unreachable`, `unsupported`, `refused` or `pending`.
    pub status: String,
    /// The last answer is older than `STALE_AFTER`.
    pub stale: bool,
    /// Seconds since the last answer; none before the first one.
    pub age_secs: Option<u64>,
    pub activity: Option<DeviceActivity>,
}

/// The peers' activity, fetched only while someone watches. One per
/// process (`global`); tests make their own.
pub struct PeerCache {
    watched_ms: AtomicI64,
    peers: Mutex<Option<Arc<crate::p2p::Peers>>>,
    /// In an organization: the only devices asked (and answered).
    audience: Mutex<Option<BTreeSet<DeviceId>>>,
    heard: Mutex<BTreeMap<DeviceId, Heard>>,
}

impl Default for PeerCache {
    fn default() -> Self {
        PeerCache {
            watched_ms: AtomicI64::new(-1),
            peers: Mutex::new(None),
            audience: Mutex::new(None),
            heard: Mutex::new(BTreeMap::new()),
        }
    }
}

impl PeerCache {
    /// Someone looks at the activity now (the local interface, the CLI).
    pub fn watch(&self) {
        self.watched_ms.store(now_ms() as i64, Ordering::Relaxed);
    }

    pub fn watched(&self) -> bool {
        let at = self.watched_ms.load(Ordering::Relaxed);
        at >= 0 && now_ms().saturating_sub(at as u64) <= WATCH_FOR.as_millis() as u64
    }

    /// The peer table to ask (the service's, rebuilt every sync), and in an
    /// organization the devices of this user. `None` stops the asking.
    pub fn set_peers(
        &self,
        peers: Option<Arc<crate::p2p::Peers>>,
        audience: Option<BTreeSet<DeviceId>>,
    ) {
        *self.peers.lock().unwrap_or_else(|e| e.into_inner()) = peers;
        *self.audience.lock().unwrap_or_else(|e| e.into_inner()) = audience;
    }

    /// Ask every peer that is due, in parallel, when someone watches.
    /// Returns how many were asked.
    pub fn poll(&self) -> usize {
        if !self.watched() {
            return 0;
        }
        let Some(peers) = self.peers.lock().unwrap_or_else(|e| e.into_inner()).clone() else {
            return 0;
        };
        let audience = self
            .audience
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let due: Vec<(DeviceId, String)> = {
            let mut heard = self.heard.lock().unwrap_or_else(|e| e.into_inner());
            // Devices that left the table (removed, or another organization user) go.
            heard.retain(|d, _| {
                peers.peers.iter().any(|p| &p.device == d)
                    && audience.as_ref().is_none_or(|a| a.contains(d))
            });
            peers
                .peers
                .iter()
                .filter(|p| audience.as_ref().is_none_or(|a| a.contains(&p.device)))
                .filter_map(|p| {
                    let h = heard.entry(p.device.clone()).or_insert_with(|| Heard {
                        name: p.name.clone(),
                        activity: None,
                        asked: None,
                        answered: None,
                        status: "pending",
                    });
                    if !p.name.is_empty() {
                        h.name = p.name.clone();
                    }
                    if h.asked.is_some_and(|t| t.elapsed() < PEER_EVERY) {
                        return None;
                    }
                    h.asked = Some(Instant::now());
                    Some((p.device.clone(), p.name.clone()))
                })
                .collect()
        };
        std::thread::scope(|s| {
            for (dev, _) in &due {
                let peers = &peers;
                s.spawn(move || {
                    let got = peers.ask(dev, "/p2p/activity");
                    let mut heard = self.heard.lock().unwrap_or_else(|e| e.into_inner());
                    let Some(h) = heard.get_mut(dev) else { return };
                    match got {
                        Some((200, body)) => {
                            match serde_json::from_slice::<DeviceActivity>(&body) {
                                Ok(a) if a.device == dev.as_str() => {
                                    if !a.name.is_empty() {
                                        h.name = a.name.clone();
                                    }
                                    h.activity = Some(a);
                                    h.answered = Some(Instant::now());
                                    h.status = "ok";
                                }
                                _ => h.status = "unsupported",
                            }
                        }
                        Some((404, _)) => h.status = "unsupported",
                        Some((403, _)) => h.status = "refused",
                        Some(_) | None => h.status = "unreachable",
                    }
                });
            }
        });
        due.len()
    }

    /// What we know about every peer now.
    pub fn report(&self) -> Vec<PeerActivity> {
        let heard = self.heard.lock().unwrap_or_else(|e| e.into_inner());
        heard
            .iter()
            .map(|(d, h)| {
                let age = h.answered.map(|t| t.elapsed());
                PeerActivity {
                    device: d.to_string(),
                    name: h.name.clone(),
                    status: h.status.to_string(),
                    stale: age.is_some_and(|a| a > STALE_AFTER),
                    age_secs: age.map(|a| a.as_secs()),
                    activity: h.activity.clone(),
                }
            })
            .collect()
    }

    /// Ask the peers every half second while watched, until `stop`.
    pub fn spawn_poller(&'static self, stop: Arc<AtomicBool>) {
        let _ = std::thread::Builder::new()
            .name("activity".into())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    self.poll();
                    std::thread::sleep(Duration::from_millis(500));
                }
            });
    }
}

/// The process's peer cache (the service's).
pub fn global() -> &'static PeerCache {
    static C: OnceLock<PeerCache> = OnceLock::new();
    C.get_or_init(PeerCache::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mine(id: u64) -> Option<TaskView> {
        tasks_older_than(Duration::ZERO)
            .into_iter()
            .find(|t| t.id == id)
    }

    #[test]
    fn a_guard_lists_its_task_until_dropped() {
        let id;
        {
            let g = start(DISK_CHECK, "Blue 4TB", 0, Unit::Bytes);
            id = g.id();
            let v = mine(id).unwrap();
            assert_eq!(
                (v.kind.as_str(), v.subject.as_str()),
                ("disk_check", "Blue 4TB")
            );
            assert_eq!((v.done, v.total, v.percent, v.eta_utc), (0, 0, None, None));
            // Deep code reaches the innermost task of its thread.
            set_current_total(400);
            advance_current(100);
            g.set_phase("verify");
            let v = mine(id).unwrap();
            assert_eq!((v.done, v.total, v.percent), (100, 400, Some(25)));
            assert_eq!(v.phase, "verify");
            g.step("fill", 10, Unit::Items);
            advance_bytes(5); // a transfer does not count on an item task
            g.advance(4);
            let v = mine(id).unwrap();
            assert_eq!(
                (v.phase.as_str(), v.done, v.total, v.unit),
                ("fill", 4, 10, Unit::Items)
            );
        }
        assert!(mine(id).is_none());
        // Nothing left on this thread to count on.
        advance_current(1);
    }

    #[test]
    fn nested_tasks_count_on_the_innermost_and_young_ones_are_quiet() {
        let outer = start(BACKUP_SNAPSHOT, "pics", 0, Unit::Items);
        {
            let inner = start(UPLOAD, "pics", 1000, Unit::Bytes);
            advance_bytes(300);
            assert_eq!(mine(inner.id()).unwrap().done, 300);
            assert_eq!(mine(outer.id()).unwrap().done, 0);
            // Just started: not listed for the interface and the peers.
            assert!(tasks().iter().all(|t| t.id != inner.id()));
        }
        advance_current(2);
        assert_eq!(mine(outer.id()).unwrap().done, 2);
        // Another thread has its own innermost task (none).
        std::thread::spawn(|| advance_current(7)).join().unwrap();
        assert_eq!(mine(outer.id()).unwrap().done, 2);
    }

    #[test]
    fn tasks_of_other_processes_are_merged_and_forgotten() {
        let t = TaskView {
            id: 7,
            kind: DISK_CHECK.into(),
            phase: "verify".into(),
            subject: "Blue".into(),
            detail: None,
            done: 1,
            total: 2,
            unit: Unit::Bytes,
            percent: Some(50),
            started_utc: 0,
            updated_utc: 0,
            rate: 0,
            eta_utc: None,
        };
        merge_external(4242, vec![t.clone()]);
        let got: Vec<TaskView> = tasks()
            .into_iter()
            .filter(|x| x.subject == "Blue")
            .collect();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].id, (4242u64 << 32) | 7);
        merge_external(4242, Vec::new());
        assert!(tasks().iter().all(|x| x.subject != "Blue"));
    }

    #[test]
    fn rate_uses_the_window_and_eta_follows() {
        // Under a second of history: unknown.
        assert_eq!(rate_from(Some((0, 0)), 500, 100), 0);
        assert_eq!(rate_from(None, 5000, 100), 0);
        // 2 000 units in 2 s.
        assert_eq!(rate_from(Some((0, 0)), 2000, 2000), 1000);
        // Window from t=10 s with 5 000 done, now t=20 s with 25 000: 2 000/s,
        // although the average since the start (t=0) is 1 250/s.
        assert_eq!(rate_from(Some((10_000, 5_000)), 20_000, 25_000), 2000);
        assert_eq!(eta(1_000, 25_000, 45_000, 2000), Some(1_010));
        assert_eq!(eta(1_000, 45_000, 45_000, 2000), None);
        assert_eq!(eta(1_000, 5, 45_000, 0), None);
        assert_eq!(percent(1, 3), Some(33));
        assert_eq!(percent(5, 0), None);
        assert_eq!(percent(u64::MAX, u64::MAX / 2), Some(100));
    }

    #[test]
    fn samples_are_throttled() {
        let g = start(VERIFY, "", 1_000_000, Unit::Items);
        for _ in 0..10_000 {
            g.advance(1);
        }
        // One sample at the start, at most one more in the first half second.
        let n = g.task.samples.lock().unwrap().len();
        assert!(n <= 2, "{n} samples");
        assert_eq!(g.task.done.load(Ordering::Relaxed), 10_000);
    }

    #[test]
    fn nobody_watching_means_no_asking() {
        let cache = PeerCache::default();
        // A peer on a closed port of this machine.
        let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let peers = Arc::new(crate::p2p::Peers::new(
            crate::crypto::SecretKey::random(),
            DeviceId::random(),
            vec![crate::p2p::PeerAddr {
                device: DeviceId::random(),
                addr,
                name: "desk".into(),
            }],
        ));
        cache.set_peers(Some(peers.clone()), None);
        assert!(!cache.watched());
        assert_eq!(cache.poll(), 0);
        assert!(cache.report().is_empty());
        cache.watch();
        assert_eq!(cache.poll(), 1);
        let r = cache.report();
        assert_eq!(
            (r[0].name.as_str(), r[0].status.as_str()),
            ("desk", "unreachable")
        );
        // Asked again only after `PEER_EVERY`.
        assert_eq!(cache.poll(), 0);
        // A device outside the audience (another user of the organization) is not asked.
        let other = PeerCache::default();
        other.set_peers(Some(peers), Some(BTreeSet::new()));
        other.watch();
        assert_eq!(other.poll(), 0);
    }
}
