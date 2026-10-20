// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The last answers of the read-only GET routes the interface polls (spec
//! section 71). A sync, a verification or a ledger merge holds the state for
//! seconds to minutes; a poll that finds it busy for longer than
//! [`FRESH_WAIT`] gets the last answer of the same address instead of
//! waiting, marked stale with its age. Any change made through the API
//! (every request that is not a GET) empties the cache, so a page never sees
//! an answer older than its own change. With no answer kept, a read waits
//! at most [`BUSY_WAIT`] and is then answered "busy" (503), never held up
//! by a sync on a slow or dead link (spec section 79.3).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long a read waits for a busy state before the cached answer is used.
pub const FRESH_WAIT: Duration = Duration::from_millis(50);
/// At most this many addresses are kept ...
const MAX_ENTRIES: usize = 128;
/// ... and at most this many bytes of answers in all; an answer larger than
/// half of it is not kept (the file list of a folder of 50 000 files is
/// about 18 MiB).
const MAX_BYTES: usize = 64 << 20;

/// Bumped by [`invalidate_all`]: the service's own work (not an API request)
/// changed what the reads show, e.g. a device joined.
static EXTERNAL: AtomicU64 = AtomicU64::new(0);

/// Forget every kept answer of every cache: something the service did on
/// its own (a new device turned up, the peer table changed) makes the
/// answers from before wrong, and a poll that finds the state busy must not
/// be given them.
pub fn invalidate_all() {
    EXTERNAL.fetch_add(1, Ordering::SeqCst);
}

/// The GET routes that only read the state and are answered from the cache
/// while it is busy. Routes that take something away (`/api/link`), talk to
/// other machines or stream are not here.
pub const ROUTES: &[&str] = &[
    "/api/state",
    "/api/service",
    "/api/status",
    "/api/folders",
    "/api/devices",
    "/api/p2p",
    "/api/policy",
    "/api/advice",
    "/api/placement",
    "/api/verify",
    "/api/scrub",
    "/api/repair",
    "/api/ledger",
    "/api/ledger/health",
    "/api/ledger/status",
    "/api/trash",
    "/api/trash/status",
    "/api/history",
    "/api/history/status",
    "/api/storage/known",
    "/api/storage/costs",
    "/api/storage/quotas",
    "/api/storage/drains",
    "/api/data/locations",
    "/api/backups",
    "/api/backup/snapshots",
    "/api/files",
    "/api/changes",
    "/api/moves",
    "/api/disks",
    "/api/disk/suggest",
    "/api/disk/groups",
    "/api/strongroom",
    "/api/org",
    "/api/org/log",
    "/api/share/members",
    "/api/import/status",
    "/api/folder/settings",
    "/api/folder/ignore",
    "/api/update/settings",
    "/api/analysis",
    "/api/analyses",
    "/api/dupes",
];

/// Whether a GET of `path` may be answered from the cache.
pub fn cacheable(path: &str) -> bool {
    ROUTES.contains(&path)
}

/// Requests that run a long operation without changing any setting (as the
/// service's own syncs and checks do): the answers from before stay usable,
/// marked stale, while the state is busy, and the next fresh answer
/// replaces them.
pub const RUNS: &[&str] = &[
    "/api/sync",
    "/api/verify/run",
    "/api/scrub/run",
    "/api/fsck",
];

/// Whether a request that is not a GET empties the cache (when it arrives
/// and again when it has been answered).
pub fn drops_answers(path: &str) -> bool {
    !RUNS.contains(&path)
}

struct Entry {
    at: Instant,
    body: Arc<String>,
}

/// The cached answers, by address (path and query).
#[derive(Default)]
pub struct ReadCache {
    entries: HashMap<String, Entry>,
    bytes: usize,
    generation: u64,
    /// The value of `EXTERNAL` the entries were kept under.
    external: u64,
}

impl ReadCache {
    /// Changes when the cache is emptied: an answer computed before that is
    /// not kept.
    pub fn generation(&mut self) -> u64 {
        self.follow_external();
        self.generation
    }

    /// Empty the cache when `invalidate_all` was called since it was used.
    fn follow_external(&mut self) {
        self.follow_external_at(EXTERNAL.load(Ordering::SeqCst));
    }

    fn follow_external_at(&mut self, now: u64) {
        if now != self.external {
            self.external = now;
            self.invalidate();
        }
    }

    /// Forget every answer (something was changed).
    pub fn invalidate(&mut self) {
        self.entries.clear();
        self.bytes = 0;
        self.generation += 1;
    }

    /// Keep `body` as the answer of `key`, unless the cache was emptied since
    /// `generation` was read or the answer is too large. Returns whether it
    /// was kept.
    pub fn store(&mut self, key: &str, generation: u64, body: Arc<String>, now: Instant) -> bool {
        self.follow_external();
        if generation != self.generation || body.len() > MAX_BYTES / 2 {
            return false;
        }
        if let Some(old) = self.entries.remove(key) {
            self.bytes -= old.body.len();
        }
        while !self.entries.is_empty()
            && (self.entries.len() >= MAX_ENTRIES || self.bytes + body.len() > MAX_BYTES)
        {
            // The oldest answer goes first.
            let Some(k) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.at)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            if let Some(e) = self.entries.remove(&k) {
                self.bytes -= e.body.len();
            }
        }
        self.bytes += body.len();
        self.entries
            .insert(key.to_string(), Entry { at: now, body });
        true
    }

    /// The last answer of `key` and its age.
    pub fn get(&mut self, key: &str, now: Instant) -> Option<(Duration, Arc<String>)> {
        self.follow_external();
        self.entries
            .get(key)
            .map(|e| (now.saturating_duration_since(e.at), e.body.clone()))
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// With no answer kept, a read waits this long for a busy state (or engine)
/// and is then answered "busy" (503): a page polls again anyway, and a
/// sync on a slow or dead link can hold the engine for many minutes.
pub const BUSY_WAIT: Duration = Duration::from_secs(2);

/// The state (`G`: a lock guard, or the engine taken out of the state), or
/// the cached answer while it stays busy.
pub enum Got<G> {
    /// The state is ours: compute a fresh answer (and keep it).
    Fresh(G),
    /// The state stayed busy for `wait`: the last answer and its age.
    Cached(Duration, Arc<String>),
    /// Busy for `busy_wait` too, and nothing kept for this address.
    Busy,
}

/// Take what `take` gives if it gives it within `wait`; otherwise answer
/// from `cache` when it has `key`; without any answer keep trying until
/// `busy_wait` is up, then say busy.
pub fn take_or_cached<G>(
    mut take: impl FnMut() -> Option<G>,
    cache: &Mutex<ReadCache>,
    key: &str,
    wait: Duration,
    busy_wait: Duration,
) -> Got<G> {
    let start = Instant::now();
    let mut looked = false;
    loop {
        if let Some(g) = take() {
            return Got::Fresh(g);
        }
        let waited = start.elapsed();
        if waited >= wait && !looked {
            looked = true;
            let hit = cache
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(key, Instant::now());
            if let Some((age, body)) = hit {
                return Got::Cached(age, body);
            }
        }
        if waited >= busy_wait {
            return Got::Busy;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// [`take_or_cached`] on a plain lock, saying busy after [`BUSY_WAIT`].
#[cfg(test)]
pub fn lock_or_cached<'a, T>(
    state: &'a Mutex<T>,
    cache: &Mutex<ReadCache>,
    key: &str,
    wait: Duration,
) -> Got<std::sync::MutexGuard<'a, T>> {
    use std::sync::TryLockError;
    take_or_cached(
        || match state.try_lock() {
            Ok(g) => Some(g),
            Err(TryLockError::Poisoned(p)) => Some(p.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        },
        cache,
        key,
        wait,
        BUSY_WAIT,
    )
}

/// A cached JSON answer marked stale: objects get `"stale": true` and
/// `"stale_ms"` (arrays are sent as they are; the headers say it too).
pub fn mark_stale(body: &str, age: Duration) -> String {
    match serde_json::from_str::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(mut m)) => {
            m.insert("stale".into(), serde_json::Value::Bool(true));
            m.insert("stale_ms".into(), (age.as_millis() as u64).into());
            serde_json::Value::Object(m).to_string()
        }
        _ => body.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_are_kept_by_address_until_a_change() {
        let mut c = ReadCache::default();
        let now = Instant::now();
        let g = c.generation();
        assert!(c.store("/api/status", g, Arc::new("{\"a\":1}".into()), now));
        assert!(c.store("/api/files?folder=A", g, Arc::new("[]".into()), now));
        let (age, body) = c.get("/api/status", now + Duration::from_secs(2)).unwrap();
        assert_eq!((age, body.as_str()), (Duration::from_secs(2), "{\"a\":1}"));
        assert!(c.get("/api/files?folder=B", now).is_none());
        c.invalidate();
        assert!(c.get("/api/status", now).is_none());
        // An answer computed before the change is not kept.
        assert!(!c.store("/api/status", g, Arc::new("{}".into()), now));
        assert!(c.get("/api/status", now).is_none());
        let g = c.generation();
        assert!(c.store("/api/status", g, Arc::new("{}".into()), now));
    }

    #[test]
    fn work_of_the_service_itself_empties_the_answers() {
        // `invalidate_all` bumps a process-wide number that every cache
        // follows (checked here with explicit numbers: the real one is shared
        // with the tests running beside this one).
        let mut c = ReadCache::default();
        let now = Instant::now();
        let g = c.generation();
        assert!(c.store("/api/devices", g, Arc::new("{\"devices\":[1]}".into()), now));
        assert!(c.get("/api/devices", now).is_some());
        c.follow_external_at(c.external); // nothing happened
        assert!(c.get("/api/devices", now).is_some());
        c.follow_external_at(c.external + 1); // a device turned up
        assert!(c.get("/api/devices", now).is_none());
        // An answer computed before that is not kept either.
        assert!(!c.store("/api/devices", g, Arc::new("{}".into()), now));
    }

    #[test]
    fn the_cache_stays_bounded() {
        let mut c = ReadCache::default();
        let t0 = Instant::now();
        for i in 0..(MAX_ENTRIES + 20) {
            let at = t0 + Duration::from_millis(i as u64);
            assert!(c.store(
                &format!("/api/files?folder={i}"),
                0,
                Arc::new("x".into()),
                at
            ));
        }
        assert!(c.len() <= MAX_ENTRIES);
        // The oldest went, the newest stayed.
        assert!(c.get("/api/files?folder=0", t0).is_none());
        assert!(c
            .get(&format!("/api/files?folder={}", MAX_ENTRIES + 19), t0)
            .is_some());
        // Too large to keep.
        let big = Arc::new("y".repeat(MAX_BYTES / 2 + 1));
        assert!(!c.store("/api/files?folder=big", 0, big, t0));
        // Bytes: many large answers push the old ones out.
        let chunk = Arc::new("z".repeat(MAX_BYTES / 3));
        for i in 0..10 {
            c.store(
                &format!("/api/files?folder=c{i}"),
                0,
                chunk.clone(),
                t0 + Duration::from_secs(i),
            );
        }
        assert!(c.bytes <= MAX_BYTES);
    }

    #[test]
    fn a_busy_state_is_answered_from_the_cache() {
        let state = Arc::new(Mutex::new(0u32));
        let cache = Mutex::new(ReadCache::default());
        // Free: the state itself.
        assert!(matches!(
            lock_or_cached(&state, &cache, "/api/status", FRESH_WAIT),
            Got::Fresh(_)
        ));
        let g = cache.lock().unwrap().generation();
        cache
            .lock()
            .unwrap()
            .store("/api/status", g, Arc::new("{}".into()), Instant::now());
        // Held by a long operation: the cached answer, after the short wait.
        let held = state.lock().unwrap();
        let t = Instant::now();
        match lock_or_cached(&state, &cache, "/api/status", FRESH_WAIT) {
            Got::Cached(_, body) => assert_eq!(body.as_str(), "{}"),
            Got::Fresh(_) | Got::Busy => panic!("the state is held and an answer is kept"),
        }
        assert!(t.elapsed() < Duration::from_secs(1));
        // Nothing cached for this address: it waits for the state.
        let s2 = state.clone();
        let waiter = std::thread::spawn(move || {
            let cache = Mutex::new(ReadCache::default());
            let t = Instant::now();
            let fresh = matches!(
                lock_or_cached(&s2, &cache, "/api/folders", FRESH_WAIT),
                Got::Fresh(_)
            );
            (fresh, t.elapsed())
        });
        std::thread::sleep(Duration::from_millis(300));
        drop(held);
        let (fresh, waited) = waiter.join().unwrap();
        assert!(fresh);
        assert!(waited >= Duration::from_millis(250));
    }

    #[test]
    fn a_miss_while_busy_says_busy_instead_of_waiting() {
        // A sync on a dead link holds the engine for minutes: a read with
        // nothing kept is answered "busy" once the short wait is up.
        let cache = Mutex::new(ReadCache::default());
        let t = Instant::now();
        let got: Got<()> = take_or_cached(
            || None,
            &cache,
            "/api/folders",
            FRESH_WAIT,
            Duration::from_millis(200),
        );
        assert!(matches!(got, Got::Busy));
        let took = t.elapsed();
        assert!(took >= Duration::from_millis(200), "{took:?}");
        assert!(took < Duration::from_secs(2), "{took:?}");
        // Something kept: that, after the short wait only.
        let g = cache.lock().unwrap().generation();
        cache
            .lock()
            .unwrap()
            .store("/api/folders", g, Arc::new("[]".into()), Instant::now());
        let t = Instant::now();
        let got: Got<()> = take_or_cached(
            || None,
            &cache,
            "/api/folders",
            FRESH_WAIT,
            Duration::from_secs(30),
        );
        assert!(matches!(got, Got::Cached(_, _)));
        assert!(t.elapsed() < Duration::from_secs(1));
        // Free in the meantime: fresh.
        let mut tries = 0;
        let got = take_or_cached(
            || {
                tries += 1;
                (tries > 3).then_some(7u8)
            },
            &cache,
            "/api/other",
            FRESH_WAIT,
            Duration::from_secs(30),
        );
        assert!(matches!(got, Got::Fresh(7)));
    }

    #[test]
    fn stale_answers_say_so() {
        let v: serde_json::Value =
            serde_json::from_str(&mark_stale("{\"a\":1}", Duration::from_millis(1500))).unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(v["stale"], true);
        assert_eq!(v["stale_ms"], 1500);
        assert_eq!(mark_stale("[1,2]", Duration::from_secs(1)), "[1,2]");
    }

    #[test]
    fn only_reading_routes_are_cached() {
        assert!(cacheable("/api/status"));
        assert!(cacheable("/api/files"));
        for p in [
            "/api/link",
            "/api/sync",
            "/api/events",
            "/api/update/check",
            "/api/pair/status",
        ] {
            assert!(!cacheable(p), "{p}");
        }
        // A sync keeps the answers from before while it runs; a setting does not.
        assert!(!drops_answers("/api/sync"));
        assert!(drops_answers("/api/folder/add"));
    }
}
