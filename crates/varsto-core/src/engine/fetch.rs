// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Fetching chunk objects for downloads. Requests run side by side in a
//! window that adapts to the link (deeper while that raises the throughput,
//! shallower when it lowers it), and each object goes to the
//! peers or to the storages by how fast each has been answering during the
//! pull: peers are preferred, a storage that answers faster takes a share
//! of the objects in proportion to its speed, and either one standing in
//! for the other when it lacks an object. With peer-to-peer on, a download
//! therefore uses both instead of waiting on the slower one.

use super::chunk_storage_key;
use crate::crypto;
use crate::ids::ObjectName;
use crate::manifest::ChunkRef;
use crate::pool::{self, PoolError};
use crate::storage::{Storage, StorageSpec};
use anyhow::anyhow;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Requests in flight when a pull starts, and the bounds the window moves
/// in, by `WINDOW_STEP`. Never below 8, which earlier versions always used.
const WINDOW_START: usize = 16;
const WINDOW_MIN: usize = 8;
pub(super) const WINDOW_MAX: usize = 32;
const WINDOW_STEP: usize = 4;
/// The throughput is measured over this long (and at least 8 objects)
/// before the window moves.
const ROUND: Duration = Duration::from_millis(500);
/// Fetching ahead across single-block files during a pull: at most this
/// many files looked at and objects fetched per batch.
pub(super) const PREFETCH_FILES: usize = 64;
pub(super) const PREFETCH_OBJECTS: usize = 32;
/// A storage answers faster than the peers only if it beats them by this
/// factor: peer-to-peer costs nothing per gigabyte.
const PEER_BIAS: f64 = 1.25;
/// Statistics older than this describe another moment of the network.
const STALE: Duration = Duration::from_secs(120);
/// While the storages have no sample, every n-th object asks them first.
const EXPLORE_EVERY: u64 = 16;

/// One chunk object as a download looked for it.
pub(super) enum Fetched {
    Got {
        source: String,
        bytes: Vec<u8>,
        from_peer: bool,
    },
    /// On no reachable storage; maybe on a pool disk that is away.
    Missing(Option<PoolError>),
    Failed(anyhow::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Source {
    Peers,
    Storages,
}

/// Exponentially weighted mean of seconds per object.
#[derive(Default)]
struct Speed {
    mean: f64,
    samples: u32,
    at: Option<Instant>,
    /// Objects asked for in a row that this source did not have.
    misses: u32,
    resting_until: Option<Instant>,
}

impl Speed {
    fn add(&mut self, secs: f64) {
        let now = Instant::now();
        self.mean = if self.samples == 0 {
            secs
        } else {
            0.8 * self.mean + 0.2 * secs
        };
        self.samples += 1;
        self.at = Some(now);
        self.misses = 0;
    }
    fn known(&self) -> bool {
        self.samples > 0 && self.at.is_some_and(|t| t.elapsed() < STALE)
    }
    fn resting(&self) -> bool {
        self.resting_until.is_some_and(|t| Instant::now() < t)
    }
    /// A miss: after `limit` in a row the source rests for `rest`, so a
    /// bucket whose blocks were moved away or peers that hold nothing of
    /// the folder cost one round trip each now and then, not every time.
    fn miss(&mut self, limit: u32, rest: Duration) {
        self.misses += 1;
        if self.misses >= limit {
            self.resting_until = Some(Instant::now() + rest);
            self.misses = 0;
        }
    }
}

/// Hill climbing on throughput: each round's bytes per second against the
/// previous round's; a gain keeps the window moving the same way, a loss
/// turns it round. Latency alone cannot steer it: a shallow window leaves
/// kept connections idle long enough for TCP to restart slowly, so answers
/// get slower when fewer are asked for.
struct Climb {
    started: Instant,
    bytes: u64,
    objects: u32,
    last_rate: f64,
    up: bool,
}

struct Inner {
    window: usize,
    climb: Climb,
    last: Option<Instant>,
    peers: Speed,
    storages: Speed,
    counter: u64,
    /// Share of objects owed to the storages, paid out one at a time.
    credit: f64,
}

/// What the downloads of this engine have seen of their sources.
pub(super) struct FetchStats {
    inner: Mutex<Inner>,
}

impl Default for FetchStats {
    fn default() -> Self {
        FetchStats {
            inner: Mutex::new(Inner {
                window: WINDOW_START,
                climb: Climb {
                    started: Instant::now(),
                    bytes: 0,
                    objects: 0,
                    last_rate: 0.0,
                    up: true,
                },
                last: None,
                peers: Speed::default(),
                storages: Speed::default(),
                counter: 0,
                credit: 0.0,
            }),
        }
    }
}

impl FetchStats {
    pub(super) fn window(&self) -> usize {
        self.inner.lock().unwrap().window
    }

    fn choose(&self, has_peers: bool, has_storages: bool) -> Source {
        if !has_peers {
            return Source::Storages;
        }
        if !has_storages {
            return Source::Peers;
        }
        let mut s = self.inner.lock().unwrap();
        if s.last.is_some_and(|t| t.elapsed() > STALE) {
            // A new burst of downloads after a quiet spell starts afresh.
            s.window = WINDOW_START;
            s.climb.last_rate = 0.0;
            s.climb.up = true;
            s.peers = Speed::default();
            s.storages = Speed::default();
            s.credit = 0.0;
        }
        s.last = Some(Instant::now());
        s.counter += 1;
        if s.storages.resting() {
            return Source::Peers;
        }
        if s.peers.resting() {
            return Source::Storages;
        }
        if !s.peers.known() {
            return Source::Peers;
        }
        if !s.storages.known() {
            return if s.counter % EXPLORE_EVERY == 0 {
                Source::Storages
            } else {
                Source::Peers
            };
        }
        // Each source's share follows its speed; peers get the benefit of the doubt.
        let peer_rate = PEER_BIAS / s.peers.mean.max(1e-4);
        let storage_rate = 1.0 / s.storages.mean.max(1e-4);
        let share = storage_rate / (storage_rate + peer_rate);
        s.credit += share;
        if s.credit >= 1.0 {
            s.credit -= 1.0;
            Source::Storages
        } else {
            Source::Peers
        }
    }

    fn record(&self, source: Source, secs: f64, found: Option<usize>) {
        let mut s = self.inner.lock().unwrap();
        let speed = match source {
            Source::Peers => &mut s.peers,
            Source::Storages => &mut s.storages,
        };
        let Some(bytes) = found else {
            match source {
                Source::Peers => speed.miss(4, Duration::from_secs(10)),
                Source::Storages => speed.miss(2, Duration::from_secs(30)),
            }
            return;
        };
        speed.add(secs);
        s.climb.bytes += bytes as u64;
        s.climb.objects += 1;
        let elapsed = s.climb.started.elapsed();
        if elapsed < ROUND || s.climb.objects < 8 {
            return;
        }
        let rate = s.climb.bytes as f64 / elapsed.as_secs_f64();
        let last = s.climb.last_rate;
        if last > 0.0 && rate < last * 0.95 {
            s.climb.up = !s.climb.up;
        }
        s.window = if s.climb.up {
            (s.window + WINDOW_STEP).min(WINDOW_MAX)
        } else {
            s.window.saturating_sub(WINDOW_STEP).max(WINDOW_MIN)
        };
        // At a bound, turn round so the next round tests the other way.
        if s.window == WINDOW_MAX || s.window == WINDOW_MIN {
            s.climb.up = s.window == WINDOW_MIN;
        }
        if std::env::var_os("VARSTO_P2P_DEBUG").is_some() {
            eprintln!(
                "fetch: {:.1} MB/s, window {} peers {:.3}s ({}) storages {:.3}s ({})",
                rate / 1e6,
                s.window,
                s.peers.mean,
                s.peers.samples,
                s.storages.mean,
                s.storages.samples
            );
        }
        s.climb.last_rate = rate;
        s.climb.started = Instant::now();
        s.climb.bytes = 0;
        s.climb.objects = 0;
    }
}

fn from_peers(
    peers: &crate::p2p::Peers,
    object: &ObjectName,
    stats: &FetchStats,
) -> Option<Fetched> {
    let t = Instant::now();
    let got = peers.get(object);
    stats.record(
        Source::Peers,
        t.elapsed().as_secs_f64(),
        got.as_ref().map(|(_, b)| b.len()),
    );
    got.map(|(dev, ct)| Fetched::Got {
        source: format!("peer:{}", dev.short()),
        bytes: ct,
        from_peer: true,
    })
}

/// Every storage in order; a copy that does not match its name is skipped.
fn from_storages(
    object: &ObjectName,
    storages: &[(StorageSpec, Box<dyn Storage>)],
    stats: &FetchStats,
) -> Fetched {
    let t = Instant::now();
    let key = chunk_storage_key(object);
    let mut needs_disk: Option<PoolError> = None;
    for (spec, backend) in storages {
        match backend.get(&key) {
            Ok(Some(ct)) => {
                if ObjectName::from_bytes(&crypto::hash(&ct)) != *object {
                    continue; // corrupt copy; try the next storage
                }
                stats.record(Source::Storages, t.elapsed().as_secs_f64(), Some(ct.len()));
                return Fetched::Got {
                    source: spec.name().to_string(),
                    bytes: ct,
                    from_peer: false,
                };
            }
            Ok(None) => {}
            // The copy is on a pool disk that is away: remember which one,
            // in case no other storage has the chunk.
            Err(e) => match pool::pool_error(&e) {
                Some(nd @ PoolError::NeedsDisk { .. }) => {
                    needs_disk.get_or_insert(nd.clone());
                }
                _ => return Fetched::Failed(e),
            },
        }
    }
    stats.record(Source::Storages, t.elapsed().as_secs_f64(), None);
    Fetched::Missing(needs_disk)
}

/// Fetch one object from the source `stats` picks, falling back to the
/// other when it lacks the object or fails.
pub(super) fn fetch_object(
    peers: Option<&crate::p2p::Peers>,
    object: &ObjectName,
    storages: &[(StorageSpec, Box<dyn Storage>)],
    stats: &FetchStats,
) -> Fetched {
    let peers = peers.filter(|p| !p.is_empty());
    match stats.choose(peers.is_some(), !storages.is_empty()) {
        Source::Peers => {
            if let Some(got) = peers.and_then(|p| from_peers(p, object, stats)) {
                return got;
            }
            from_storages(object, storages, stats)
        }
        Source::Storages => match from_storages(object, storages, stats) {
            got @ Fetched::Got { .. } => got,
            other => peers
                .and_then(|p| from_peers(p, object, stats))
                .unwrap_or(other),
        },
    }
}

/// Fetch `chunks` with up to the current window of requests in flight and
/// hand each to `each` in file order, on the calling thread. The window
/// slides: a slow answer holds back only the chunks more than a window
/// behind it. The first error from `each` stops the fetching.
pub(super) fn fetch_in_order(
    peers: Option<&crate::p2p::Peers>,
    chunks: &[ChunkRef],
    storages: &[(StorageSpec, Box<dyn Storage>)],
    stats: &FetchStats,
    mut each: impl FnMut(&ChunkRef, Fetched) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    if chunks.len() <= 1 {
        for c in chunks {
            each(c, fetch_object(peers, &c.object, storages, stats))?;
        }
        return Ok(());
    }
    struct Window {
        next: usize,
        consumed: usize,
        active: usize,
        ready: BTreeMap<usize, Fetched>,
        stop: bool,
    }
    let shared = Mutex::new(Window {
        next: 0,
        consumed: 0,
        active: 0,
        ready: BTreeMap::new(),
        stop: false,
    });
    let changed = std::sync::Condvar::new();
    std::thread::scope(|s| {
        for _ in 0..WINDOW_MAX.min(chunks.len()) {
            s.spawn(|| loop {
                let i = {
                    let mut w = shared.lock().unwrap();
                    loop {
                        if w.stop || w.next >= chunks.len() {
                            return;
                        }
                        let window = stats.window();
                        if w.next < w.consumed + window && w.active < window {
                            break;
                        }
                        w = changed.wait(w).unwrap();
                    }
                    w.next += 1;
                    w.active += 1;
                    w.next - 1
                };
                // A panic must still fill the slot, or the reader would wait forever.
                let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    fetch_object(peers, &chunks[i].object, storages, stats)
                }))
                .unwrap_or_else(|_| Fetched::Failed(anyhow!("chunk fetch panicked")));
                {
                    let mut w = shared.lock().unwrap();
                    w.ready.insert(i, got);
                    w.active -= 1;
                }
                changed.notify_all();
            });
        }
        let mut result = Ok(());
        for (i, c) in chunks.iter().enumerate() {
            let got = {
                let mut w = shared.lock().unwrap();
                loop {
                    if let Some(f) = w.ready.remove(&i) {
                        w.consumed = i + 1;
                        break f;
                    }
                    w = changed.wait(w).unwrap();
                }
            };
            changed.notify_all();
            if let Err(e) = each(c, got) {
                result = Err(e);
                break;
            }
        }
        shared.lock().unwrap().stop = true;
        changed.notify_all();
        result
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peers_first_then_storages_take_a_share_by_speed() {
        let st = FetchStats::default();
        assert_eq!(st.choose(true, true), Source::Peers);
        st.record(Source::Peers, 0.4, Some(1000));
        // No storage sample yet: every 16th object explores the storages.
        let picks: Vec<Source> = (0..32).map(|_| st.choose(true, true)).collect();
        assert!(picks.contains(&Source::Storages));
        // A storage four times faster takes most objects; peers keep some.
        st.record(Source::Storages, 0.1, Some(1000));
        let picks: Vec<Source> = (0..100).map(|_| st.choose(true, true)).collect();
        let s = picks.iter().filter(|p| **p == Source::Storages).count();
        assert!((60..90).contains(&s), "storages got {s} of 100");
        // A storage without the objects (moved away) rests after two misses.
        st.record(Source::Storages, 0.01, None);
        st.record(Source::Storages, 0.01, None);
        assert!((0..20).all(|_| st.choose(true, true) == Source::Peers));
        // Without peers, everything goes to the storages and vice versa.
        assert_eq!(st.choose(false, true), Source::Storages);
        assert_eq!(st.choose(true, false), Source::Peers);
    }

    /// One round of `n` objects of `bytes` each, taking `secs` in all.
    fn round(st: &FetchStats, n: u32, bytes: usize, secs: f64) {
        st.inner.lock().unwrap().climb.started = Instant::now() - Duration::from_secs_f64(secs);
        for _ in 0..n {
            st.record(Source::Peers, 0.05, Some(bytes));
        }
    }

    #[test]
    fn the_window_climbs_while_throughput_rises_and_turns_when_it_falls() {
        let st = FetchStats::default();
        assert_eq!(st.window(), WINDOW_START);
        round(&st, 10, 1_000_000, 1.0);
        assert_eq!(st.window(), WINDOW_START + WINDOW_STEP);
        round(&st, 10, 2_000_000, 1.0); // faster: keep going
        assert_eq!(st.window(), WINDOW_START + 2 * WINDOW_STEP);
        round(&st, 10, 1_000_000, 1.0); // slower: back down
        assert_eq!(st.window(), WINDOW_START + WINDOW_STEP);
        for _ in 0..10 {
            round(&st, 10, 1_000_000, 1.0);
        }
        assert!((WINDOW_MIN..=WINDOW_MAX).contains(&st.window()));
    }
}
