// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Parallel verification with read-ahead, aware of the medium (`crate::media`).
//!
//! Every path that re-hashes stored data (bit-rot checks, `fsck --verify`,
//! automatic verification, pool disk checks) hands its items to
//! [`run_ordered`] in the order it would read them one by one. Each item
//! belongs to a *lane* (a storage, a pool disk, a folder): what is read from
//! one place. A lane has its own readers:
//!
//! - a spinning disk (or a medium not recognised) has one reader, which
//!   takes the lane's items strictly in order, so the disk reads exactly as
//!   it did before; hashing happens on another thread while the next item
//!   is read (read-ahead of what is next anyway, no extra seeks);
//! - an SSD or NVMe disk has a few readers (min(4, cores / 2) by default);
//! - a network storage (S3, rclone, network filesystems) has as many
//!   readers as uploads use (8), so round trips overlap.
//!
//! Results are handed back to the caller **in the original order**, on the
//! caller's thread, whatever order they complete in. The caller's loop is
//! therefore the sequential one it always was: it advances a cursor only
//! past items it has seen, counts progress, collects damage, and may stop
//! at any item (a read error, a budget), after which nothing more is
//! started and whatever was read ahead is dropped unseen. A crash never
//! skips an unchecked item, and the results equal a sequential run's.
//!
//! Memory stays bounded: an item's size is reserved from [`MEMORY_CAP`]
//! before it is read and given back once it is hashed (an item larger than
//! the cap is read alone), and no item more than [`WINDOW`] places ahead of
//! the one the caller waits for is started.

use crate::media::Media;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Condvar, Mutex};

/// Most bytes read but not yet hashed at any time.
pub const MEMORY_CAP: u64 = 256 << 20;
/// Most items started ahead of the one the caller waits for.
pub const WINDOW: usize = 256;
/// Readers of a network lane: as many as the uploader threads.
pub const NETWORK_READERS: usize = 8;
/// Most readers a setting may ask for, per lane.
pub const MAX_READERS: usize = 32;

/// Readers on an SSD by default: min(4, cores / 2), at least one.
pub fn default_ssd_readers() -> usize {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    (cores / 2).clamp(1, 4)
}

/// The user's choice for a storage, pool or folder (`config.json`,
/// `verify_parallelism`): `"auto"`, `"sequential"` or a number of readers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Parallelism {
    /// By the medium (`crate::media`).
    #[default]
    Auto,
    /// One reader, in order (as for a spinning disk).
    Sequential,
    /// This many readers, whatever the medium.
    Readers(u32),
}

impl Serialize for Parallelism {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Parallelism::Auto => s.serialize_str("auto"),
            Parallelism::Sequential => s.serialize_str("sequential"),
            Parallelism::Readers(n) => s.serialize_u32(*n),
        }
    }
}

impl<'de> Deserialize<'de> for Parallelism {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            N(u32),
            Word(String),
        }
        match Raw::deserialize(d)? {
            Raw::N(0) | Raw::N(1) => Ok(Parallelism::Sequential),
            Raw::N(n) => Ok(Parallelism::Readers(n)),
            Raw::Word(w) => w.parse().map_err(serde::de::Error::custom),
        }
    }
}

impl std::str::FromStr for Parallelism {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim() {
            "auto" | "" => Ok(Parallelism::Auto),
            "sequential" | "0" | "1" => Ok(Parallelism::Sequential),
            n => n
                .parse::<u32>()
                .map(Parallelism::Readers)
                .map_err(|_| format!("{n:?}: use auto, sequential or a number of readers")),
        }
    }
}

impl std::fmt::Display for Parallelism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Parallelism::Auto => f.write_str("auto"),
            Parallelism::Sequential => f.write_str("sequential"),
            Parallelism::Readers(n) => write!(f, "{n}"),
        }
    }
}

/// How one lane is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LanePlan {
    pub media: Media,
    /// Reader threads; 1 reads the lane strictly in order.
    pub readers: usize,
}

impl LanePlan {
    pub fn sequential(media: Media) -> Self {
        LanePlan { media, readers: 1 }
    }
}

/// The readers for a lane on `media` under `setting`. Spinning and unknown
/// media get one reader unless the setting names a number.
pub fn lane_plan(media: Media, setting: Parallelism) -> LanePlan {
    let readers = match setting {
        Parallelism::Sequential => 1,
        Parallelism::Readers(n) => (n as usize).clamp(1, MAX_READERS),
        Parallelism::Auto => match media {
            Media::Rotational | Media::Unknown => 1,
            Media::SolidState => default_ssd_readers(),
            Media::Network => NETWORK_READERS,
        },
    };
    LanePlan { media, readers }
}

/// One item to verify: its lane (index into the plans) and its size, used
/// to bound memory (0 when unknown: counted as the largest block, 16 MiB).
pub struct Job<I> {
    pub item: I,
    pub lane: usize,
    pub size: u64,
}

/// Size reserved for an item of unknown size: the largest block.
const UNKNOWN_SIZE: u64 = 16 << 20;

struct Sched<L, R> {
    /// Per lane: indices not yet started, in order.
    todo: Vec<VecDeque<usize>>,
    /// The index the caller waits for (all before it are handed back).
    consumed: usize,
    /// Bytes read or being read and not yet hashed.
    reserved: u64,
    /// Read, waiting for a hasher.
    loaded: VecDeque<(usize, L)>,
    readers_left: usize,
    results: BTreeMap<usize, R>,
    stop: bool,
    /// A reader or hasher panicked: its payload, raised again on this thread.
    panic: Option<Box<dyn std::any::Any + Send>>,
}

/// Verify `jobs` with the lanes' readers and hand each result to `consume`
/// in the jobs' order, on this thread. `load` runs on reader threads (the
/// I/O), `check` on hasher threads (the hashing). `consume` returns false
/// to stop: nothing more is started and results not handed back are
/// dropped. Returns the number of results handed back.
pub fn run_ordered<I, L, R>(
    jobs: &[Job<I>],
    lanes: &[LanePlan],
    load: impl Fn(&I) -> L + Sync,
    check: impl Fn(&I, L) -> R + Sync,
    mut consume: impl FnMut(usize, &I, R) -> bool,
) -> usize
where
    I: Sync,
    L: Send,
    R: Send,
{
    if jobs.is_empty() {
        return 0;
    }
    let mut todo: Vec<VecDeque<usize>> = vec![VecDeque::new(); lanes.len().max(1)];
    let last_lane = todo.len() - 1;
    for (i, j) in jobs.iter().enumerate() {
        todo[j.lane.min(last_lane)].push_back(i);
    }
    let readers: Vec<usize> = (0..todo.len())
        .map(|l| {
            if todo[l].is_empty() {
                0
            } else {
                lanes
                    .get(l)
                    .map_or(1, |p| p.readers.max(1))
                    .min(todo[l].len())
            }
        })
        .collect();
    let total_readers: usize = readers.iter().sum();
    let hashers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
        .min(total_readers)
        .max(1);
    let size_of = |i: usize| match jobs[i].size {
        0 => UNKNOWN_SIZE,
        s => s,
    };
    let sched = Mutex::new(Sched::<L, R> {
        todo,
        consumed: 0,
        reserved: 0,
        loaded: VecDeque::new(),
        readers_left: total_readers,
        results: BTreeMap::new(),
        stop: false,
        panic: None,
    });
    let changed = Condvar::new();
    let (load, check) = (&load, &check);
    let (sched, changed) = (&sched, &changed);
    let mut handed = 0usize;
    std::thread::scope(|s| {
        for (lane, n) in readers.iter().enumerate() {
            for _ in 0..*n {
                s.spawn(move || {
                    loop {
                        let i = {
                            let mut st = sched.lock().unwrap();
                            loop {
                                if st.stop {
                                    break None;
                                }
                                let Some(&i) = st.todo[lane].front() else {
                                    break None;
                                };
                                // The lowest index not yet started, of any lane.
                                let head = st
                                    .todo
                                    .iter()
                                    .filter_map(|q| q.front().copied())
                                    .min()
                                    .unwrap_or(i);
                                let size = size_of(i);
                                let fits = if i == head {
                                    st.reserved == 0 || st.reserved + size <= MEMORY_CAP
                                } else {
                                    // Leave room for the head, so it is never starved.
                                    st.reserved + size + size_of(head) <= MEMORY_CAP
                                };
                                // Keep hashers fed, not flooded.
                                let backlog = st.loaded.len() < 2 * hashers + total_readers;
                                if i < st.consumed + WINDOW && fits && backlog {
                                    st.todo[lane].pop_front();
                                    st.reserved += size;
                                    break Some(i);
                                }
                                st = changed.wait(st).unwrap();
                            }
                        };
                        let Some(i) = i else { break };
                        let l = match catch_unwind(AssertUnwindSafe(|| load(&jobs[i].item))) {
                            Ok(l) => l,
                            Err(p) => {
                                let mut st = sched.lock().unwrap();
                                st.stop = true;
                                st.panic.get_or_insert(p);
                                st.reserved -= size_of(i);
                                break;
                            }
                        };
                        sched.lock().unwrap().loaded.push_back((i, l));
                        changed.notify_all();
                    }
                    let mut st = sched.lock().unwrap();
                    st.readers_left -= 1;
                    drop(st);
                    changed.notify_all();
                });
            }
        }
        for _ in 0..hashers {
            s.spawn(move || loop {
                let next = {
                    let mut st = sched.lock().unwrap();
                    loop {
                        if let Some(x) = st.loaded.pop_front() {
                            break Some(x);
                        }
                        if st.readers_left == 0 {
                            break None;
                        }
                        st = changed.wait(st).unwrap();
                    }
                };
                let Some((i, l)) = next else { break };
                // Hash even after a stop: the reservation is given back
                // either way, and the result is simply not handed back.
                let r = catch_unwind(AssertUnwindSafe(|| check(&jobs[i].item, l)));
                let mut st = sched.lock().unwrap();
                st.reserved -= size_of(i);
                match r {
                    Ok(r) if !st.stop => {
                        st.results.insert(i, r);
                    }
                    Ok(_) => {}
                    Err(p) => {
                        st.stop = true;
                        st.panic.get_or_insert(p);
                    }
                }
                drop(st);
                changed.notify_all();
            });
        }
        // The caller's loop, in order.
        let mut st = sched.lock().unwrap();
        while st.consumed < jobs.len() && st.panic.is_none() {
            let i = st.consumed;
            let Some(r) = st.results.remove(&i) else {
                st = changed.wait(st).unwrap();
                continue;
            };
            st.consumed += 1;
            drop(st);
            changed.notify_all();
            handed += 1;
            let go_on = consume(i, &jobs[i].item, r);
            st = sched.lock().unwrap();
            if !go_on {
                st.stop = true;
                st.results.clear();
                break;
            }
        }
        st.stop = true;
        drop(st);
        changed.notify_all();
    });
    if let Some(p) = sched.lock().unwrap().panic.take() {
        std::panic::resume_unwind(p);
    }
    handed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn jobs(n: usize, lanes: usize, size: u64) -> Vec<Job<usize>> {
        (0..n)
            .map(|i| Job {
                item: i,
                lane: i % lanes,
                size,
            })
            .collect()
    }

    #[test]
    fn plans_follow_the_medium_and_the_setting() {
        let auto = Parallelism::Auto;
        assert_eq!(lane_plan(Media::Rotational, auto).readers, 1);
        assert_eq!(lane_plan(Media::Unknown, auto).readers, 1);
        assert_eq!(
            lane_plan(Media::SolidState, auto).readers,
            default_ssd_readers()
        );
        assert!((1..=4).contains(&default_ssd_readers()));
        assert_eq!(lane_plan(Media::Network, auto).readers, NETWORK_READERS);
        assert_eq!(
            lane_plan(Media::SolidState, Parallelism::Sequential).readers,
            1
        );
        assert_eq!(
            lane_plan(Media::Rotational, Parallelism::Readers(3)).readers,
            3
        );
        assert_eq!(
            lane_plan(Media::Network, Parallelism::Readers(500)).readers,
            MAX_READERS
        );
        // config.json spellings.
        let p: BTreeMap<String, Parallelism> =
            serde_json::from_str(r#"{"a":"auto","b":"sequential","c":6,"d":1}"#).unwrap();
        assert_eq!(p["a"], Parallelism::Auto);
        assert_eq!(p["b"], Parallelism::Sequential);
        assert_eq!(p["c"], Parallelism::Readers(6));
        assert_eq!(p["d"], Parallelism::Sequential);
        assert_eq!(
            serde_json::to_string(&p).unwrap(),
            r#"{"a":"auto","b":"sequential","c":6,"d":"sequential"}"#
        );
        assert!(serde_json::from_str::<Parallelism>(r#""fast""#).is_err());
        assert_eq!("4".parse::<Parallelism>().unwrap(), Parallelism::Readers(4));
    }

    #[test]
    fn one_reader_reads_in_key_order() {
        let order = Mutex::new(Vec::new());
        let j = jobs(200, 1, 10);
        let mut seen = Vec::new();
        let n = run_ordered(
            &j,
            &[LanePlan::sequential(Media::Rotational)],
            |i| {
                order.lock().unwrap().push(*i);
                *i
            },
            |_, l| l * 2,
            |i, item, r| {
                assert_eq!(i, *item);
                seen.push(r);
                true
            },
        );
        assert_eq!(n, 200);
        assert_eq!(*order.lock().unwrap(), (0..200).collect::<Vec<_>>());
        assert_eq!(seen, (0..200).map(|i| i * 2).collect::<Vec<_>>());
    }

    #[test]
    fn rotational_lanes_stay_in_order_next_to_parallel_ones() {
        // Lane 0 spins, lane 1 is an SSD with 4 readers.
        let lane0 = Mutex::new(Vec::new());
        let busy = AtomicUsize::new(0);
        let most = AtomicUsize::new(0);
        let j = jobs(300, 2, 10);
        let mut seen = Vec::new();
        run_ordered(
            &j,
            &[
                LanePlan::sequential(Media::Rotational),
                LanePlan {
                    media: Media::SolidState,
                    readers: 4,
                },
            ],
            |i| {
                if i % 2 == 0 {
                    let now = busy.fetch_add(1, Ordering::SeqCst) + 1;
                    most.fetch_max(now, Ordering::SeqCst);
                    lane0.lock().unwrap().push(*i);
                    std::thread::sleep(Duration::from_micros(200));
                    busy.fetch_sub(1, Ordering::SeqCst);
                } else {
                    std::thread::sleep(Duration::from_micros((*i as u64 * 37) % 500));
                }
                *i
            },
            |_, l| l,
            |_, _, r| {
                seen.push(r);
                true
            },
        );
        assert_eq!(
            most.load(Ordering::SeqCst),
            1,
            "one reader on the spinning lane"
        );
        let l0 = lane0.into_inner().unwrap();
        assert_eq!(l0, (0..300).step_by(2).collect::<Vec<_>>());
        assert_eq!(seen, (0..300).collect::<Vec<_>>());
    }

    #[test]
    fn ssd_lanes_read_in_parallel_and_hand_back_in_order() {
        let busy = AtomicUsize::new(0);
        let most = AtomicUsize::new(0);
        let j = jobs(64, 1, 1 << 20);
        let mut seen = Vec::new();
        run_ordered(
            &j,
            &[LanePlan {
                media: Media::SolidState,
                readers: 4,
            }],
            |i| {
                let now = busy.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                // Later items finish first now and then.
                std::thread::sleep(Duration::from_millis(if i % 3 == 0 { 6 } else { 1 }));
                busy.fetch_sub(1, Ordering::SeqCst);
                *i
            },
            |_, l| l,
            |_, _, r| {
                seen.push(r);
                true
            },
        );
        let m = most.load(Ordering::SeqCst);
        assert!(m > 1 && m <= 4, "{m} readers at once");
        assert_eq!(seen, (0..64).collect::<Vec<_>>());
    }

    #[test]
    fn a_stop_is_never_passed_and_nothing_after_it_is_handed_back() {
        // Items complete out of order; the caller stops at the first
        // failure (item 37): every item before it is handed back, none after.
        let j = jobs(500, 1, 100);
        let mut seen = Vec::new();
        let started = AtomicUsize::new(0);
        let n = run_ordered(
            &j,
            &[LanePlan {
                media: Media::Network,
                readers: 8,
            }],
            |i| {
                started.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(Duration::from_micros(((500 - *i) as u64 * 13) % 900));
                if *i == 37 {
                    Err("read failed")
                } else {
                    Ok(*i)
                }
            },
            |_, l| l,
            |i, _, r| {
                seen.push(i);
                r.is_ok()
            },
        );
        assert_eq!(n, 38);
        assert_eq!(seen, (0..38).collect::<Vec<_>>());
        // Read-ahead stays within the window.
        assert!(started.load(Ordering::SeqCst) <= 38 + WINDOW);
    }

    #[test]
    fn memory_stays_under_the_cap() {
        let held = AtomicUsize::new(0);
        let most = AtomicUsize::new(0);
        let size = 100u64 << 20; // two fit under 256 MiB, three do not
        let j = jobs(12, 1, size);
        run_ordered(
            &j,
            &[LanePlan {
                media: Media::SolidState,
                readers: 8,
            }],
            |i| {
                let now = held.fetch_add(1, Ordering::SeqCst) + 1;
                most.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(3));
                *i
            },
            |_, l| {
                std::thread::sleep(Duration::from_millis(2));
                held.fetch_sub(1, Ordering::SeqCst);
                l
            },
            |_, _, _| true,
        );
        assert!(most.load(Ordering::SeqCst) <= 2);
        // One item larger than the cap is still read (alone).
        let j = jobs(3, 1, MEMORY_CAP * 2);
        let n = run_ordered(
            &j,
            &[LanePlan {
                media: Media::SolidState,
                readers: 4,
            }],
            |i| *i,
            |_, l| l,
            |_, _, _| true,
        );
        assert_eq!(n, 3);
    }

    #[test]
    fn budget_picks_are_exact() {
        // The scrub plans its picks within the budget first; the executor
        // reads exactly those and no more.
        use crate::scrub::{plan, Budget, Pace, ScrubSchedule, Sweep};
        let items: Vec<(String, u64)> = (0..100).map(|i| (format!("k{i:03}"), 1000)).collect();
        let mut b = Budget::new(25_500);
        let p = plan(
            &items,
            &Sweep::default(),
            1,
            &ScrubSchedule::default(),
            Pace::Budget,
            &mut b,
        );
        assert_eq!(p.picks.len(), 25);
        let j: Vec<Job<usize>> = p
            .picks
            .iter()
            .map(|&i| Job {
                item: i,
                lane: 0,
                size: items[i].1,
            })
            .collect();
        let read = AtomicUsize::new(0);
        let bytes = AtomicUsize::new(0);
        run_ordered(
            &j,
            &[LanePlan {
                media: Media::Network,
                readers: 8,
            }],
            |i| {
                read.fetch_add(1, Ordering::SeqCst);
                bytes.fetch_add(items[*i].1 as usize, Ordering::SeqCst);
            },
            |_, _| (),
            |_, _, _| true,
        );
        assert_eq!(read.load(Ordering::SeqCst), 25);
        assert!(bytes.load(Ordering::SeqCst) as u64 <= 25_500);
    }

    #[test]
    fn empty_and_single() {
        let none: Vec<Job<usize>> = Vec::new();
        assert_eq!(run_ordered(&none, &[], |i| *i, |_, l| l, |_, _, _| true), 0);
        let one = jobs(1, 1, 0);
        let mut got = None;
        run_ordered(
            &one,
            &[LanePlan::sequential(Media::Unknown)],
            |i| *i + 1,
            |_, l| l,
            |_, _, r| {
                got = Some(r);
                true
            },
        );
        assert_eq!(got, Some(1));
    }

    #[test]
    fn a_panicking_reader_does_not_hang_the_caller() {
        let j = jobs(50, 1, 10);
        let r = std::panic::catch_unwind(AssertUnwindSafe(|| {
            run_ordered(
                &j,
                &[LanePlan {
                    media: Media::SolidState,
                    readers: 4,
                }],
                |i| {
                    assert!(*i != 9, "broken item");
                    *i
                },
                |_, l| l,
                |_, _, _| true,
            )
        }));
        assert!(r.is_err());
    }

    /// Sequential against parallel on 2000 objects of 256 KiB in a temporary
    /// directory (`cargo test -p varsto-core --release parverify -- --ignored
    /// --nocapture`). The page cache is warm after the first pass, so this
    /// measures hashing and scheduling more than the disk.
    #[test]
    #[ignore]
    fn bench_sequential_vs_parallel() {
        let dir = tempfile::tempdir().unwrap();
        let mut files = Vec::new();
        for i in 0..2000u32 {
            let p = dir.path().join(format!("{i:05}"));
            let data: Vec<u8> = (0..256 * 1024).map(|b| (b as u32 ^ i) as u8).collect();
            std::fs::write(&p, data).unwrap();
            files.push(p);
        }
        let run = |plan: LanePlan| {
            let j: Vec<Job<std::path::PathBuf>> = files
                .iter()
                .map(|p| Job {
                    item: p.clone(),
                    lane: 0,
                    size: 256 * 1024,
                })
                .collect();
            let t = std::time::Instant::now();
            let mut n = 0;
            run_ordered(
                &j,
                &[plan],
                |p| std::fs::read(p).unwrap(),
                |_, b| crate::crypto::hash(&b),
                |_, _, _| {
                    n += 1;
                    true
                },
            );
            assert_eq!(n, 2000);
            t.elapsed()
        };
        let _warm = run(LanePlan::sequential(Media::Unknown));
        let plain = {
            let t = std::time::Instant::now();
            for p in &files {
                let _ = crate::crypto::hash(&std::fs::read(p).unwrap());
            }
            t.elapsed()
        };
        let seq = run(LanePlan::sequential(Media::Rotational));
        let par = run(lane_plan(Media::SolidState, Parallelism::Auto));
        let par8 = run(LanePlan {
            media: Media::SolidState,
            readers: 8,
        });
        eprintln!(
            "2000 x 256 KiB: plain loop {plain:?}, one reader + hasher {seq:?}, {} readers {par:?}, 8 readers {par8:?}",
            default_ssd_readers()
        );
    }
}
