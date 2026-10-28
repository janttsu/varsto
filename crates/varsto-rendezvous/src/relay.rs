// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Relay sessions (spec 83.7): the table of one-time tokens, and the
//! splicer that copies bytes between the two sides with a rate cap and an
//! idle timeout. The bytes are the peers' TLS 1.3 records (or, for
//! pairing, the SPAKE2 exchange); the server never reads them.

use crate::proto::{self, ErrorCode, Tag, Token};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Which side of a session a token opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The asker (`relay_ready`).
    A,
    /// The holder of the slot (`relay_offer`).
    B,
}

/// What a token stands for until it is used.
#[derive(Clone, Debug)]
struct Pending {
    session: u64,
    side: Side,
    created: Instant,
}

/// Tokens waiting to be used, and the sessions running per tag.
#[derive(Debug)]
pub struct RelayTable {
    pending: HashMap<Token, Pending>,
    /// Sessions per tag: created and not yet finished.
    per_tag: HashMap<Tag, usize>,
    sessions: HashMap<u64, Tag>,
    per_tag_max: usize,
    next: u64,
}

impl RelayTable {
    pub fn new(per_tag_max: usize) -> RelayTable {
        RelayTable {
            pending: HashMap::new(),
            per_tag: HashMap::new(),
            sessions: HashMap::new(),
            per_tag_max,
            next: 1,
        }
    }

    /// A new session under `tag`: the two sides' tokens.
    pub fn create(&mut self, tag: Tag, now: Instant) -> Result<(Token, Token), ErrorCode> {
        let n = self.per_tag.get(&tag).copied().unwrap_or(0);
        if n >= self.per_tag_max {
            return Err(ErrorCode::RateLimited);
        }
        let session = self.next;
        self.next += 1;
        let a = proto::random_token();
        let b = proto::random_token();
        for (t, side) in [(a, Side::A), (b, Side::B)] {
            self.pending.insert(
                t,
                Pending {
                    session,
                    side,
                    created: now,
                },
            );
        }
        *self.per_tag.entry(tag).or_default() += 1;
        self.sessions.insert(session, tag);
        Ok((a, b))
    }

    /// Use a token (once): its session and side, or `None` for an unknown
    /// or expired one.
    pub fn take(&mut self, token: &Token, now: Instant) -> Option<(u64, Side)> {
        let p = self.pending.remove(token)?;
        if now.saturating_duration_since(p.created) > Duration::from_secs(proto::RELAY_JOIN_SECS) {
            self.finish(p.session);
            return None;
        }
        Some((p.session, p.side))
    }

    /// The session ended (or never started): its tag's count goes down.
    pub fn finish(&mut self, session: u64) {
        self.pending.retain(|_, p| p.session != session);
        if let Some(tag) = self.sessions.remove(&session) {
            if let Some(n) = self.per_tag.get_mut(&tag) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.per_tag.remove(&tag);
                }
            }
        }
    }

    /// Drop sessions whose tokens were not both used in time.
    pub fn expire(&mut self, now: Instant) {
        let late: Vec<u64> = self
            .pending
            .values()
            .filter(|p| {
                now.saturating_duration_since(p.created)
                    > Duration::from_secs(proto::RELAY_JOIN_SECS)
            })
            .map(|p| p.session)
            .collect();
        for s in late {
            self.finish(s);
        }
    }

    /// The tag a session was created under.
    pub fn tag_of(&self, session: u64) -> Option<Tag> {
        self.sessions.get(&session).copied()
    }

    /// Sessions created and not finished.
    pub fn active(&self) -> usize {
        self.sessions.len()
    }

    /// Whether `tag` has a session (tests).
    pub fn has_tag(&self, tag: &Tag) -> bool {
        self.per_tag.contains_key(tag)
    }
}

/// A byte-rate cap shared by many sessions (the global relay cap): each
/// caller reserves the time its bytes take at `rate` and sleeps for it.
#[derive(Debug)]
pub struct Throttle {
    rate: u64,
    /// When the shared pipe is free again.
    free_at: Mutex<Option<Instant>>,
}

impl Throttle {
    /// `rate` bytes per second (use `Option<Throttle>` for "no cap").
    pub fn new(rate: u64) -> Throttle {
        Throttle {
            rate: rate.max(1),
            free_at: Mutex::new(None),
        }
    }

    /// Reserve `n` bytes: how long to wait before sending them. At most a
    /// quarter second of burst is credited to an idle pipe.
    pub fn reserve(&self, n: u64, now: Instant) -> Duration {
        let cost = Duration::from_secs_f64(n as f64 / self.rate as f64);
        let mut free = self.free_at.lock().unwrap_or_else(|e| e.into_inner());
        let floor = now.checked_sub(Duration::from_millis(250)).unwrap_or(now);
        let start = free.map_or(floor, |f| f.max(floor));
        *free = Some(start + cost);
        start.saturating_duration_since(now)
    }
}

/// The relay bytes one tag may move per window (an hour): shared by all
/// the tag's sessions, so a vault cannot use the relay as a file host.
#[derive(Debug)]
pub struct Quota {
    used: AtomicU64,
    limit: u64,
}

impl Quota {
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }
    pub fn exhausted(&self) -> bool {
        self.limit > 0 && self.used() >= self.limit
    }
    pub fn add(&self, n: u64) {
        self.used.fetch_add(n, Ordering::Relaxed);
    }
}

/// Per-tag byte quotas in windows.
#[derive(Debug)]
pub struct TagBytes {
    limit: u64,
    window: Duration,
    cells: Mutex<HashMap<Tag, (Instant, Arc<Quota>)>>,
}

impl TagBytes {
    /// `limit` bytes per tag per `window`; 0 turns the quota off.
    pub fn new(limit: u64, window: Duration) -> TagBytes {
        TagBytes {
            limit,
            window,
            cells: Mutex::new(HashMap::new()),
        }
    }

    fn fresh(&self) -> Arc<Quota> {
        Arc::new(Quota {
            used: AtomicU64::new(0),
            limit: self.limit,
        })
    }

    /// The tag's quota in the current window.
    pub fn cell(&self, tag: &Tag, now: Instant) -> Arc<Quota> {
        let mut m = self.cells.lock().unwrap_or_else(|e| e.into_inner());
        let e = m.entry(*tag).or_insert_with(|| (now, self.fresh()));
        if now.saturating_duration_since(e.0) >= self.window {
            *e = (now, self.fresh());
        }
        e.1.clone()
    }

    /// Whether `tag` has used up its window.
    pub fn exhausted(&self, tag: &Tag, now: Instant) -> bool {
        if self.limit == 0 {
            return false;
        }
        let m = self.cells.lock().unwrap_or_else(|e| e.into_inner());
        match m.get(tag) {
            Some((at, q)) => now.saturating_duration_since(*at) < self.window && q.exhausted(),
            None => false,
        }
    }

    /// Forget finished windows.
    pub fn prune(&self, now: Instant) {
        let mut m = self.cells.lock().unwrap_or_else(|e| e.into_inner());
        m.retain(|_, (at, _)| now.saturating_duration_since(*at) < self.window);
    }

    pub fn len(&self) -> usize {
        self.cells.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Caps shared beyond one session; both optional.
#[derive(Clone, Copy, Default)]
pub struct Caps<'a> {
    /// The byte rate of all relay sessions together.
    pub total: Option<&'a Throttle>,
    /// The tag's byte quota; a session ends when it runs out.
    pub quota: Option<&'a Quota>,
}

/// Limits of one spliced session.
#[derive(Clone, Copy, Debug)]
pub struct SpliceLimits {
    /// Bytes per second per direction (0: no cap).
    pub rate: u64,
    /// A session that moves nothing either way for this long ends.
    pub idle: Duration,
}

/// Copy `from` to `to` until end of stream, error, or the whole session
/// (both directions) moved nothing for `lim.idle`; at most `rate` bytes
/// per second. `last` is the session's last activity in milliseconds since
/// `epoch`, shared by both directions: a long download keeps the quiet
/// direction alive. Returns the bytes copied.
async fn pump<R, W>(
    mut from: R,
    mut to: W,
    lim: SpliceLimits,
    counter: &AtomicU64,
    epoch: Instant,
    last: &AtomicU64,
    caps: Caps<'_>,
) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    let started = Instant::now();
    let mut total = 0u64;
    let tick = lim
        .idle
        .min(Duration::from_secs(1))
        .max(Duration::from_millis(10));
    loop {
        let n = match tokio::time::timeout(tick, from.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => n,
            Err(_) => {
                let quiet = epoch.elapsed().as_millis() as u64 - last.load(Ordering::Relaxed);
                if quiet >= lim.idle.as_millis() as u64 {
                    break;
                }
                continue;
            }
        };
        if to.write_all(&buf[..n]).await.is_err() {
            break;
        }
        last.store(epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
        total += n as u64;
        counter.fetch_add(n as u64, Ordering::Relaxed);
        if let Some(q) = caps.quota {
            q.add(n as u64);
            if q.exhausted() {
                break;
            }
        }
        if let Some(t) = caps.total {
            let wait = t.reserve(n as u64, Instant::now());
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
        }
        if lim.rate > 0 {
            // Sleep until the average since the start is back under the cap.
            let due = Duration::from_secs_f64(total as f64 / lim.rate as f64);
            let spent = started.elapsed();
            if due > spent {
                tokio::time::sleep(due - spent).await;
            }
        }
    }
    let _ = to.shutdown().await;
    total
}

/// Splice two byte streams: each direction is copied until it ends; when
/// one direction ends, the other's write side is shut down and the session
/// ends when both have, or when neither moved a byte for `lim.idle`.
/// Returns (bytes a→b, bytes b→a). `counter` adds up the bytes of both
/// directions (for `/health`).
pub async fn splice<A, B>(a: A, b: B, lim: SpliceLimits, counter: &AtomicU64) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    splice_with(a, b, lim, counter, Caps::default()).await
}

/// [`splice`] with the global rate and the tag's byte quota.
pub async fn splice_with<A, B>(
    a: A,
    b: B,
    lim: SpliceLimits,
    counter: &AtomicU64,
    caps: Caps<'_>,
) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    let epoch = Instant::now();
    let last = AtomicU64::new(0);
    tokio::join!(
        pump(ar, bw, lim, counter, epoch, &last, caps),
        pump(br, aw, lim, counter, epoch, &last, caps)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_work_once_and_expire() {
        let mut t = RelayTable::new(4);
        let now = Instant::now();
        let (a, b) = t.create([1; 16], now).unwrap();
        assert_eq!(t.active(), 1);
        let (s, side) = t.take(&a, now).unwrap();
        assert_eq!(side, Side::A);
        assert!(t.take(&a, now).is_none(), "once");
        assert_eq!(t.take(&b, now).unwrap(), (s, Side::B));
        t.finish(s);
        assert_eq!(t.active(), 0);
        assert!(!t.has_tag(&[1; 16]));

        let (a, _) = t.create([1; 16], now).unwrap();
        let late = now + Duration::from_secs(proto::RELAY_JOIN_SECS + 1);
        assert!(t.take(&a, late).is_none());
        assert_eq!(t.active(), 0, "a late token ends its session");
        t.create([1; 16], now).unwrap();
        t.expire(late);
        assert_eq!(t.active(), 0);
    }

    #[test]
    fn sessions_per_tag_are_capped() {
        let mut t = RelayTable::new(1);
        let now = Instant::now();
        t.create([1; 16], now).unwrap();
        assert_eq!(t.create([1; 16], now), Err(ErrorCode::RateLimited));
        t.create([2; 16], now).unwrap();
    }

    fn lim() -> SpliceLimits {
        SpliceLimits {
            rate: 0,
            idle: Duration::from_secs(5),
        }
    }

    #[tokio::test]
    async fn two_duplex_streams_are_spliced_both_ways() {
        let (mut a_client, a_server) = tokio::io::duplex(1024);
        let (mut b_client, b_server) = tokio::io::duplex(1024);
        let counter = AtomicU64::new(0);
        let splice = splice(a_server, b_server, lim(), &counter);
        let talk = async {
            a_client.write_all(b"hello from a").await.unwrap();
            let mut buf = [0u8; 12];
            b_client.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello from a");
            // Far more than the buffers hold: written and read at once.
            let big = vec![7u8; 200_000];
            let mut got = vec![0u8; big.len()];
            let (w, r) = tokio::join!(b_client.write_all(&big), a_client.read_exact(&mut got));
            w.unwrap();
            r.unwrap();
            assert_eq!(got, big);
            a_client.shutdown().await.unwrap();
            // b sees the end of a's stream, then ends its own.
            let mut rest = Vec::new();
            b_client.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
            b_client.shutdown().await.unwrap();
        };
        let ((ab, ba), ()) = tokio::join!(splice, talk);
        assert_eq!(ab, 12);
        assert_eq!(ba, 200_000);
        assert_eq!(counter.load(Ordering::Relaxed), 200_012);
    }

    #[tokio::test]
    async fn an_idle_session_ends() {
        let (_a_client, a_server) = tokio::io::duplex(64);
        let (_b_client, b_server) = tokio::io::duplex(64);
        let counter = AtomicU64::new(0);
        let lim = SpliceLimits {
            rate: 0,
            idle: Duration::from_millis(200),
        };
        let started = Instant::now();
        let (ab, ba) = splice(a_server, b_server, lim, &counter).await;
        assert_eq!((ab, ba), (0, 0));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn the_rate_cap_holds() {
        let (mut a_client, a_server) = tokio::io::duplex(1 << 16);
        let (mut b_client, b_server) = tokio::io::duplex(1 << 16);
        let counter = AtomicU64::new(0);
        let lim = SpliceLimits {
            rate: 100_000,
            idle: Duration::from_secs(5),
        };
        let started = Instant::now();
        let splice = splice(a_server, b_server, lim, &counter);
        let talk = async {
            a_client.write_all(&vec![1u8; 50_000]).await.unwrap();
            a_client.shutdown().await.unwrap();
            let mut got = Vec::new();
            b_client.read_to_end(&mut got).await.unwrap();
            assert_eq!(got.len(), 50_000);
            b_client.shutdown().await.unwrap();
        };
        tokio::join!(splice, talk);
        // 50 kB at 100 kB/s: about half a second, not instantly.
        assert!(
            started.elapsed() >= Duration::from_millis(350),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn the_global_throttle_serialises_reservations() {
        let t = Throttle::new(1000);
        let now = Instant::now();
        // The first 250 ms of credit pass at once, then each reservation
        // waits for those before it.
        assert_eq!(t.reserve(100, now), Duration::ZERO);
        let w = t.reserve(1000, now);
        assert!(w < Duration::from_millis(1), "{w:?}");
        let w2 = t.reserve(1000, now);
        assert!(
            w2 >= Duration::from_millis(800) && w2 <= Duration::from_millis(1000),
            "{w2:?}"
        );
    }

    #[tokio::test]
    async fn the_global_cap_slows_sessions_together() {
        let thr = Throttle::new(100_000);
        let started = Instant::now();
        let mut jobs = Vec::new();
        for _ in 0..2 {
            let thr = &thr;
            jobs.push(async move {
                let (mut a_client, a_server) = tokio::io::duplex(1 << 16);
                let (mut b_client, b_server) = tokio::io::duplex(1 << 16);
                let counter = AtomicU64::new(0);
                let caps = Caps {
                    total: Some(thr),
                    quota: None,
                };
                let sp = splice_with(a_server, b_server, lim(), &counter, caps);
                let talk = async {
                    a_client.write_all(&vec![1u8; 50_000]).await.unwrap();
                    a_client.shutdown().await.unwrap();
                    let mut got = Vec::new();
                    b_client.read_to_end(&mut got).await.unwrap();
                    assert_eq!(got.len(), 50_000);
                    b_client.shutdown().await.unwrap();
                };
                tokio::join!(sp, talk);
            });
        }
        futures_join(jobs).await;
        // 100 kB through a 100 kB/s pipe shared by two sessions.
        assert!(
            started.elapsed() >= Duration::from_millis(600),
            "{:?}",
            started.elapsed()
        );
    }

    async fn futures_join<F: std::future::Future<Output = ()>>(jobs: Vec<F>) {
        let mut it = jobs.into_iter();
        let (a, b) = (it.next().unwrap(), it.next().unwrap());
        tokio::join!(a, b);
    }

    #[tokio::test]
    async fn a_spent_tag_quota_ends_the_session() {
        let tb = TagBytes::new(10_000, Duration::from_secs(3600));
        let now = Instant::now();
        let q = tb.cell(&[1; 16], now);
        let (mut a_client, a_server) = tokio::io::duplex(1 << 16);
        let (mut b_client, b_server) = tokio::io::duplex(1 << 16);
        let counter = AtomicU64::new(0);
        let caps = Caps {
            total: None,
            quota: Some(&q),
        };
        let sp = splice_with(a_server, b_server, lim(), &counter, caps);
        let talk = async {
            a_client.write_all(&vec![1u8; 40_000]).await.unwrap();
            let mut got = Vec::new();
            // The relay stops copying once the quota is spent.
            b_client.read_to_end(&mut got).await.unwrap();
            assert!(got.len() < 40_000, "{}", got.len());
            drop(a_client);
        };
        tokio::join!(sp, talk);
        assert!(tb.exhausted(&[1; 16], now));
        assert!(!tb.exhausted(&[2; 16], now));
        // A new window starts afresh, and old windows are pruned.
        let later = now + Duration::from_secs(3601);
        assert!(!tb.exhausted(&[1; 16], later));
        assert_eq!(tb.cell(&[1; 16], later).used(), 0);
        tb.prune(later + Duration::from_secs(3601));
        assert!(tb.is_empty());
    }
}
