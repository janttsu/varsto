// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Relay sessions (spec 83.7): the table of one-time tokens, and the
//! splicer that copies bytes between the two sides with a rate cap and an
//! idle timeout. The bytes are the peers' TLS 1.3 records (or, for
//! pairing, the SPAKE2 exchange); the server never reads them.

use crate::proto::{self, ErrorCode, Tag, Token};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
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

    /// Sessions created and not finished.
    pub fn active(&self) -> usize {
        self.sessions.len()
    }

    /// Whether `tag` has a session (tests).
    pub fn has_tag(&self, tag: &Tag) -> bool {
        self.per_tag.contains_key(tag)
    }
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
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    let epoch = Instant::now();
    let last = AtomicU64::new(0);
    tokio::join!(
        pump(ar, bw, lim, counter, epoch, &last),
        pump(br, aw, lim, counter, epoch, &last)
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
}
