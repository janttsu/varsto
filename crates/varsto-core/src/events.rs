// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! What happens in the service, as a stream of events for the local
//! interface (`GET /api/events`, Server-Sent Events): syncs, tasks and their
//! progress, transfers, peers, storage and disk-space problems,
//! notifications, configuration and policy changes, new files, the ledger,
//! backups, the trash. The interface follows them instead of asking every
//! few seconds.
//!
//! Every event gets the next number of this process. The last
//! [`RING`] events are kept, so that a client that lost its connection
//! resumes where it stopped (`Last-Event-ID`); one that fell further behind
//! is told to load everything again (`reset`). Nothing is written to disk:
//! the numbers start again with the process, and a client that sees a
//! smaller number than it had knows the service started again.
//!
//! Events carry counts, names and states, never file contents; they go only
//! to the local interface, which holds the session token.

use serde::Serialize;
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Events kept for clients that reconnect.
pub const RING: usize = 1024;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct Event {
    pub id: u64,
    /// `sync.started`, `activity.progress`, `peer.connected`, ...
    pub kind: String,
    pub utc: i64,
    pub data: Value,
}

impl Event {
    /// The event in the `text/event-stream` format.
    pub fn sse(&self) -> String {
        let data = serde_json::to_string(&serde_json::json!({
            "id": self.id,
            "kind": self.kind,
            "utc": self.utc,
            "data": self.data,
        }))
        .unwrap_or_default();
        format!("id: {}\nevent: {}\ndata: {}\n\n", self.id, self.kind, data)
    }
}

struct Ring {
    events: VecDeque<Event>,
    next: u64,
}

pub struct Bus {
    ring: Mutex<Ring>,
    cond: Condvar,
}

/// What a client gets after the event it saw last.
#[derive(Debug, PartialEq)]
pub enum Since {
    /// The events after it (possibly none).
    Events(Vec<Event>),
    /// It is older than the ring (or from an earlier run of the service):
    /// the client must load everything again; the number to continue from.
    Reset(u64),
}

impl Bus {
    pub const fn new() -> Bus {
        Bus {
            ring: Mutex::new(Ring {
                events: VecDeque::new(),
                next: 1,
            }),
            cond: Condvar::new(),
        }
    }

    /// Add an event; returns its number.
    pub fn publish(&self, kind: &str, data: Value) -> u64 {
        let mut r = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        let id = r.next;
        r.next += 1;
        r.events.push_back(Event {
            id,
            kind: kind.to_string(),
            utc: crate::util::now_utc(),
            data,
        });
        while r.events.len() > RING {
            r.events.pop_front();
        }
        drop(r);
        self.cond.notify_all();
        id
    }

    /// The number of the newest event (0: none yet).
    pub fn last_id(&self) -> u64 {
        self.ring.lock().unwrap_or_else(|e| e.into_inner()).next - 1
    }

    /// The events after `last`.
    pub fn since(&self, last: u64) -> Since {
        let r = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        Self::since_locked(&r, last)
    }

    fn since_locked(r: &Ring, last: u64) -> Since {
        let newest = r.next - 1;
        if last > newest {
            // From an earlier run of the service.
            return Since::Reset(newest);
        }
        let oldest = r.events.front().map(|e| e.id).unwrap_or(r.next);
        if last + 1 < oldest {
            return Since::Reset(newest);
        }
        Since::Events(r.events.iter().filter(|e| e.id > last).cloned().collect())
    }

    /// Wait up to `wait` for events after `last`.
    pub fn wait(&self, last: u64, wait: Duration) -> Since {
        let until = Instant::now() + wait;
        let mut r = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            match Self::since_locked(&r, last) {
                Since::Events(v) if v.is_empty() => {}
                other => return other,
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Since::Events(Vec::new());
            }
            r = self
                .cond
                .wait_timeout(r, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

impl Default for Bus {
    fn default() -> Self {
        Bus::new()
    }
}

static BUS: Bus = Bus::new();

/// The service's event bus.
pub fn bus() -> &'static Bus {
    &BUS
}

/// Publish on the service's bus.
pub fn publish(kind: &str, data: Value) -> u64 {
    BUS.publish(kind, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn numbered_kept_in_a_ring_and_resumed() {
        let b = Bus::new();
        assert_eq!(b.last_id(), 0);
        assert_eq!(b.since(0), Since::Events(vec![]));
        let a = b.publish("sync.started", json!({"reason": "timer"}));
        let c = b.publish("sync.finished", json!({"updated": 2}));
        assert_eq!((a, c), (1, 2));
        match b.since(1) {
            Since::Events(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].kind, "sync.finished");
                assert_eq!(v[0].data["updated"], 2);
            }
            other => panic!("{other:?}"),
        }
        // A number from an earlier run: start over.
        assert_eq!(b.since(99), Since::Reset(2));
        // Older than the ring: start over too.
        for i in 0..RING + 10 {
            b.publish("activity.progress", json!({"i": i}));
        }
        assert_eq!(b.since(1), Since::Reset(b.last_id()));
        let last = b.last_id();
        match b.since(last - 3) {
            Since::Events(v) => assert_eq!(v.len(), 3),
            other => panic!("{other:?}"),
        }
        let s = b.since(last - 1);
        let Since::Events(v) = s else { panic!() };
        let text = v[0].sse();
        assert!(text.starts_with(&format!("id: {last}\nevent: activity.progress\ndata: {{")));
        assert!(text.ends_with("}\n\n"));
    }

    #[test]
    fn a_waiting_client_wakes_up_on_the_next_event() {
        let b: &'static Bus = Box::leak(Box::new(Bus::new()));
        let last = b.last_id();
        let t = std::thread::spawn(move || b.wait(last, Duration::from_secs(5)));
        std::thread::sleep(Duration::from_millis(50));
        b.publish("notification", json!({"title": "x"}));
        match t.join().unwrap() {
            Since::Events(v) => assert_eq!(v[0].kind, "notification"),
            other => panic!("{other:?}"),
        }
        // Nothing new: an empty answer after the wait.
        let start = Instant::now();
        assert_eq!(
            b.wait(b.last_id(), Duration::from_millis(100)),
            Since::Events(vec![])
        );
        assert!(start.elapsed() >= Duration::from_millis(100));
    }
}
