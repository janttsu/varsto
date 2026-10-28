// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Load tests in process: many tags and slots, many control connections and
//! relay sessions at once, with a bound on the memory the server (and this
//! process) may grow by. `load_in_process` runs with the normal tests
//! (hundreds of tags, thousands of slots, 50 relay sessions);
//! `load_heavy` (ignored; `cargo test -p varsto-rendezvous --test load --
//! --ignored`) takes 10 000 slots and 1 000 control connections.

use ed25519_dalek::SigningKey;
use futures_util::SinkExt;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;
use varsto_rendezvous::proto::{
    self, Health, Hex, Kind, Lookup, LookupAnswer, PutSlot, ToClient, ToServer,
};
use varsto_rendezvous::selftest::{http, post, recv_binary, relay_open, Ctl};
use varsto_rendezvous::Server;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Resident memory of this process in bytes (Linux; 0 elsewhere).
fn rss() -> u64 {
    std::fs::read_to_string("/proc/self/statm")
        .ok()
        .and_then(|s| {
            s.split_whitespace()
                .nth(1)
                .and_then(|n| n.parse::<u64>().ok())
        })
        .map(|pages| pages * 4096)
        .unwrap_or(0)
}

fn key(tag: u32, slot: u32) -> SigningKey {
    let mut seed = [0u8; 32];
    seed[..4].copy_from_slice(&tag.to_le_bytes());
    seed[4..8].copy_from_slice(&slot.to_le_bytes());
    SigningKey::from_bytes(&seed)
}

fn id(n: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&n.to_le_bytes());
    b[15] = 0xaa;
    b
}

const BLOB: usize = 1024;

/// Register `tags` x `per_tag` slots from 8 concurrent tasks; returns the
/// bytes of blobs stored.
async fn fill(addr: std::net::SocketAddr, tags: u32, per_tag: u32) -> usize {
    let mut jobs = Vec::new();
    for worker in 0..8u32 {
        jobs.push(tokio::spawn(async move {
            let mut bytes = 0;
            for t in (worker..tags).step_by(8) {
                for s in 0..per_tag {
                    let p = PutSlot::sign(
                        Kind::Peer,
                        id(t),
                        id(s),
                        &key(t, s),
                        now(),
                        3600,
                        vec![(t % 251) as u8; BLOB],
                    );
                    let (st, body) = post(addr, proto::PATH_PUT, &p).await.unwrap();
                    assert_eq!(st, 200, "tag {t} slot {s}: {body}");
                    bytes += BLOB;
                }
            }
            bytes
        }));
    }
    let mut total = 0;
    for j in jobs {
        total += j.await.unwrap();
    }
    total
}

/// `pairs` relay sessions at once, each moving `payload` bytes both ways
/// in 16 kB frames; returns the elapsed time.
async fn relay_load(
    addr: std::net::SocketAddr,
    tag_base: u32,
    pairs: u32,
    payload: usize,
) -> Duration {
    let started = Instant::now();
    let mut jobs = Vec::new();
    for n in 0..pairs {
        let tag = tag_base + n;
        jobs.push(tokio::spawn(async move {
            let (s1, s2) = (id(0), id(1));
            let (k1, k2) = (key(tag, 0), key(tag, 1));
            let mut a = Ctl::connect(addr).await.unwrap();
            let mut b = Ctl::connect(addr).await.unwrap();
            assert_eq!(a.hello(vec![(id(tag), s1, &k1)]).await.unwrap(), 1);
            assert_eq!(b.hello(vec![(id(tag), s2, &k2)]).await.unwrap(), 1);
            a.send(&ToServer::Relay {
                id: 1,
                tag: Hex(id(tag)),
                slot: Hex(s2),
            })
            .await
            .unwrap();
            let ToClient::RelayReady { token: ta, .. } = a.recv().await.unwrap() else {
                panic!("no relay_ready");
            };
            let ToClient::RelayOffer { token: tb, .. } = b.recv().await.unwrap() else {
                panic!("no relay_offer");
            };
            let (mut ra, mut rb) = (
                relay_open(addr, &ta.0).await.unwrap(),
                relay_open(addr, &tb.0).await.unwrap(),
            );
            let data: Vec<u8> = (0..payload).map(|i| (i % 255) as u8).collect();
            let up = async {
                for c in data.chunks(16 * 1024) {
                    ra.send(Message::binary(c.to_vec())).await.unwrap();
                }
                ra
            };
            let down = async {
                let mut got = Vec::new();
                while got.len() < payload {
                    got.extend(recv_binary(&mut rb).await.unwrap());
                }
                assert_eq!(got, data, "session {n}");
                for c in data.chunks(16 * 1024) {
                    rb.send(Message::binary(c.to_vec())).await.unwrap();
                }
                rb
            };
            let (mut ra, mut rb) = tokio::join!(up, down);
            let mut got = Vec::new();
            while got.len() < payload {
                got.extend(recv_binary(&mut ra).await.unwrap());
            }
            assert_eq!(got, data, "session {n} back");
            let _ = ra.close(None).await;
            let _ = rb.close(None).await;
            a.close().await;
            b.close().await;
        }));
    }
    for j in jobs {
        j.await.unwrap();
    }
    started.elapsed()
}

async fn health(addr: std::net::SocketAddr) -> Health {
    let (st, body) = http(addr, "GET", "/health", b"").await.unwrap();
    assert_eq!(st, 200);
    Health::parse(body.trim()).unwrap()
}

fn big_config(c: &mut varsto_rendezvous::Config) {
    c.max_controls_per_ip = 100_000;
    c.max_controls = 100_000;
    c.max_relays = 10_000;
    c.limits.relay_per_tag = 8;
    c.relay_total_rate = 0;
    c.relay_tag_bytes = 0;
}

fn run(tags: u32, per_tag: u32, relays: u32, controls: u32, mem_bound_mib: u64) {
    let (_url, udp, h) = Server::spawn_for_tests_with(big_config);
    let addr = h.http;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let before = rss();
    rt.block_on(async {
        // Many tags and slots.
        let t0 = Instant::now();
        let stored = fill(addr, tags, per_tag).await;
        let put_time = t0.elapsed();
        let hl = health(addr).await;
        assert_eq!(hl.tags, tags as u64);
        assert_eq!(hl.slots, (tags * per_tag) as u64);
        assert_eq!(
            h.shared.registry.lock().unwrap().counts().bytes,
            stored,
            "the registry holds exactly the blobs"
        );
        // Lookups of every tag.
        for t in (0..tags).step_by(7) {
            let (_, body) = post(addr, proto::PATH_LOOKUP, &Lookup::new(id(t)))
                .await
                .unwrap();
            let l: LookupAnswer = serde_json::from_str(&body).unwrap();
            assert_eq!(l.slots.len(), per_tag as usize);
            assert_eq!(l.slots[0].blob.0[0], (t % 251) as u8);
        }

        // Many control connections held open at once (held, idle, claimed).
        let mut held = Vec::new();
        for n in 0..controls {
            let mut c = Ctl::connect(addr).await.unwrap();
            let t = n % tags;
            let s = n % per_tag;
            // Claim only for the tags the fill wrote (all of them).
            assert_eq!(c.hello(vec![(id(t), id(s), &key(t, s))]).await.unwrap(), 1);
            held.push(c);
        }
        if controls > 0 {
            assert_eq!(health(addr).await.controls, controls as u64);
        }

        // Relay sessions at once (their own tags above the filled ones).
        if relays > 0 {
            for n in 0..relays {
                let t = 1_000_000 + n;
                for s in 0..2u32 {
                    let p = PutSlot::sign(
                        Kind::Peer,
                        id(t),
                        id(s),
                        &key(t, s),
                        now(),
                        3600,
                        vec![1; 64],
                    );
                    assert_eq!(post(addr, proto::PATH_PUT, &p).await.unwrap().0, 200);
                }
            }
            let took = relay_load(addr, 1_000_000, relays, 256 * 1024).await;
            eprintln!("{relays} relay sessions of 2 x 256 kB in {took:?}");
            assert!(took < Duration::from_secs(60), "{took:?}");
            // Every session finished and was accounted.
            let deadline = Instant::now() + Duration::from_secs(10);
            while health(addr).await.relays > 0 && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let hl = health(addr).await;
            assert_eq!(hl.relays, 0, "sessions leaked");
            assert!(hl.relay_bytes >= relays as u64 * 2 * 256 * 1024);
        }
        eprintln!("{} slots in {put_time:?}", tags * per_tag);
        drop(held);
        // Closed connections leave nothing behind.
        let deadline = Instant::now() + Duration::from_secs(20);
        while health(addr).await.controls > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(health(addr).await.controls, 0);
        assert_eq!(h.shared.counters.control_slow.load(Ordering::Relaxed), 0);
    });
    let after = rss();
    let _ = udp;
    drop(Arc::new(()));
    if before > 0 {
        let grown = after.saturating_sub(before) / (1 << 20);
        eprintln!("resident memory grew by {grown} MiB (bound {mem_bound_mib})");
        assert!(
            grown <= mem_bound_mib,
            "memory grew by {grown} MiB, bound {mem_bound_mib}"
        );
    }
    h.stop();
}

#[test]
fn load_in_process() {
    // 400 tags x 10 slots = 4000 slots of 1 kB, 50 relay sessions, 100
    // held control connections; this process (server and clients) may
    // grow by 300 MiB.
    run(400, 10, 50, 100, 300);
}

#[test]
#[ignore = "heavy: 10 000 slots and 1 000 control connections"]
fn load_heavy() {
    run(1000, 10, 50, 1000, 600);
}
