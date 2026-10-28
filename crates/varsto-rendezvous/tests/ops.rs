// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Operations behaviour over real sockets: replay window and owner checks,
//! expiry sweeps, rate limits per tag and per address, the server's pings,
//! graceful shutdown with open connections, the per-tag relay quota, junk
//! input that must never hurt the server.

use ed25519_dalek::SigningKey;
use futures_util::StreamExt;
use rand::{Rng, RngCore, SeedableRng};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;
use varsto_rendezvous::proto::{
    self, DeleteSlot, ErrorAnswer, ErrorCode, Health, Hex, Kind, Lookup, LookupAnswer, PutSlot,
    ToClient, ToServer,
};
use varsto_rendezvous::selftest::{http, post, recv_binary, relay_open, Ctl};
use varsto_rendezvous::Server;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

async fn status(
    addr: std::net::SocketAddr,
    path: &str,
    body: &impl serde::Serialize,
) -> (u16, Option<ErrorCode>) {
    let (s, b) = post(addr, path, body).await.unwrap();
    (
        s,
        serde_json::from_str::<ErrorAnswer>(&b)
            .ok()
            .map(|e| e.error),
    )
}

#[test]
fn replay_window_owner_and_rising_timestamps_are_enforced() {
    let (_url, _udp, h) = Server::spawn_for_tests();
    let addr = h.http;
    rt().block_on(async {
        let tag = [1; 16];
        let slot = [2; 16];
        let k = key(1);
        let put = |ts: u64| PutSlot::sign(Kind::Peer, tag, slot, &k, ts, 600, vec![1; 10]);
        // Too old and too far in the future: outside the replay window.
        let w = proto::REPLAY_WINDOW_SECS;
        assert_eq!(
            status(addr, proto::PATH_PUT, &put(now() - w - 10)).await,
            (409, Some(ErrorCode::Stale))
        );
        assert_eq!(
            status(addr, proto::PATH_PUT, &put(now() + w + 10)).await,
            (409, Some(ErrorCode::Stale))
        );
        // Inside it: taken once, and an exact replay is refused (ts must rise).
        let first = put(now());
        assert_eq!(status(addr, proto::PATH_PUT, &first).await.0, 200);
        assert_eq!(
            status(addr, proto::PATH_PUT, &first).await,
            (409, Some(ErrorCode::Stale))
        );
        assert_eq!(
            status(addr, proto::PATH_PUT, &put(now() - 5)).await,
            (409, Some(ErrorCode::Stale))
        );
        assert_eq!(status(addr, proto::PATH_PUT, &put(now() + 5)).await.0, 200);
        // Another key can neither overwrite nor delete.
        let other = PutSlot::sign(Kind::Peer, tag, slot, &key(2), now() + 10, 600, vec![9; 10]);
        assert_eq!(
            status(addr, proto::PATH_PUT, &other).await,
            (403, Some(ErrorCode::NotOwner))
        );
        let del = DeleteSlot::sign(tag, slot, &key(2), now() + 10);
        assert_eq!(
            status(addr, proto::PATH_DELETE, &del).await,
            (403, Some(ErrorCode::NotOwner))
        );
        // A delete of an old replayed request is refused, the owner's works.
        let old_del = DeleteSlot::sign(tag, slot, &k, now() - w - 10);
        assert_eq!(
            status(addr, proto::PATH_DELETE, &old_del).await,
            (409, Some(ErrorCode::Stale))
        );
        let del = DeleteSlot::sign(tag, slot, &k, now() + 10);
        assert_eq!(status(addr, proto::PATH_DELETE, &del).await.0, 200);
        // A tag keeps its kind: a pairing offer cannot join a peer tag.
        assert_eq!(status(addr, proto::PATH_PUT, &put(now() + 20)).await.0, 200);
        let pair = PutSlot::sign(Kind::Pair, tag, proto::PAIR_SLOT, &k, now(), 60, vec![1]);
        assert_eq!(
            status(addr, proto::PATH_PUT, &pair).await,
            (409, Some(ErrorCode::TagFull))
        );
    });
    h.stop();
}

#[test]
fn expired_slots_are_swept_and_leave_no_trace() {
    let (_url, _udp, h) = Server::spawn_for_tests_with(|c| {
        c.sweep_every = Duration::from_millis(200);
    });
    let addr = h.http;
    rt().block_on(async {
        let p = PutSlot::sign(
            Kind::Peer,
            [3; 16],
            [4; 16],
            &key(3),
            now(),
            1,
            vec![7; 100],
        );
        assert_eq!(status(addr, proto::PATH_PUT, &p).await.0, 200);
        let (_, body) = http(addr, "GET", "/health", b"").await.unwrap();
        assert_eq!(Health::parse(body.trim()).unwrap().slots, 1);
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let (_, body) = post(addr, proto::PATH_LOOKUP, &Lookup::new([3; 16]))
            .await
            .unwrap();
        assert!(serde_json::from_str::<LookupAnswer>(&body)
            .unwrap()
            .slots
            .is_empty());
        let (_, body) = http(addr, "GET", "/health", b"").await.unwrap();
        let hl = Health::parse(body.trim()).unwrap();
        assert_eq!((hl.slots, hl.tags), (0, 0), "{body}");
    });
    assert_eq!(h.shared.registry.lock().unwrap().counts().bytes, 0);
    h.stop();
}

#[test]
fn rate_limits_per_tag_and_per_address_apply_and_recover_per_class() {
    let (_url, _udp, h) = Server::spawn_for_tests_with(|c| {
        c.rates.put_per_tag = 2;
        c.rates.lookup_per_ip = 3;
    });
    let addr = h.http;
    rt().block_on(async {
        let k = key(4);
        // Two writes per minute for one tag; another tag is unaffected.
        for (i, want) in [200, 200, 429].into_iter().enumerate() {
            let p = PutSlot::sign(
                Kind::Peer,
                [5; 16],
                [6; 16],
                &k,
                now() + i as u64,
                600,
                vec![1],
            );
            assert_eq!(status(addr, proto::PATH_PUT, &p).await.0, want, "write {i}");
        }
        let p = PutSlot::sign(Kind::Peer, [6; 16], [6; 16], &k, now(), 600, vec![1]);
        assert_eq!(status(addr, proto::PATH_PUT, &p).await.0, 200);
        // Three lookups per minute per address; puts have their own bucket.
        for want in [200, 200, 200, 429] {
            assert_eq!(
                status(addr, proto::PATH_LOOKUP, &Lookup::new([5; 16]))
                    .await
                    .0,
                want
            );
        }
        let p = PutSlot::sign(Kind::Peer, [7; 16], [6; 16], &k, now(), 600, vec![1]);
        assert_eq!(status(addr, proto::PATH_PUT, &p).await.0, 200);
        let (_, body) = http(addr, "GET", "/health", b"").await.unwrap();
        assert!(Health::parse(body.trim()).unwrap().rate_limited >= 2);
    });
    h.stop();
}

#[test]
fn the_server_pings_control_connections_and_closes_them_on_shutdown() {
    let (_url, _udp, h) = Server::spawn_for_tests_with(|c| {
        c.control_ping = Duration::from_millis(150);
        c.grace = Duration::from_secs(3);
    });
    let addr = h.http;
    let t0 = Instant::now();
    rt().block_on(async {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut ws, _) =
            tokio_tungstenite::client_async(format!("ws://{addr}{}", proto::PATH_CONTROL), tcp)
                .await
                .unwrap();
        // The challenge, then pings without anyone asking.
        let mut pings = 0;
        let deadline = Instant::now() + Duration::from_secs(3);
        while pings < 2 && Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(2), ws.next()).await {
                Ok(Some(Ok(Message::Ping(_)))) => pings += 1,
                Ok(Some(Ok(_))) => {}
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(pings, 2, "the server did not ping");
        // Stop with the connection still open: it is told to close and the
        // stop does not wait for the whole grace period.
        let stopper = std::thread::spawn(move || h.stop());
        let mut closed = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(1), ws.next()).await {
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => {
                    closed = true;
                    break;
                }
                _ => {}
            }
        }
        assert!(closed, "the connection was not closed on shutdown");
        stopper.join().unwrap();
    });
    assert!(t0.elapsed() < Duration::from_secs(6));
}

#[test]
fn a_vault_that_spends_its_relay_quota_is_refused_more_for_now() {
    let (_url, _udp, h) = Server::spawn_for_tests_with(|c| {
        c.relay_tag_bytes = 50_000;
    });
    let addr = h.http;
    rt().block_on(async {
        let tag = [8; 16];
        let (s1, s2) = ([1; 16], [2; 16]);
        let (k1, k2) = (key(5), key(6));
        for (k, s) in [(&k1, s1), (&k2, s2)] {
            let p = PutSlot::sign(Kind::Peer, tag, s, k, now(), 600, vec![1]);
            assert_eq!(status(addr, proto::PATH_PUT, &p).await.0, 200);
        }
        let mut a = Ctl::connect(addr).await.unwrap();
        let mut b = Ctl::connect(addr).await.unwrap();
        a.hello(vec![(tag, s1, &k1)]).await.unwrap();
        b.hello(vec![(tag, s2, &k2)]).await.unwrap();
        let ask = |id| ToServer::Relay {
            id,
            tag: Hex(tag),
            slot: Hex(s2),
        };
        a.send(&ask(1)).await.unwrap();
        let ToClient::RelayReady { token: ta, .. } = a.recv().await.unwrap() else {
            panic!()
        };
        let ToClient::RelayOffer { token: tb, .. } = b.recv().await.unwrap() else {
            panic!()
        };
        let mut ra = relay_open(addr, &ta.0).await.unwrap();
        let mut rb = relay_open(addr, &tb.0).await.unwrap();
        // Push more than the quota through; the relay ends the session.
        use futures_util::SinkExt;
        let chunk = vec![3u8; 16 * 1024];
        let mut sent = 0usize;
        let mut ended = false;
        for _ in 0..40 {
            if ra.send(Message::binary(chunk.clone())).await.is_err() {
                ended = true;
                break;
            }
            sent += chunk.len();
            let mut got = 0;
            while got < chunk.len() {
                match recv_binary(&mut rb).await {
                    Ok(b) => got += b.len(),
                    Err(_) => {
                        ended = true;
                        break;
                    }
                }
            }
            if ended {
                break;
            }
        }
        assert!(ended, "{sent} bytes passed a 50 kB quota");
        assert!(sent < 120_000, "{sent}");
        // The next session for the same vault is refused, not queued.
        a.send(&ask(2)).await.unwrap();
        match a.recv().await.unwrap() {
            ToClient::Error {
                id: Some(2),
                error: ErrorCode::RateLimited,
                ..
            } => {}
            other => panic!("{other:?}"),
        }
        // Other vaults are not affected.
        let t2 = [9; 16];
        for (k, s) in [(&k1, s1), (&k2, s2)] {
            let p = PutSlot::sign(Kind::Peer, t2, s, k, now(), 600, vec![1]);
            assert_eq!(status(addr, proto::PATH_PUT, &p).await.0, 200);
        }
        let mut c = Ctl::connect(addr).await.unwrap();
        let mut d = Ctl::connect(addr).await.unwrap();
        c.hello(vec![(t2, s1, &k1)]).await.unwrap();
        d.hello(vec![(t2, s2, &k2)]).await.unwrap();
        c.send(&ToServer::Relay {
            id: 3,
            tag: Hex(t2),
            slot: Hex(s2),
        })
        .await
        .unwrap();
        assert!(matches!(
            c.recv().await.unwrap(),
            ToClient::RelayReady { .. }
        ));
    });
    assert!(
        h.shared
            .counters
            .quota_stopped
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );
    h.stop();
}

#[test]
fn random_bytes_never_hurt_the_server() {
    let (_url, udp, h) = Server::spawn_for_tests();
    let addr = h.http;
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x5eed);

    // The parsers take any bytes without panicking.
    for _ in 0..3000 {
        let n = rng.gen_range(0..200);
        let mut b = vec![0u8; n];
        rng.fill_bytes(&mut b);
        let _ = proto::parse_observe(&b);
        let _ = proto::parse_observed(&b, &[0; 12]);
        let s = String::from_utf8_lossy(&b).into_owned();
        let _ = proto::parse_to_server(&s);
        let _ = proto::parse_to_client(&s);
    }
    // And near-valid JSON.
    for text in [
        "{}",
        "[]",
        "null",
        "{\"t\":\"hello\"}",
        "{\"t\":\"hello\",\"v\":1,\"claims\":[{}]}",
        "{\"t\":\"punch\",\"id\":-1}",
        "{\"t\":\"relay\",\"id\":1,\"tag\":\"zz\",\"slot\":\"\"}",
        "{\"t\":\"nonsense\"}",
        "\u{0}",
        "{\"t\":\"ping\",\"id\":99999999999}",
    ] {
        let _ = proto::parse_to_server(text);
    }

    rt().block_on(async {
        // HTTP bodies: garbage is refused with a 4xx, never a 5xx or a hang.
        for path in [proto::PATH_PUT, proto::PATH_DELETE, proto::PATH_LOOKUP] {
            for round in 0..40 {
                let n = if round == 0 { 0 } else { rng.gen_range(1..400) };
                let mut b = vec![0u8; n];
                rng.fill_bytes(&mut b);
                let (s, _) = http(addr, "POST", path, &b).await.unwrap();
                assert!((400..500).contains(&s), "{path} answered {s}");
            }
            let (s, _) = http(addr, "POST", path, b"{\"v\":1,\"tag\":\"00\"}")
                .await
                .unwrap();
            assert!((400..500).contains(&s));
        }
        for bad in [
            "/v1/relay/zz",
            "/v1/relay/00000000000000000000000000000000",
            "/nope",
            "/v1/put",
        ] {
            let (s, _) = http(addr, "GET", bad, b"").await.unwrap();
            assert!((400..500).contains(&s), "{bad} answered {s}");
        }
        // UDP junk of every length gets no answer and no crash.
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for _ in 0..300 {
            let n = rng.gen_range(0..1600);
            let mut b = vec![0u8; n];
            rng.fill_bytes(&mut b);
            sock.send_to(&b, udp).await.unwrap();
        }
        // A control connection that sends junk is answered or closed.
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut ws, _) =
            tokio_tungstenite::client_async(format!("ws://{addr}{}", proto::PATH_CONTROL), tcp)
                .await
                .unwrap();
        use futures_util::SinkExt;
        for _ in 0..20 {
            let mut b = vec![0u8; rng.gen_range(1..300)];
            rng.fill_bytes(&mut b);
            if ws.send(Message::binary(b)).await.is_err() {
                break;
            }
        }
        // Still serving.
        let (s, body) = http(addr, "GET", "/health", b"").await.unwrap();
        assert_eq!(s, 200, "{body}");
        let (s, _) = http(addr, "GET", "/info", b"").await.unwrap();
        assert_eq!(s, 200);
    });
    h.stop();
}
