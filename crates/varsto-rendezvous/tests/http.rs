// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The server over real HTTP and UDP on loopback, with plain `ureq` and a
//! UDP socket as the client: register, lookup, a pairing offer, refusals,
//! the `/rv` prefix, `/info`, `/health`.

use ed25519_dalek::SigningKey;
use std::time::Duration;
use varsto_rendezvous::proto::{
    self, ErrorAnswer, ErrorCode, Health, Info, Kind, Lookup, LookupAnswer, PutAnswer, PutSlot,
    PAIR_SLOT,
};
use varsto_rendezvous::Server;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into()
}

fn post<T: serde::Serialize>(a: &ureq::Agent, url: &str, body: &T) -> (u16, String) {
    let mut r = a
        .post(url)
        .header("Content-Type", "application/json")
        .send(serde_json::to_vec(body).unwrap().as_slice())
        .unwrap();
    let s = r.status().as_u16();
    (s, r.body_mut().read_to_string().unwrap())
}

fn get(a: &ureq::Agent, url: &str) -> (u16, String) {
    let mut r = a.get(url).call().unwrap();
    let s = r.status().as_u16();
    (s, r.body_mut().read_to_string().unwrap())
}

#[test]
fn register_lookup_pairing_and_health_over_http() {
    let (url, udp, h) = Server::spawn_for_tests();
    let a = agent();
    let k1 = SigningKey::from_bytes(&[1; 32]);
    let k2 = SigningKey::from_bytes(&[2; 32]);
    let tag = [0x11; 16];

    // Info first: the UDP endpoint comes from here.
    let (s, body) = get(&a, &format!("{url}/info"));
    assert_eq!(s, 200);
    let info: Info = serde_json::from_str(&body).unwrap();
    assert_eq!(info.v, proto::VERSION);
    assert_eq!(info.udp, vec![udp.to_string()]);
    assert!(info.relay);
    assert!(now().abs_diff(info.time) < 5);

    // Two devices register under one tag.
    for (k, slot) in [(&k1, [1u8; 16]), (&k2, [2; 16])] {
        let p = PutSlot::sign(Kind::Peer, tag, slot, k, now(), 3600, vec![slot[0]; 100]);
        let (s, body) = post(&a, &format!("{url}/v1/put"), &p);
        assert_eq!(s, 200, "{body}");
        let ans: PutAnswer = serde_json::from_str(&body).unwrap();
        assert!(ans.created);
    }
    // Another key cannot overwrite a slot; the answer names why.
    let steal = PutSlot::sign(Kind::Peer, tag, [1; 16], &k2, now() + 1, 3600, vec![0; 10]);
    let (s, body) = post(&a, &format!("{url}/v1/put"), &steal);
    assert_eq!(s, 403);
    assert_eq!(
        serde_json::from_str::<ErrorAnswer>(&body).unwrap().error,
        ErrorCode::NotOwner
    );
    // A forged body is refused.
    let mut forged = PutSlot::sign(Kind::Peer, tag, [3; 16], &k1, now(), 3600, vec![0; 10]);
    forged.blob.0[0] = 1;
    let (s, _) = post(&a, &format!("{url}/v1/put"), &forged);
    assert_eq!(s, 400);

    // Lookup, at the root and under /rv (Caddy may keep the prefix).
    for base in [url.clone(), format!("{url}/rv")] {
        let (s, body) = post(&a, &format!("{base}/v1/lookup"), &Lookup::new(tag));
        assert_eq!(s, 200);
        let l: LookupAnswer = serde_json::from_str(&body).unwrap();
        assert_eq!(l.kind, Some(Kind::Peer));
        assert_eq!(l.slots.len(), 2);
        assert_eq!(l.slots[0].blob.0, vec![1; 100]);
        assert!(
            !body.contains(&hex::encode(k1.verifying_key().to_bytes())),
            "owner keys are not handed out"
        );
    }
    let (s, body) = post(&a, &format!("{url}/v1/lookup"), &Lookup::new([0x99; 16]));
    assert_eq!(s, 200);
    assert!(serde_json::from_str::<LookupAnswer>(&body)
        .unwrap()
        .slots
        .is_empty());

    // A pairing offer: one slot, and a second holder of the code is told.
    let pk = SigningKey::from_bytes(&[7; 32]);
    let ptag = [0x22; 16];
    let offer = PutSlot::sign(Kind::Pair, ptag, PAIR_SLOT, &pk, now(), 600, vec![5; 40]);
    assert_eq!(post(&a, &format!("{url}/v1/put"), &offer).0, 200);
    let other = PutSlot::sign(Kind::Pair, ptag, PAIR_SLOT, &k1, now(), 600, vec![6; 40]);
    assert_eq!(post(&a, &format!("{url}/v1/put"), &other).0, 403);
    let (_, body) = post(&a, &format!("{url}/v1/lookup"), &Lookup::new(ptag));
    let l: LookupAnswer = serde_json::from_str(&body).unwrap();
    assert_eq!(l.kind, Some(Kind::Pair));
    assert_eq!(l.slots[0].blob.0, vec![5; 40]);
    let del = proto::DeleteSlot::sign(ptag, PAIR_SLOT, &pk, now());
    assert_eq!(post(&a, &format!("{url}/v1/delete"), &del).0, 200);
    let (_, body) = post(&a, &format!("{url}/v1/lookup"), &Lookup::new(ptag));
    assert!(serde_json::from_str::<LookupAnswer>(&body)
        .unwrap()
        .slots
        .is_empty());

    // Oversize bodies never reach the parser.
    let big = vec![b'x'; proto::MAX_BODY + 10];
    let mut r = a
        .post(&format!("{url}/v1/put"))
        .header("Content-Type", "application/json")
        .send(&big[..])
        .unwrap();
    assert_eq!(r.status().as_u16(), 413);
    let _ = r.body_mut().read_to_string();

    // UDP observe: the answer is the address we sent from.
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    sock.send_to(&proto::encode_observe(&[3; 12], None), udp)
        .unwrap();
    let mut buf = [0u8; 128];
    let (n, _) = sock.recv_from(&mut buf).unwrap();
    assert_eq!(
        proto::parse_observed(&buf[..n], &[3; 12]),
        Some(sock.local_addr().unwrap())
    );
    // Junk gets nothing.
    sock.send_to(b"VARSTOPU", udp).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    assert!(sock.recv_from(&mut buf).is_err());

    // Health: one line of counters, no per-tag detail.
    let (s, body) = get(&a, &format!("{url}/rv/health"));
    assert_eq!(s, 200);
    assert_eq!(body.lines().count(), 1);
    let hl = Health::parse(body.trim()).unwrap();
    assert_eq!(hl.tags, 1);
    assert_eq!(hl.slots, 2);
    assert_eq!(hl.udp_answered, 1);
    assert!(hl.refused >= 3);
    assert!(!body.contains(&hex::encode(tag)));
    h.stop();
}

#[test]
fn rate_limits_answer_429() {
    let (url, _udp, h) = Server::spawn_for_tests_with(|c| c.rates.lookup_per_ip = 2);
    let a = agent();
    let l = Lookup::new([1; 16]);
    assert_eq!(post(&a, &format!("{url}/v1/lookup"), &l).0, 200);
    assert_eq!(post(&a, &format!("{url}/v1/lookup"), &l).0, 200);
    let (s, body) = post(&a, &format!("{url}/v1/lookup"), &l);
    assert_eq!(s, 429);
    assert_eq!(
        serde_json::from_str::<ErrorAnswer>(&body).unwrap().error,
        ErrorCode::RateLimited
    );
    h.stop();
}

#[test]
fn a_large_lookup_comes_back_in_bounded_chunks() {
    let (_url, _udp, h) = Server::spawn_for_tests();
    let addr = h.http;
    let a = agent();
    let k = SigningKey::from_bytes(&[4; 32]);
    let blob = vec![0xab; proto::MAX_BLOB];
    let p = PutSlot::sign(
        Kind::Peer,
        [0x44; 16],
        [1; 16],
        &k,
        now(),
        3600,
        blob.clone(),
    );
    assert_eq!(post(&a, &format!("http://{addr}/v1/put"), &p).0, 200);

    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let req = serde_json::to_vec(&Lookup::new([0x44; 16])).unwrap();
    let head = format!(
        "POST /v1/lookup HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        req.len()
    );
    s.write_all(head.as_bytes()).unwrap();
    s.write_all(&req).unwrap();
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).unwrap();
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = std::str::from_utf8(&raw[..split]).unwrap();
    assert!(head.lines().next().unwrap().contains(" 200 "), "{head}");
    assert!(
        head.to_ascii_lowercase().contains("chunked"),
        "lookup was buffered whole: {head}"
    );
    let mut body = &raw[split + 4..];
    let mut joined = Vec::new();
    let mut chunks = 0usize;
    let cap = varsto_rendezvous::registry::LOOKUP_JSON_CHUNK;
    while !body.is_empty() {
        let rel = body.windows(2).position(|w| w == b"\r\n").unwrap();
        let line = std::str::from_utf8(&body[..rel]).unwrap();
        let n = usize::from_str_radix(line.split(';').next().unwrap().trim(), 16).unwrap();
        body = &body[rel + 2..];
        if n == 0 {
            break;
        }
        assert!(n <= cap, "chunk of {n} bytes exceeds {cap}");
        joined.extend_from_slice(&body[..n]);
        body = &body[n + 2..];
        chunks += 1;
    }
    assert!(chunks > 1, "a max blob was sent as one piece");
    let l: LookupAnswer = serde_json::from_slice(&joined).unwrap();
    assert_eq!(l.slots.len(), 1);
    assert_eq!(l.slots[0].blob.0, blob);
    h.stop();
}
