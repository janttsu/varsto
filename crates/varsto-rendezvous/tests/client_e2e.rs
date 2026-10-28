// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The core library's client against the server: peer slots under the
//! vault tag, pairing offers found by code and by link token, the control
//! channel with claims, a coordinated punch and a relayed byte stream.

use std::io::{Read, Write};
use std::time::Duration;
use varsto_core::crypto::SecretKey;
use varsto_core::rendezvous::{self, keys, proto, Control, RelayStream, RvClient, VaultKeys};
use varsto_rendezvous::Server;

#[test]
fn peers_publish_and_find_each_other_and_pairing_offers_are_found() {
    let (url, udp, h) = Server::spawn_for_tests();
    let rv = RvClient::new(&url).unwrap();
    assert_eq!(rv.udp_addrs().unwrap(), vec![udp]);
    let vault = VaultKeys::new(&SecretKey([3; 32]), "vault-one");
    let d1 = [1u8; 16];
    let d2 = [2u8; 16];
    let o1 = keys::owner_key(&[1; 32], &vault.tag());
    let o2 = keys::owner_key(&[2; 32], &vault.tag());
    let parts1 = vec![("vault/peers/a/1.rec".to_string(), vec![1u8; 500])];
    let parts2 = vec![("vault/peers/b/1.rec".to_string(), vec![2u8; 700])];
    rendezvous::publish_peer(&rv, &vault, &o1, &d1, &parts1).unwrap();
    rendezvous::publish_peer(&rv, &vault, &o2, &d2, &parts2).unwrap();
    let (found, bad) = rendezvous::fetch_peers(&rv, &vault).unwrap();
    assert_eq!(bad, 0);
    let mut got: Vec<_> = found.into_iter().map(|(_, p)| p).collect();
    got.sort();
    assert_eq!(got, vec![parts1.clone(), parts2.clone()]);
    // Another vault sees nothing.
    let other = VaultKeys::new(&SecretKey([4; 32]), "vault-one");
    assert!(rendezvous::fetch_peers(&rv, &other).unwrap().0.is_empty());
    // A second write within the same second is refused as stale (ts must
    // rise); the next second it is taken.
    let again = rendezvous::publish_peer(&rv, &vault, &o1, &d1, &parts1);
    if let Err(e) = again {
        assert_eq!(e.code(), Some(proto::ErrorCode::Stale));
        std::thread::sleep(Duration::from_millis(1100));
        rendezvous::publish_peer(&rv, &vault, &o1, &d1, &parts1).unwrap();
    }

    // Pairing: by link token and by code alone.
    let token = proto::random_token();
    let owner = keys::ephemeral_owner();
    let offer = proto::PairOffer {
        v: proto::VERSION,
        addrs: vec!["192.0.2.10:17894".into()],
        expires: rendezvous::now() + 600,
        relay: true,
    };
    rendezvous::register_pair_offer(&rv, "123456789", Some(&token), &offer, &owner).unwrap();
    let (_, by_token) = rendezvous::find_pair_offer(&rv, "123456789", Some(&token))
        .unwrap()
        .unwrap();
    assert_eq!(by_token, offer);
    let (k, by_code) = rendezvous::find_pair_offer(&rv, "123456789", None)
        .unwrap()
        .unwrap();
    assert_eq!(by_code, offer);
    assert_eq!(k.tag, keys::pair_code_keys("123456789").unwrap().tag);
    assert!(rendezvous::find_pair_offer(&rv, "123456780", None)
        .unwrap()
        .is_none());
    // Someone else with the same code is told the tag is taken.
    let clash =
        rendezvous::register_pair_offer(&rv, "123456789", None, &offer, &keys::ephemeral_owner());
    assert!(clash.is_err());
    rendezvous::withdraw_pair_offer(&rv, "123456789", Some(&token), &owner).unwrap();
    assert!(rendezvous::find_pair_offer(&rv, "123456789", Some(&token))
        .unwrap()
        .is_none());

    let health = rv.health().unwrap();
    assert_eq!(health.slots, 2);
    h.stop();
}

#[test]
fn control_channels_coordinate_a_punch_and_relay_a_stream() {
    let (url, udp, h) = Server::spawn_for_tests();
    let rv = RvClient::new(&url).unwrap();
    let vault = VaultKeys::new(&SecretKey([5; 32]), "vault-two");
    let tag = vault.tag();
    let (s1, s2) = (vault.slot(&[1; 16]), vault.slot(&[2; 16]));
    let o1 = keys::owner_key(&[1; 32], &tag);
    let o2 = keys::owner_key(&[2; 32], &tag);
    rendezvous::publish_peer(&rv, &vault, &o1, &[1; 16], &vec![("a".into(), vec![1])]).unwrap();
    rendezvous::publish_peer(&rv, &vault, &o2, &[2; 16], &vec![("b".into(), vec![2])]).unwrap();

    let wait = Duration::from_secs(5);
    let mut c1 = Control::open(rv.base()).unwrap();
    let claim = c1.claim(tag, s1, &o1);
    let w1 = c1.hello(vec![claim], wait).unwrap();
    assert_eq!(w1.claimed, vec![(tag, s1)]);
    let mut c2 = Control::open(rv.base()).unwrap();
    let claim = c2.claim(tag, s2, &o2);
    let w2 = c2.hello(vec![claim], wait).unwrap();
    assert_ne!(w1.udp_token, w2.udp_token);
    // A claim signed for another connection's challenge is not taken.
    let mut c3 = Control::open(rv.base()).unwrap();
    let stolen = c1.claim(tag, s2, &o2);
    assert!(c3.hello(vec![stolen], wait).unwrap().claimed.is_empty());

    // Both observe from their UDP sockets with their tokens.
    let u1 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let u2 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    for (u, t) in [(&u1, &w1.udp_token), (&u2, &w2.udp_token)] {
        u.set_read_timeout(Some(wait)).unwrap();
        u.send_to(&proto::encode_observe(&[9; 12], Some(t)), udp)
            .unwrap();
        let mut b = [0u8; 64];
        let (n, _) = u.recv_from(&mut b).unwrap();
        assert_eq!(
            proto::parse_observed(&b[..n], &[9; 12]),
            Some(u.local_addr().unwrap())
        );
    }
    c1.send(&proto::ToServer::Punch {
        id: 1,
        tag: proto::Hex(tag),
        slot: proto::Hex(s2),
    })
    .unwrap();
    match c1.recv(wait).unwrap() {
        Some(proto::ToClient::PunchGo {
            id: Some(1), peer, ..
        }) => {
            assert_eq!(peer, u2.local_addr().unwrap().to_string())
        }
        other => panic!("{other:?}"),
    }
    match c2.recv(wait).unwrap() {
        Some(proto::ToClient::PunchGo {
            id: None,
            peer,
            slot,
            ..
        }) => {
            assert_eq!(peer, u1.local_addr().unwrap().to_string());
            assert_eq!(slot.0, s2);
        }
        other => panic!("{other:?}"),
    }
    // A stranger may not coordinate with a vault's device.
    c3.send(&proto::ToServer::Relay {
        id: 2,
        tag: proto::Hex(tag),
        slot: proto::Hex(s2),
    })
    .unwrap();
    assert!(matches!(
        c3.recv(wait).unwrap(),
        Some(proto::ToClient::Error {
            error: proto::ErrorCode::NotOwner,
            ..
        })
    ));

    // A relay session: the asker gets its token, the holder an offer.
    c1.send(&proto::ToServer::Relay {
        id: 3,
        tag: proto::Hex(tag),
        slot: proto::Hex(s2),
    })
    .unwrap();
    let Some(proto::ToClient::RelayReady { id: 3, token: ta }) = c1.recv(wait).unwrap() else {
        panic!("no relay_ready")
    };
    let Some(proto::ToClient::RelayOffer { token: tb, .. }) = c2.recv(wait).unwrap() else {
        panic!("no relay_offer")
    };
    let base = rv.base().clone();
    let holder = std::thread::spawn(move || {
        let mut b = RelayStream::open(&base, &tb.0).unwrap();
        let mut buf = vec![0u8; 5];
        b.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
        let big = vec![0xabu8; 300_000];
        b.write_all(&big).unwrap();
        b.flush().unwrap();
        // Wait for the asker's last word before closing.
        let mut end = [0u8; 3];
        b.read_exact(&mut end).unwrap();
        assert_eq!(&end, b"bye");
        b.close();
    });
    let mut a = RelayStream::open(rv.base(), &ta.0).unwrap();
    a.write_all(b"hello").unwrap();
    a.flush().unwrap();
    let mut got = vec![0u8; 300_000];
    a.read_exact(&mut got).unwrap();
    assert!(got.iter().all(|b| *b == 0xab));
    a.write_all(b"bye").unwrap();
    a.flush().unwrap();
    holder.join().unwrap();
    // A used token does not open again.
    assert!(RelayStream::open(rv.base(), &ta.0).is_err());
    assert!(rv.health().unwrap().relay_bytes >= 300_008);

    c1.send(&proto::ToServer::Ping { id: 4 }).unwrap();
    assert_eq!(
        c1.recv(wait).unwrap(),
        Some(proto::ToClient::Pong { id: 4 })
    );
    c1.close();
    c2.close();
    c3.close();
    h.stop();
}
