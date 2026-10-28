// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The control hub (spec 83.6): which control connection speaks for which
//! slot, and what a `hello`, `claim`, `punch` or `relay` makes the server
//! send to whom. Pure logic: [`Hub::handle`] returns the messages to
//! deliver, the WebSocket front (`http.rs`) delivers them.

use crate::proto::{self, Claim, ErrorCode, Hex, Kind, Slot, Tag, ToClient, ToServer, Token};
use crate::registry::Registry;
use crate::relay::RelayTable;
use crate::udp::Observed;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// A control connection's id (never sent anywhere).
pub type SessionId = u64;

/// What the hub knows of one connection.
#[derive(Clone, Debug)]
pub struct Session {
    pub ip: IpAddr,
    pub challenge: [u8; 32],
    pub udp_token: Token,
    pub hello: bool,
    pub claims: HashSet<(Tag, Slot)>,
}

/// Every live control connection and the slots they claimed.
#[derive(Debug, Default)]
pub struct Hub {
    sessions: HashMap<SessionId, Session>,
    /// The newest connection that claimed each slot.
    by_slot: HashMap<(Tag, Slot), SessionId>,
}

/// One message to deliver.
pub type Out = (SessionId, ToClient);

fn error(id: Option<u32>, e: ErrorCode, msg: &str) -> ToClient {
    ToClient::Error {
        id,
        error: e,
        message: msg.to_string(),
    }
}

/// What the hub needs of the rest of the server for one message.
pub struct Ctx<'a> {
    pub registry: &'a Registry,
    pub relays: &'a mut RelayTable,
    pub observed: &'a Observed,
    pub now_unix: u64,
    pub now: Instant,
    /// Whether the relay is offered.
    pub relay_enabled: bool,
}

impl Hub {
    /// A new connection: its challenge and UDP token are chosen by the
    /// caller (random) and the first message to send is the challenge.
    pub fn open(
        &mut self,
        id: SessionId,
        ip: IpAddr,
        challenge: [u8; 32],
        udp_token: Token,
        now_unix: u64,
    ) -> ToClient {
        self.sessions.insert(
            id,
            Session {
                ip,
                challenge,
                udp_token,
                hello: false,
                claims: HashSet::new(),
            },
        );
        ToClient::Challenge {
            v: proto::VERSION,
            nonce: Hex(challenge),
            time: now_unix,
        }
    }

    /// The connection closed: its claims go with it.
    pub fn close(&mut self, id: SessionId) -> Option<Session> {
        let s = self.sessions.remove(&id)?;
        for c in &s.claims {
            if self.by_slot.get(c) == Some(&id) {
                self.by_slot.remove(c);
            }
        }
        Some(s)
    }

    pub fn session(&self, id: SessionId) -> Option<&Session> {
        self.sessions.get(&id)
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Connections from `ip`.
    pub fn count_ip(&self, ip: IpAddr) -> usize {
        let k = crate::limits::ip_key(ip);
        self.sessions
            .values()
            .filter(|s| crate::limits::ip_key(s.ip) == k)
            .count()
    }

    /// The connection holding a live claim on (`tag`, `slot`).
    pub fn holder(&self, tag: &Tag, slot: &Slot) -> Option<SessionId> {
        self.by_slot.get(&(*tag, *slot)).copied()
    }

    fn take_claims(&mut self, id: SessionId, claims: &[Claim], reg: &Registry, now: u64) {
        let Some(s) = self.sessions.get_mut(&id) else {
            return;
        };
        for c in claims {
            if c.verify(&s.challenge).is_err() {
                continue;
            }
            if reg.owner(&c.tag.0, &c.slot.0, now) != Some(c.owner.0) {
                continue;
            }
            if s.claims.len() >= proto::MAX_CLAIMS * 2 && !s.claims.contains(&(c.tag.0, c.slot.0)) {
                continue;
            }
            s.claims.insert((c.tag.0, c.slot.0));
            self.by_slot.insert((c.tag.0, c.slot.0), id);
        }
    }

    fn welcome(&self, id: SessionId) -> ToClient {
        let s = &self.sessions[&id];
        let mut claimed: Vec<(Hex<16>, Hex<16>)> =
            s.claims.iter().map(|(t, sl)| (Hex(*t), Hex(*sl))).collect();
        claimed.sort();
        ToClient::Welcome {
            udp_token: Hex(s.udp_token),
            claimed,
        }
    }

    /// May connection `id` ask for the holder of (`tag`, `slot`)? A pairing
    /// offer: anyone with a control connection (the joiner knows the code or
    /// the link, which is what found the tag). A peer slot: only a
    /// connection that holds a claim under the same tag (a device of the
    /// same vault).
    fn may_reach(
        &self,
        id: SessionId,
        tag: &Tag,
        reg: &Registry,
        now: u64,
    ) -> Result<(), ErrorCode> {
        match reg.kind(tag, now) {
            None => Err(ErrorCode::NotFound),
            Some(Kind::Pair) => Ok(()),
            Some(Kind::Peer) => {
                let s = &self.sessions[&id];
                if s.claims.iter().any(|(t, _)| t == tag) {
                    Ok(())
                } else {
                    Err(ErrorCode::NotOwner)
                }
            }
        }
    }

    /// The live holder of a slot that still exists in the registry.
    fn target(
        &self,
        id: SessionId,
        tag: &Tag,
        slot: &Slot,
        reg: &Registry,
        now: u64,
    ) -> Result<SessionId, ErrorCode> {
        self.may_reach(id, tag, reg, now)?;
        if reg.owner(tag, slot, now).is_none() {
            return Err(ErrorCode::NotFound);
        }
        match self.holder(tag, slot) {
            Some(t) if t != id => Ok(t),
            _ => Err(ErrorCode::NotFound),
        }
    }

    /// Handle one message of connection `id`.
    pub fn handle(&mut self, id: SessionId, msg: ToServer, ctx: &mut Ctx<'_>) -> Vec<Out> {
        let Some(s) = self.sessions.get(&id) else {
            return Vec::new();
        };
        let hello = s.hello;
        match msg {
            ToServer::Hello { claims, .. } => {
                if hello {
                    return vec![(id, error(None, ErrorCode::BadRequest, "hello twice"))];
                }
                if let Some(s) = self.sessions.get_mut(&id) {
                    s.hello = true;
                }
                self.take_claims(id, &claims, ctx.registry, ctx.now_unix);
                vec![(id, self.welcome(id))]
            }
            _ if !hello => vec![(id, error(None, ErrorCode::BadRequest, "hello first"))],
            ToServer::Claim { claims } => {
                self.take_claims(id, &claims, ctx.registry, ctx.now_unix);
                vec![(id, self.welcome(id))]
            }
            ToServer::Unclaim { slots } => {
                for (t, sl) in slots {
                    let key = (t.0, sl.0);
                    if let Some(s) = self.sessions.get_mut(&id) {
                        s.claims.remove(&key);
                    }
                    if self.by_slot.get(&key) == Some(&id) {
                        self.by_slot.remove(&key);
                    }
                }
                vec![(id, self.welcome(id))]
            }
            ToServer::Ping { id: n } => vec![(id, ToClient::Pong { id: n })],
            ToServer::Punch { id: n, tag, slot } => {
                let target = match self.target(id, &tag.0, &slot.0, ctx.registry, ctx.now_unix) {
                    Ok(t) => t,
                    Err(e) => return vec![(id, error(Some(n), e, ""))],
                };
                let age = Duration::from_secs(proto::OBSERVED_MAX_AGE_SECS);
                let mine = ctx
                    .observed
                    .get(&self.sessions[&id].udp_token, ctx.now, age);
                let theirs = ctx
                    .observed
                    .get(&self.sessions[&target].udp_token, ctx.now, age);
                let (Some(mine), Some(theirs)) = (mine, theirs) else {
                    return vec![(id, error(Some(n), ErrorCode::NotObserved, ""))];
                };
                vec![
                    (
                        id,
                        ToClient::PunchGo {
                            id: Some(n),
                            tag,
                            slot,
                            peer: theirs.to_string(),
                        },
                    ),
                    (
                        target,
                        ToClient::PunchGo {
                            id: None,
                            tag,
                            slot,
                            peer: mine.to_string(),
                        },
                    ),
                ]
            }
            ToServer::Relay { id: n, tag, slot } => {
                if !ctx.relay_enabled {
                    return vec![(id, error(Some(n), ErrorCode::Unavailable, "no relay here"))];
                }
                let target = match self.target(id, &tag.0, &slot.0, ctx.registry, ctx.now_unix) {
                    Ok(t) => t,
                    Err(e) => return vec![(id, error(Some(n), e, ""))],
                };
                let (a, b) = match ctx.relays.create(tag.0, ctx.now) {
                    Ok(x) => x,
                    Err(e) => return vec![(id, error(Some(n), e, ""))],
                };
                vec![
                    (
                        id,
                        ToClient::RelayReady {
                            id: n,
                            token: Hex(a),
                        },
                    ),
                    (
                        target,
                        ToClient::RelayOffer {
                            token: Hex(b),
                            tag,
                            slot,
                        },
                    ),
                ]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{PutSlot, PAIR_SLOT};
    use ed25519_dalek::SigningKey;
    use std::net::SocketAddr;

    const NOW: u64 = 1_800_000_000;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    struct World {
        reg: Registry,
        relays: RelayTable,
        obs: Observed,
        hub: Hub,
        at: Instant,
    }

    impl World {
        fn new() -> World {
            World {
                reg: Registry::new(100, 1 << 20),
                relays: RelayTable::new(2),
                obs: Observed::default(),
                hub: Hub::default(),
                at: Instant::now(),
            }
        }
        fn handle(&mut self, id: SessionId, m: ToServer) -> Vec<Out> {
            let mut ctx = Ctx {
                registry: &self.reg,
                relays: &mut self.relays,
                observed: &self.obs,
                now_unix: NOW,
                now: self.at,
                relay_enabled: true,
            };
            self.hub.handle(id, m, &mut ctx)
        }
        fn connect(&mut self, id: SessionId, tok: u8) -> [u8; 32] {
            let ch = [id as u8; 32];
            self.obs.register([tok; 16]);
            self.hub
                .open(id, "192.0.2.1".parse().unwrap(), ch, [tok; 16], NOW);
            ch
        }
        fn observe(&mut self, tok: u8, addr: &str) {
            let req = proto::encode_observe(&[0; 12], Some(&[tok; 16]));
            let a: SocketAddr = addr.parse().unwrap();
            crate::udp::handle_datagram(&mut self.obs, a, &req, self.at).unwrap();
        }
    }

    fn claim(ch: &[u8; 32], tag: u8, slot: Slot, k: &SigningKey) -> Claim {
        Claim::sign(ch, [tag; 16], slot, k)
    }

    #[test]
    fn claims_need_the_slot_owner_s_signature_over_this_connection_s_challenge() {
        let mut w = World::new();
        w.reg
            .put(
                &PutSlot::sign(Kind::Peer, [1; 16], [1; 16], &key(1), NOW, 100, vec![]),
                NOW,
            )
            .unwrap();
        let ch = w.connect(1, 1);
        let good = claim(&ch, 1, [1; 16], &key(1));
        let wrong_key = claim(&ch, 1, [1; 16], &key(2));
        let wrong_challenge = claim(&[0xee; 32], 1, [1; 16], &key(1));
        let no_slot = claim(&ch, 1, [2; 16], &key(1));
        let out = w.handle(
            1,
            ToServer::Hello {
                v: 1,
                claims: vec![wrong_key, wrong_challenge, no_slot, good],
            },
        );
        match &out[0].1 {
            ToClient::Welcome { udp_token, claimed } => {
                assert_eq!(udp_token.0, [1; 16]);
                assert_eq!(claimed, &vec![(Hex([1; 16]), Hex([1; 16]))]);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(w.hub.holder(&[1; 16], &[1; 16]), Some(1));
        w.hub.close(1);
        assert_eq!(w.hub.holder(&[1; 16], &[1; 16]), None);
    }

    #[test]
    fn nothing_but_hello_comes_first() {
        let mut w = World::new();
        w.connect(1, 1);
        let out = w.handle(1, ToServer::Ping { id: 1 });
        assert!(matches!(
            out[0].1,
            ToClient::Error {
                error: ErrorCode::BadRequest,
                ..
            }
        ));
        w.handle(
            1,
            ToServer::Hello {
                v: 1,
                claims: vec![],
            },
        );
        let out = w.handle(1, ToServer::Ping { id: 1 });
        assert_eq!(out[0].1, ToClient::Pong { id: 1 });
    }

    fn two_devices(w: &mut World) {
        for (n, slot) in [(1u8, [1u8; 16]), (2, [2; 16])] {
            w.reg
                .put(
                    &PutSlot::sign(Kind::Peer, [7; 16], slot, &key(n), NOW, 100, vec![]),
                    NOW,
                )
                .unwrap();
            let ch = w.connect(n as u64, n);
            w.handle(
                n as u64,
                ToServer::Hello {
                    v: 1,
                    claims: vec![claim(&ch, 7, slot, &key(n))],
                },
            );
        }
    }

    #[test]
    fn a_punch_tells_both_sides_the_other_s_observed_address() {
        let mut w = World::new();
        two_devices(&mut w);
        let ask = ToServer::Punch {
            id: 5,
            tag: Hex([7; 16]),
            slot: Hex([2; 16]),
        };
        let out = w.handle(1, ask.clone());
        assert!(matches!(
            out[0].1,
            ToClient::Error {
                error: ErrorCode::NotObserved,
                ..
            }
        ));
        w.observe(1, "198.51.100.1:5001");
        w.observe(2, "203.0.113.2:6002");
        let out = w.handle(1, ask);
        assert_eq!(out.len(), 2);
        assert_eq!(
            out[0],
            (
                1,
                ToClient::PunchGo {
                    id: Some(5),
                    tag: Hex([7; 16]),
                    slot: Hex([2; 16]),
                    peer: "203.0.113.2:6002".into()
                }
            )
        );
        assert_eq!(
            out[1],
            (
                2,
                ToClient::PunchGo {
                    id: None,
                    tag: Hex([7; 16]),
                    slot: Hex([2; 16]),
                    peer: "198.51.100.1:5001".into()
                }
            )
        );
    }

    #[test]
    fn a_stranger_cannot_reach_a_peer_slot_but_may_reach_a_pairing_offer() {
        let mut w = World::new();
        two_devices(&mut w);
        w.connect(3, 3);
        w.handle(
            3,
            ToServer::Hello {
                v: 1,
                claims: vec![],
            },
        );
        let out = w.handle(
            3,
            ToServer::Relay {
                id: 1,
                tag: Hex([7; 16]),
                slot: Hex([2; 16]),
            },
        );
        assert!(matches!(
            out[0].1,
            ToClient::Error {
                error: ErrorCode::NotOwner,
                ..
            }
        ));
        // A pairing offer held by connection 2.
        w.reg
            .put(
                &PutSlot::sign(Kind::Pair, [9; 16], PAIR_SLOT, &key(5), NOW, 60, vec![]),
                NOW,
            )
            .unwrap();
        let ch2 = w.hub.session(2).unwrap().challenge;
        w.handle(
            2,
            ToServer::Claim {
                claims: vec![claim(&ch2, 9, PAIR_SLOT, &key(5))],
            },
        );
        let out = w.handle(
            3,
            ToServer::Relay {
                id: 2,
                tag: Hex([9; 16]),
                slot: Hex(PAIR_SLOT),
            },
        );
        assert_eq!(out.len(), 2);
        let ToClient::RelayReady { token: a, .. } = &out[0].1 else {
            panic!("{out:?}")
        };
        let ToClient::RelayOffer { token: b, tag, .. } = &out[1].1 else {
            panic!("{out:?}")
        };
        assert_eq!(out[1].0, 2);
        assert_eq!(tag.0, [9; 16]);
        assert_ne!(a, b);
        // Unknown tags and own slots give nothing away.
        let out = w.handle(
            3,
            ToServer::Punch {
                id: 3,
                tag: Hex([0x55; 16]),
                slot: Hex([1; 16]),
            },
        );
        assert!(matches!(
            out[0].1,
            ToClient::Error {
                error: ErrorCode::NotFound,
                ..
            }
        ));
        let out = w.handle(
            1,
            ToServer::Relay {
                id: 4,
                tag: Hex([7; 16]),
                slot: Hex([1; 16]),
            },
        );
        assert!(matches!(
            out[0].1,
            ToClient::Error {
                error: ErrorCode::NotFound,
                ..
            }
        ));
    }

    #[test]
    fn relays_per_tag_are_capped() {
        let mut w = World::new();
        two_devices(&mut w);
        let ask = |n| ToServer::Relay {
            id: n,
            tag: Hex([7; 16]),
            slot: Hex([2; 16]),
        };
        assert!(matches!(
            w.handle(1, ask(1))[0].1,
            ToClient::RelayReady { .. }
        ));
        assert!(matches!(
            w.handle(1, ask(2))[0].1,
            ToClient::RelayReady { .. }
        ));
        assert!(matches!(
            w.handle(1, ask(3))[0].1,
            ToClient::Error {
                error: ErrorCode::RateLimited,
                ..
            }
        ));
    }
}
