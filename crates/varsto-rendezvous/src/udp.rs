// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! UDP observe handling (spec 83.5) as pure functions over datagrams: an
//! observe request (a STUN Binding Request, optionally with the control
//! connection's UDP token) is answered with the address it came from, and
//! a known token records that address for punch coordination. The server
//! never sends a datagram nobody asked for. An answer is 32 bytes for IPv4
//! (44 for IPv6): a plain 20-byte request gets 1.6 times its size back, as
//! from any STUN server, a request with a token (40 bytes) less than its
//! size; the per-address UDP rate limit caps both.

use crate::proto::{self, Token};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// The observed address of each live control connection's UDP token.
#[derive(Debug, Default)]
pub struct Observed {
    by_token: HashMap<Token, Option<(SocketAddr, Instant)>>,
}

impl Observed {
    /// A control connection opened with this token.
    pub fn register(&mut self, token: Token) {
        self.by_token.insert(token, None);
    }

    /// Its connection closed.
    pub fn unregister(&mut self, token: &Token) {
        self.by_token.remove(token);
    }

    /// The token's address, if one was observed within `max_age`.
    pub fn get(&self, token: &Token, now: Instant, max_age: Duration) -> Option<SocketAddr> {
        match self.by_token.get(token)? {
            Some((a, at)) if now.saturating_duration_since(*at) <= max_age => Some(*a),
            _ => None,
        }
    }

    pub fn len(&self) -> usize {
        self.by_token.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_token.is_empty()
    }
}

/// Answer one datagram from `src`: `Some(answer)` for an observe request
/// (recording `src` under its token when the token belongs to a live
/// control connection; an unknown token is answered like plain STUN and
/// recorded nowhere), `None` for anything else, which is dropped.
pub fn handle_datagram(
    obs: &mut Observed,
    src: SocketAddr,
    buf: &[u8],
    now: Instant,
) -> Option<Vec<u8>> {
    let o = proto::parse_observe(buf)?;
    if let Some(t) = o.token {
        if let Some(slot) = obs.by_token.get_mut(&t) {
            *slot = Some((src, now));
        }
    }
    Some(proto::encode_observed(&o.tx, src))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_observe_is_answered_with_the_source_and_records_a_known_token() {
        let mut obs = Observed::default();
        let tok = [5u8; 16];
        obs.register(tok);
        let src: SocketAddr = "198.51.100.20:40001".parse().unwrap();
        let now = Instant::now();
        let req = proto::encode_observe(&[1; 12], Some(&tok));
        let ans = handle_datagram(&mut obs, src, &req, now).unwrap();
        assert_eq!(proto::parse_observed(&ans, &[1; 12]), Some(src));
        assert!(
            ans.len() <= req.len() + 8,
            "no amplification worth the name"
        );
        assert_eq!(obs.get(&tok, now, Duration::from_secs(120)), Some(src));
        assert_eq!(
            obs.get(
                &tok,
                now + Duration::from_secs(121),
                Duration::from_secs(120)
            ),
            None
        );
        obs.unregister(&tok);
        assert!(obs.is_empty());
    }

    #[test]
    fn unknown_tokens_and_plain_stun_are_answered_but_not_recorded() {
        let mut obs = Observed::default();
        let src: SocketAddr = "198.51.100.20:40001".parse().unwrap();
        let now = Instant::now();
        let plain = proto::encode_observe(&[2; 12], None);
        assert!(handle_datagram(&mut obs, src, &plain, now).is_some());
        let stranger = proto::encode_observe(&[2; 12], Some(&[9; 16]));
        assert!(handle_datagram(&mut obs, src, &stranger, now).is_some());
        assert!(obs.is_empty());
        assert!(handle_datagram(&mut obs, src, b"VARSTOPU", now).is_none());
        assert!(handle_datagram(&mut obs, src, &[0u8; 1200], now).is_none());
    }
}
