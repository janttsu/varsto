// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Request tokens bound to the TLS connection (format 3 design, section 8).
//!
//! `X-Varsto-Auth: <device>:<responder>:<unix>:<nonce 32 hex>:<mac 64 hex>`
//! with `mac = keyed_hash(exporter, aad("p2p-token", [device, responder,
//! unix, nonce, path]))`, where `exporter` is the TLS exporter value of the
//! connection the request travels on (label `EXPORTER-varsto-p2p-token`, no
//! context, 32 bytes). Both ends of one connection compute the same value;
//! nobody else can, and another connection has another one.
//!
//! The responder accepts a token only when `device` is the device the
//! client certificate of that very connection belongs to (the directory of
//! accepted peer records says so), `responder` is itself, the time is
//! within five minutes and the nonce was not seen within that window. No
//! vault secret is involved: holding the vault key without a device's
//! certificate and its private key gives nothing.

use super::Id16;
use crate::crypto::{self, SecretKey};
use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;

/// How far a token's time may be from the responder's clock.
pub const WINDOW_SECS: i64 = 300;
/// Nonces kept per responder (older ones leave first).
pub const MAX_NONCES: usize = 65_536;

/// Why a token was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenError {
    Malformed,
    /// It names another responder.
    OtherResponder,
    /// It names another device than the certificate of the connection.
    OtherDevice,
    /// Its time is outside the window.
    Stale,
    /// The MAC does not verify: another connection, another path, forged.
    BadMac,
    /// Its nonce was used already.
    Replayed,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TokenError::Malformed => "malformed token",
            TokenError::OtherResponder => "token for another device",
            TokenError::OtherDevice => "token of another device than the certificate",
            TokenError::Stale => "token outside the time window",
            TokenError::BadMac => "token does not verify on this connection",
            TokenError::Replayed => "token used already",
        })
    }
}

fn mac(
    exporter: &[u8; 32],
    device: &Id16,
    responder: &Id16,
    unix: i64,
    nonce: &[u8; 16],
    path: &str,
) -> [u8; 32] {
    let key = SecretKey(*exporter);
    crypto::keyed_hash(
        &key,
        &crypto::aad_for_format(
            crate::record::FORMAT,
            "p2p-token",
            &[
                device,
                responder,
                &unix.to_le_bytes(),
                nonce,
                path.as_bytes(),
            ],
        ),
    )
}

/// A token for a request of `device` to `responder` for `path`, on the
/// connection whose exporter value is `exporter`.
pub fn make(exporter: &[u8; 32], device: &Id16, responder: &Id16, path: &str, now: i64) -> String {
    let mut nonce = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
    let m = mac(exporter, device, responder, now, &nonce, path);
    format!(
        "{}:{}:{now}:{}:{}",
        hex::encode(device),
        hex::encode(responder),
        hex::encode(nonce),
        hex::encode(m)
    )
}

/// A parsed token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub device: Id16,
    pub responder: Id16,
    pub unix: i64,
    pub nonce: [u8; 16],
    pub mac: [u8; 32],
}

impl Token {
    pub fn parse(header: &str) -> Result<Token, TokenError> {
        let mut it = header.trim().split(':');
        let mut next = || it.next().ok_or(TokenError::Malformed);
        let (d, r, t, n, m) = (next()?, next()?, next()?, next()?, next()?);
        if it.next().is_some() {
            return Err(TokenError::Malformed);
        }
        let hex16 = |s: &str| crate::record::kinds::parse_id16(s).ok_or(TokenError::Malformed);
        let mut nonce = [0u8; 16];
        let mut mac = [0u8; 32];
        if n.len() != 32 || m.len() != 64 {
            return Err(TokenError::Malformed);
        }
        hex::decode_to_slice(n, &mut nonce).map_err(|_| TokenError::Malformed)?;
        hex::decode_to_slice(m, &mut mac).map_err(|_| TokenError::Malformed)?;
        Ok(Token {
            device: hex16(d)?,
            responder: hex16(r)?,
            unix: t.parse().map_err(|_| TokenError::Malformed)?,
            nonce,
            mac,
        })
    }
}

/// The nonces a responder accepted inside the window.
#[derive(Default)]
pub struct NonceWindow {
    inner: Mutex<Spent>,
}

/// The nonces, and the same in the order they were spent, with their time.
type Spent = (HashSet<[u8; 16]>, VecDeque<(i64, [u8; 16])>);

impl NonceWindow {
    /// Record `nonce` seen at `now`; false when it was used already.
    pub fn spend(&self, nonce: [u8; 16], now: i64) -> bool {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let (set, order) = &mut *g;
        while let Some((t, _)) = order.front() {
            if now - *t > 2 * WINDOW_SECS || order.len() >= MAX_NONCES {
                let (_, n) = order.pop_front().expect("checked front");
                set.remove(&n);
            } else {
                break;
            }
        }
        if !set.insert(nonce) {
            return false;
        }
        order.push_back((now, nonce));
        true
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.1.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Check `header` for a request for `path` on a connection with exporter
/// value `exporter`, whose client certificate belongs to `presented`, at
/// responder `me`; spends the nonce. The device of the request on success.
pub fn verify(
    header: &str,
    exporter: &[u8; 32],
    presented: &Id16,
    me: &Id16,
    path: &str,
    now: i64,
    seen: &NonceWindow,
) -> Result<Id16, TokenError> {
    let t = Token::parse(header)?;
    if &t.responder != me {
        return Err(TokenError::OtherResponder);
    }
    if &t.device != presented {
        return Err(TokenError::OtherDevice);
    }
    if now.abs_diff(t.unix) > WINDOW_SECS as u64 {
        return Err(TokenError::Stale);
    }
    let want = mac(exporter, &t.device, &t.responder, t.unix, &t.nonce, path);
    if !crypto::ct_eq(&want, &t.mac) {
        return Err(TokenError::BadMac);
    }
    if !seen.spend(t.nonce, now) {
        return Err(TokenError::Replayed);
    }
    Ok(t.device)
}
