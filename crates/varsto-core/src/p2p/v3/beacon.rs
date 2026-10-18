// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Signed LAN beacons of format 3 (design section 8):
//! `VARSTO3 <tag> <device> <port> <seq> <sig>` to the multicast group, where
//! `sig` is the Ed25519 part of the device's K6 (64 bytes, hex) over
//! `aad("p2p-beacon", [tag, device, port, seq])`. A listener keeps the
//! highest seq it accepted per device and ignores a beacon that is not
//! newer, not signed by a trusted full device, or not of this vault. A
//! beacon only suggests an address: it is used through a connection whose
//! handshake pins the certificate of the device's peer record.

use super::Id16;
use crate::crypto::{SigningKey, VerifyingKey};
use crate::ids::DeviceId;
use crate::p2p::{PeerAddr, BEACON_GROUP, BEACON_PORT};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const MAGIC: &str = "VARSTO3";

fn message(tag: &str, device: &Id16, port: u16, seq: u64) -> Vec<u8> {
    crate::crypto::aad_for_format(
        crate::record::FORMAT,
        "p2p-beacon",
        &[
            tag.as_bytes(),
            device,
            &port.to_le_bytes(),
            &seq.to_le_bytes(),
        ],
    )
}

/// One beacon line.
pub fn encode(tag: &str, device: &Id16, port: u16, seq: u64, signer: &SigningKey) -> String {
    let sig = signer.sign_ed25519(&message(tag, device, port, seq));
    format!(
        "{MAGIC} {tag} {} {port} {seq} {}",
        hex::encode(device),
        hex::encode(sig)
    )
}

/// Why a beacon was ignored (for tests and the debug log).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ignored {
    Malformed,
    OtherVault,
    Own,
    UnknownDevice,
    BadSignature,
    Replayed,
}

/// The highest seq accepted per device.
#[derive(Default)]
pub struct BeaconBook {
    highest: HashMap<Id16, u64>,
}

impl BeaconBook {
    /// Check one received beacon from `ip`. `key_of` gives the K6 public
    /// key of a trusted full device.
    pub fn accept(
        &mut self,
        msg: &str,
        ip: IpAddr,
        tag: &str,
        me: &Id16,
        key_of: &dyn Fn(&Id16) -> Option<VerifyingKey>,
    ) -> Result<PeerAddr, Ignored> {
        let parts: Vec<&str> = msg.split_whitespace().collect();
        let [magic, t, dev, port, seq, sig] = parts.as_slice() else {
            return Err(Ignored::Malformed);
        };
        if *magic != MAGIC {
            return Err(Ignored::Malformed);
        }
        if *t != tag {
            return Err(Ignored::OtherVault);
        }
        let device = crate::record::kinds::parse_id16(dev).ok_or(Ignored::Malformed)?;
        let port: u16 = port.parse().map_err(|_| Ignored::Malformed)?;
        let seq: u64 = seq.parse().map_err(|_| Ignored::Malformed)?;
        let sig = hex::decode(sig).map_err(|_| Ignored::Malformed)?;
        if &device == me {
            return Err(Ignored::Own);
        }
        let key = key_of(&device).ok_or(Ignored::UnknownDevice)?;
        key.verify_ed25519(&message(tag, &device, port, seq), &sig)
            .map_err(|_| Ignored::BadSignature)?;
        if self.highest.get(&device).is_some_and(|h| *h >= seq) {
            return Err(Ignored::Replayed);
        }
        self.highest.insert(device, seq);
        Ok(PeerAddr {
            device: DeviceId::from_bytes(&device),
            addr: SocketAddr::new(ip, port),
            name: String::new(),
        })
    }
}

/// The beacon of one device: announces itself and listens for others.
pub struct Beacon {
    sock: UdpSocket,
    tag: String,
    device: Id16,
    port: u16,
    signer: Arc<SigningKey>,
    seq: AtomicU64,
    book: Mutex<BeaconBook>,
}

impl Beacon {
    pub fn new(tag: String, device: Id16, port: u16, signer: Arc<SigningKey>) -> Result<Beacon> {
        let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, BEACON_PORT))
            .or_else(|_| UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)))
            .context("bind beacon socket")?;
        let _ = sock.join_multicast_v4(&BEACON_GROUP, &Ipv4Addr::UNSPECIFIED);
        sock.set_read_timeout(Some(Duration::from_millis(500)))?;
        // Sequence numbers rise across restarts as long as the clock does;
        // a listener that saw a higher one ignores us until we pass it,
        // which costs a LAN shortcut, never trust.
        let start = (crate::util::now_utc().max(0) as u64) << 16;
        Ok(Beacon {
            sock,
            tag,
            device,
            port,
            signer,
            seq: AtomicU64::new(start),
            book: Mutex::default(),
        })
    }

    pub fn announce(&self) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let msg = encode(&self.tag, &self.device, self.port, seq, &self.signer);
        let _ = self
            .sock
            .send_to(msg.as_bytes(), (BEACON_GROUP, BEACON_PORT));
    }

    /// Peers heard for `dur` whose beacons check out.
    pub fn listen(
        &self,
        dur: Duration,
        key_of: &dyn Fn(&Id16) -> Option<VerifyingKey>,
    ) -> Vec<PeerAddr> {
        let deadline = Instant::now() + dur;
        let mut out: Vec<PeerAddr> = Vec::new();
        let mut buf = [0u8; 512];
        while Instant::now() < deadline {
            let Ok((n, from)) = self.sock.recv_from(&mut buf) else {
                continue;
            };
            let msg = String::from_utf8_lossy(&buf[..n]).to_string();
            let got =
                self.book
                    .lock()
                    .unwrap()
                    .accept(&msg, from.ip(), &self.tag, &self.device, key_of);
            if let Ok(p) = got {
                if !out.iter().any(|o| o.addr == p.addr) {
                    out.push(p);
                }
            }
        }
        out
    }
}
