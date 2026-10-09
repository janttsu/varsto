// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A minimal STUN client (RFC 5389 Binding Request) used to learn the
//! address a NAT shows to the internet for our UDP socket. Only the Binding
//! method and the two mapped-address attributes are implemented: that is all
//! hole punching needs, and it keeps the module free of extra crates. The
//! encoder and parser work on byte slices so that the same code serves the
//! blocking std socket (command line) and the shared QUIC socket (service).

use anyhow::{anyhow, bail, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Servers asked when the user has not configured any. Public, free, and run
/// by parties with no interest in this traffic; they only ever see an empty
/// Binding Request from our UDP port.
pub const DEFAULT_SERVERS: [&str; 3] = [
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun.nextcloud.com:443",
];

pub const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const HEADER_LEN: usize = 20;

/// What two Binding Responses tell about the NAT in front of us. A guess:
/// the classification uses two servers and no second port, so it cannot see
/// every NAT behaviour, but it separates the cases that matter for punching.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Nat {
    /// The mapped address is one of our own: no NAT (public address).
    None,
    /// Every server saw the same mapping: a cone NAT, punchable.
    Cone,
    /// Servers saw different ports: a symmetric NAT, punching rarely works.
    Symmetric,
    /// No answer, or one server only: cannot tell.
    #[default]
    Unknown,
}

impl Nat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Nat::None => "none",
            Nat::Cone => "cone",
            Nat::Symmetric => "symmetric",
            Nat::Unknown => "unknown",
        }
    }
}

pub fn new_transaction_id() -> [u8; 12] {
    let mut id = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}

/// A Binding Request: 20-byte header, no attributes.
pub fn encode_binding_request(tx_id: &[u8; 12]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN);
    out.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(tx_id);
    out
}

/// Does this datagram look like STUN? The first two bits are zero and the
/// magic cookie is in place. QUIC packets never match: a short header has its
/// fixed bit (0x40) set and a long header its form bit (0x80).
pub fn is_stun(buf: &[u8]) -> bool {
    buf.len() >= HEADER_LEN && buf[0] & 0xC0 == 0 && buf[4..8] == MAGIC_COOKIE.to_be_bytes()
}

/// The mapped address in a Binding Success Response for `tx_id`.
/// XOR-MAPPED-ADDRESS is preferred; MAPPED-ADDRESS is accepted from old
/// servers. Other messages (errors, other transactions) are an error.
pub fn parse_binding_response(buf: &[u8], tx_id: &[u8; 12]) -> Result<SocketAddr> {
    if !is_stun(buf) {
        bail!("not a STUN message");
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    let msg_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if &buf[8..20] != tx_id {
        bail!("STUN transaction id mismatch");
    }
    if msg_type != BINDING_SUCCESS {
        bail!("STUN message type {msg_type:#06x} is not a binding success");
    }
    if buf.len() < HEADER_LEN + msg_len {
        bail!("truncated STUN message");
    }
    let mut pos = HEADER_LEN;
    let end = HEADER_LEN + msg_len;
    let mut plain: Option<SocketAddr> = None;
    while pos + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;
        if pos + attr_len > end {
            bail!("truncated STUN attribute");
        }
        let value = &buf[pos..pos + attr_len];
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => return parse_address(value, Some(tx_id)),
            ATTR_MAPPED_ADDRESS => plain = Some(parse_address(value, None)?),
            _ => {}
        }
        // Attributes are padded to four bytes.
        pos += (attr_len + 3) & !3;
    }
    plain.ok_or_else(|| anyhow!("STUN response carries no mapped address"))
}

/// `0x00 family port address`, XORed with the cookie and transaction id when
/// `xor` is given (RFC 5389 section 15.2).
fn parse_address(value: &[u8], xor: Option<&[u8; 12]>) -> Result<SocketAddr> {
    if value.len() < 4 {
        bail!("short STUN address attribute");
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor.is_some() {
        port ^= (MAGIC_COOKIE >> 16) as u16;
    }
    let ip = match family {
        0x01 => {
            if value.len() < 8 {
                bail!("short STUN IPv4 attribute");
            }
            let mut raw = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            if xor.is_some() {
                raw ^= MAGIC_COOKIE;
            }
            IpAddr::V4(Ipv4Addr::from(raw))
        }
        0x02 => {
            if value.len() < 20 {
                bail!("short STUN IPv6 attribute");
            }
            let mut raw = [0u8; 16];
            raw.copy_from_slice(&value[4..20]);
            if let Some(tx) = xor {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                mask[4..].copy_from_slice(tx);
                for (b, m) in raw.iter_mut().zip(mask.iter()) {
                    *b ^= m;
                }
            }
            IpAddr::V6(Ipv6Addr::from(raw))
        }
        f => bail!("unknown STUN address family {f}"),
    };
    Ok(SocketAddr::new(ip, port))
}

/// Resolve a `host:port` server name to the addresses a socket of `family`
/// can reach (an IPv4 socket cannot send to an IPv6 server).
pub fn resolve(server: &str, ipv6: bool) -> Vec<SocketAddr> {
    server
        .to_socket_addrs()
        .map(|it| it.filter(|a| a.is_ipv6() == ipv6).collect())
        .unwrap_or_default()
}

/// One blocking query over a std socket, for the command line and tests.
pub fn query(sock: &UdpSocket, server: SocketAddr, timeout: Duration) -> Result<SocketAddr> {
    let tx = new_transaction_id();
    sock.send_to(&encode_binding_request(&tx), server)?;
    let old = sock.read_timeout()?;
    sock.set_read_timeout(Some(timeout))?;
    let mut buf = [0u8; 1500];
    let result = loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Ok(a) = parse_binding_response(&buf[..n], &tx) {
                    break Ok(a);
                }
            }
            Err(e) => break Err(anyhow!("no STUN answer from {server}: {e}")),
        }
    };
    sock.set_read_timeout(old)?;
    result
}

/// Ask every configured server once from `sock`; the first two answers decide
/// the NAT guess. An empty server list disables STUN and yields nothing.
pub fn probe(sock: &UdpSocket, servers: &[String], timeout: Duration) -> Probe {
    let ipv6 = sock.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
    let mut mapped = Vec::new();
    for s in servers {
        let Some(addr) = resolve(s, ipv6).into_iter().next() else {
            continue;
        };
        if let Ok(a) = query(sock, addr, timeout) {
            mapped.push(a);
        }
        if mapped.len() >= 2 {
            break;
        }
    }
    let nat = classify(&super::local_ipv4_addrs(), &mapped);
    Probe { mapped, nat }
}

/// Result of a NAT probe: the addresses servers saw and the guess.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Probe {
    pub mapped: Vec<SocketAddr>,
    pub nat: Nat,
}

impl Probe {
    /// Distinct mapped addresses, for the peer record.
    pub fn public_addrs(&self) -> Vec<SocketAddr> {
        let mut out: Vec<SocketAddr> = Vec::new();
        for a in &self.mapped {
            if !out.contains(a) {
                out.push(*a);
            }
        }
        out
    }
}

/// Classify from the mapped addresses two servers returned and our own
/// interface addresses: our own address means no NAT, agreement means a cone
/// NAT, disagreement a symmetric one, fewer than two answers no guess.
pub fn classify(local: &[IpAddr], mapped: &[SocketAddr]) -> Nat {
    if mapped.iter().any(|m| local.contains(&m.ip())) {
        return Nat::None;
    }
    match mapped {
        [] | [_] => Nat::Unknown,
        [first, rest @ ..] => {
            if rest.iter().all(|m| m == first) {
                Nat::Cone
            } else {
                Nat::Symmetric
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(tx: &[u8; 12], attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (t, v) in attrs {
            body.extend_from_slice(&t.to_be_bytes());
            body.extend_from_slice(&(v.len() as u16).to_be_bytes());
            body.extend_from_slice(v);
            while body.len() % 4 != 0 {
                body.push(0);
            }
        }
        let mut out = Vec::new();
        out.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(tx);
        out.extend_from_slice(&body);
        out
    }

    fn xor_v4(addr: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut v = vec![0u8, 0x01];
        v.extend_from_slice(&(port ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        v.extend_from_slice(&(u32::from(addr) ^ MAGIC_COOKIE).to_be_bytes());
        v
    }

    #[test]
    fn binding_request_has_the_header_layout() {
        let tx = [7u8; 12];
        let req = encode_binding_request(&tx);
        assert_eq!(req.len(), 20);
        assert_eq!(&req[..4], &[0, 1, 0, 0]);
        assert_eq!(&req[4..8], &MAGIC_COOKIE.to_be_bytes());
        assert_eq!(&req[8..], &tx);
        assert!(is_stun(&req));
        // A QUIC short header (fixed bit set) or long header is never STUN.
        assert!(!is_stun(&[0x40; 20]));
        assert!(!is_stun(&[0xC0; 20]));
    }

    #[test]
    fn xor_mapped_ipv4_is_preferred_over_plain() {
        let tx = new_transaction_id();
        let plain = {
            let mut v = vec![0u8, 0x01];
            v.extend_from_slice(&1234u16.to_be_bytes());
            v.extend_from_slice(&[10, 0, 0, 1]);
            v
        };
        let msg = response(
            &tx,
            &[
                (ATTR_MAPPED_ADDRESS, plain),
                (0x8022, b"server".to_vec()), // SOFTWARE, padded, ignored
                (
                    ATTR_XOR_MAPPED_ADDRESS,
                    xor_v4(Ipv4Addr::new(203, 0, 113, 7), 40000),
                ),
            ],
        );
        assert_eq!(
            parse_binding_response(&msg, &tx).unwrap(),
            "203.0.113.7:40000".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn plain_mapped_address_is_the_fallback() {
        let tx = new_transaction_id();
        let mut plain = vec![0u8, 0x01];
        plain.extend_from_slice(&1234u16.to_be_bytes());
        plain.extend_from_slice(&[198, 51, 100, 2]);
        let msg = response(&tx, &[(ATTR_MAPPED_ADDRESS, plain)]);
        assert_eq!(
            parse_binding_response(&msg, &tx).unwrap(),
            "198.51.100.2:1234".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn xor_mapped_ipv6_roundtrips() {
        let tx = new_transaction_id();
        let ip: Ipv6Addr = "2001:db8::42".parse().unwrap();
        let port = 5555u16;
        let mut v = vec![0u8, 0x02];
        v.extend_from_slice(&(port ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        let mut mask = [0u8; 16];
        mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        mask[4..].copy_from_slice(&tx);
        let raw = ip.octets();
        for i in 0..16 {
            v.push(raw[i] ^ mask[i]);
        }
        let msg = response(&tx, &[(ATTR_XOR_MAPPED_ADDRESS, v)]);
        assert_eq!(
            parse_binding_response(&msg, &tx).unwrap(),
            SocketAddr::new(IpAddr::V6(ip), port)
        );
    }

    #[test]
    fn wrong_transaction_errors_and_truncation_are_refused() {
        let tx = [1u8; 12];
        let msg = response(
            &tx,
            &[(
                ATTR_XOR_MAPPED_ADDRESS,
                xor_v4(Ipv4Addr::new(203, 0, 113, 7), 1),
            )],
        );
        assert!(parse_binding_response(&msg, &[2u8; 12]).is_err());
        assert!(parse_binding_response(&msg[..msg.len() - 3], &tx).is_err());
        let mut err = msg.clone();
        err[1] = 0x11; // Binding Error Response
        assert!(parse_binding_response(&err, &tx).is_err());
        assert!(parse_binding_response(b"short", &tx).is_err());
    }

    #[test]
    fn nat_is_classified_from_two_mappings() {
        let local: Vec<IpAddr> = vec!["192.168.1.5".parse().unwrap()];
        let a: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let b: SocketAddr = "203.0.113.7:40001".parse().unwrap();
        assert_eq!(classify(&local, &[]), Nat::Unknown);
        assert_eq!(classify(&local, &[a]), Nat::Unknown);
        assert_eq!(classify(&local, &[a, a]), Nat::Cone);
        assert_eq!(classify(&local, &[a, b]), Nat::Symmetric);
        let public: Vec<IpAddr> = vec![a.ip()];
        assert_eq!(classify(&public, &[a, b]), Nat::None);
        assert_eq!(
            serde_json::to_string(&Nat::Symmetric).unwrap(),
            "\"symmetric\""
        );
    }

    #[test]
    fn a_local_stun_server_answers_the_blocking_query() {
        // A tiny server on localhost: answer every request with an XOR-mapped address.
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server.local_addr().unwrap();
        let th = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            let (n, from) = server.recv_from(&mut buf).unwrap();
            assert!(is_stun(&buf[..n]));
            let mut tx = [0u8; 12];
            tx.copy_from_slice(&buf[8..20]);
            let IpAddr::V4(ip) = from.ip() else { panic!() };
            let msg = response(&tx, &[(ATTR_XOR_MAPPED_ADDRESS, xor_v4(ip, from.port()))]);
            server.send_to(&msg, from).unwrap();
        });
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mapped = query(&client, server_addr, Duration::from_secs(2)).unwrap();
        assert_eq!(mapped, client.local_addr().unwrap());
        th.join().unwrap();
    }
}
