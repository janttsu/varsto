// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Pairing: add a device to a vault from the interface with a one-time code.
//!
//! The device that already holds the vault opens an offer and shows a code of
//! nine digits. The new device finds it on the LAN (a query to the multicast
//! group and the broadcast address, answered by unicast) or at an address the
//! user types, and the two run SPAKE2 keyed by the code. A wrong code yields a
//! different key, so each connection is one online guess and nothing a
//! listener records can be checked against guesses offline. After key
//! confirmation in both directions the offering device sends the vault key
//! and its storage settings, secrets included, sealed under the shared key.
//! An offer serves one device, lasts ten minutes and closes after three
//! failed attempts.
//!
//! The first three digits are the rendezvous id that discovery matches on; it
//! only tells concurrent offers apart. The password is all nine digits.

use crate::crypto::{self, SecretKey};
use crate::storage::StorageSpec;
use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// UDP port the offering device answers discovery queries on.
pub const PAIR_PORT: u16 = 17894;
/// Multicast group of discovery queries (the LAN beacon group).
pub const PAIR_GROUP: Ipv4Addr = crate::p2p::BEACON_GROUP;
pub const OFFER_TTL: Duration = Duration::from_secs(600);
pub const MAX_ATTEMPTS: u32 = 3;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_LINE: u64 = 1 << 20;
const QUERY: &str = "VARSTO-PAIR?";
const ANSWER: &str = "VARSTO-PAIR!";

/// What a new device receives: everything it needs to join.
#[derive(Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub vault_id: String,
    pub vault_key: String,
    /// Name of the device that sent it.
    pub from: String,
    pub storages: Vec<BundleStorage>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BundleStorage {
    pub spec: StorageSpec,
    /// The S3 secret access key, when the storage needs one.
    #[serde(default)]
    pub secret: Option<String>,
}

/// A fresh code, `123-456-789`.
pub fn new_code() -> String {
    let mut rng = rand::thread_rng();
    let d: String = (0..9)
        .map(|_| char::from(b'0' + rng.gen_range(0..10u8)))
        .collect();
    format!("{}-{}-{}", &d[0..3], &d[3..6], &d[6..9])
}

/// The nine digits of a code as typed (spaces, dashes and dots ignored).
pub fn normalize(code: &str) -> Result<String> {
    let d: String = code
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '.'))
        .collect();
    if d.len() != 9 || !d.chars().all(|c| c.is_ascii_digit()) {
        bail!("a pairing code has nine digits, like 123-456-789");
    }
    Ok(d)
}

fn spake_ids() -> (Identity, Identity) {
    (
        Identity::new(b"varsto-pair-offer"),
        Identity::new(b"varsto-pair-join"),
    )
}

fn confirm(key: &SecretKey, side: &str) -> String {
    hex::encode(crypto::keyed_hash(
        key,
        format!("varsto-pair confirm {side}").as_bytes(),
    ))
}

fn session_key(raw: &[u8]) -> Result<SecretKey> {
    SecretKey::from_bytes(&crypto::hash(raw))
}

fn read_line(r: &mut impl BufRead) -> Result<serde_json::Value> {
    let mut line = String::new();
    r.take(MAX_LINE).read_line(&mut line)?;
    if line.trim().is_empty() {
        bail!("the other device closed the connection");
    }
    Ok(serde_json::from_str(line.trim())?)
}

fn write_line(w: &mut impl Write, v: &serde_json::Value) -> Result<()> {
    w.write_all(format!("{v}\n").as_bytes())?;
    w.flush()?;
    Ok(())
}

fn field(v: &serde_json::Value, k: &str) -> Result<String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("pairing message lacks {k}"))
}

// ----- offering device ------------------------------------------------------

#[derive(Clone, Serialize)]
pub struct OfferStatus {
    pub open: bool,
    pub code: String,
    pub port: u16,
    /// Addresses the new device can type when discovery does not find us.
    pub addresses: Vec<String>,
    pub expires_in_secs: u64,
    pub failed_attempts: u32,
    /// Name of the device that received the vault, once one has.
    pub paired_with: Option<String>,
    /// Why the offer closed, if it closed without pairing.
    pub closed_reason: Option<String>,
}

struct OfferInner {
    status: OfferStatus,
    expires: Instant,
}

pub struct Offer {
    inner: Arc<Mutex<OfferInner>>,
    stop: Arc<AtomicBool>,
}

impl Offer {
    /// Open an offer for `bundle`. Discovery is best effort: when the UDP
    /// port is taken the offer still works through a typed address.
    pub fn start(bundle: Bundle) -> Result<Offer> {
        let code = new_code();
        let digits = normalize(&code)?;
        let listener = TcpListener::bind(("0.0.0.0", 0)).context("cannot open a pairing port")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let addresses = crate::p2p::local_ipv4_addrs()
            .into_iter()
            .map(|ip| format!("{ip}:{port}"))
            .collect();
        let inner = Arc::new(Mutex::new(OfferInner {
            status: OfferStatus {
                open: true,
                code,
                port,
                addresses,
                expires_in_secs: OFFER_TTL.as_secs(),
                failed_attempts: 0,
                paired_with: None,
                closed_reason: None,
            },
            expires: Instant::now() + OFFER_TTL,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        if let Ok(sock) = discovery_socket() {
            let (stop, rv) = (stop.clone(), digits[0..3].to_string());
            std::thread::Builder::new()
                .name("pair-discovery".into())
                .spawn(move || answer_queries(sock, &rv, port, &stop))?;
        }
        {
            let (inner, stop) = (inner.clone(), stop.clone());
            std::thread::Builder::new()
                .name("pair-offer".into())
                .spawn(move || serve(listener, &digits, &bundle, &inner, &stop))?;
        }
        Ok(Offer { inner, stop })
    }

    pub fn status(&self) -> OfferStatus {
        let g = self.inner.lock().unwrap();
        let mut s = g.status.clone();
        s.expires_in_secs = if s.open {
            g.expires
                .saturating_duration_since(Instant::now())
                .as_secs()
        } else {
            0
        };
        s
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let mut g = self.inner.lock().unwrap();
        if g.status.open {
            g.status.open = false;
            g.status.closed_reason = Some("cancelled".into());
        }
    }
}

impl Drop for Offer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

fn discovery_socket() -> Result<UdpSocket> {
    // Shared, so two offers on one machine (the service and a command line)
    // both hear queries sent to the group or the broadcast address.
    use socket2::{Domain, Protocol, Socket, Type};
    let raw = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    raw.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    raw.set_reuse_port(true)?;
    raw.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, PAIR_PORT)).into())?;
    let sock: UdpSocket = raw.into();
    let _ = sock.join_multicast_v4(&PAIR_GROUP, &Ipv4Addr::UNSPECIFIED);
    for ip in crate::p2p::local_ipv4_addrs() {
        if let IpAddr::V4(v4) = ip {
            let _ = sock.join_multicast_v4(&PAIR_GROUP, &v4);
        }
    }
    sock.set_read_timeout(Some(Duration::from_millis(300)))?;
    Ok(sock)
}

fn answer_queries(sock: UdpSocket, rv: &str, port: u16, stop: &AtomicBool) {
    let mut buf = [0u8; 256];
    while !stop.load(Ordering::SeqCst) {
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            continue;
        };
        let msg = String::from_utf8_lossy(&buf[..n]);
        let mut parts = msg.split_whitespace();
        if parts.next() == Some(QUERY) && parts.next() == Some(rv) {
            let _ = sock.send_to(format!("{ANSWER} {rv} {port}").as_bytes(), from);
        }
    }
}

fn serve(
    listener: TcpListener,
    digits: &str,
    bundle: &Bundle,
    inner: &Mutex<OfferInner>,
    stop: &AtomicBool,
) {
    let close = |reason: Option<&str>, paired: Option<String>| {
        let mut g = inner.lock().unwrap();
        g.status.open = false;
        g.status.paired_with = paired;
        g.status.closed_reason = reason.map(str::to_string);
        stop.store(true, Ordering::SeqCst);
    };
    while !stop.load(Ordering::SeqCst) {
        if Instant::now() >= inner.lock().unwrap().expires {
            close(Some("expired"), None);
            return;
        }
        let stream = match listener.accept() {
            Ok((s, _)) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
            Err(_) => continue,
        };
        match offer_exchange(stream, digits, bundle) {
            Ok(name) => {
                close(None, Some(name));
                return;
            }
            Err(Attempt::Wrong) => {
                let failed = {
                    let mut g = inner.lock().unwrap();
                    g.status.failed_attempts += 1;
                    g.status.failed_attempts
                };
                if failed >= MAX_ATTEMPTS {
                    close(Some("too many wrong codes"), None);
                    return;
                }
            }
            // A dropped or malformed connection is not a guess.
            Err(Attempt::Broken) => {}
        }
    }
}

enum Attempt {
    Wrong,
    Broken,
}

fn offer_exchange(stream: TcpStream, digits: &str, bundle: &Bundle) -> Result<String, Attempt> {
    let broken = |_| Attempt::Broken;
    stream.set_nonblocking(false).map_err(broken)?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).map_err(broken)?;
    stream.set_write_timeout(Some(IO_TIMEOUT)).map_err(broken)?;
    let mut w = stream.try_clone().map_err(broken)?;
    let mut r = BufReader::new(stream);
    let hello = read_line(&mut r).map_err(|_| Attempt::Broken)?;
    let name = field(&hello, "name").map_err(|_| Attempt::Broken)?;
    let msg_b = hex::decode(field(&hello, "spake").map_err(|_| Attempt::Broken)?)
        .map_err(|_| Attempt::Broken)?;
    let (ida, idb) = spake_ids();
    let (spake, msg_a) = Spake2::<Ed25519Group>::start_a(&Password::new(digits), &ida, &idb);
    let key = spake
        .finish(&msg_b)
        .ok()
        .and_then(|k| session_key(&k).ok())
        .ok_or(Attempt::Broken)?;
    write_line(
        &mut w,
        &serde_json::json!({"spake": hex::encode(msg_a), "confirm": confirm(&key, "offer")}),
    )
    .map_err(|_| Attempt::Broken)?;
    // Past this point the joining device has made its guess: anything but
    // the right confirmation (a wrong one, an error line, silence) counts.
    let theirs = read_line(&mut r)
        .ok()
        .and_then(|reply| field(&reply, "confirm").ok());
    if theirs.as_deref() != Some(confirm(&key, "join").as_str()) {
        return Err(Attempt::Wrong);
    }
    let plain = serde_json::to_vec(bundle).map_err(|_| Attempt::Broken)?;
    let sealed = crypto::encrypt(
        &key.derive("pair-bundle", &[]),
        b"varsto-pair-bundle",
        &plain,
    )
    .map_err(|_| Attempt::Broken)?;
    write_line(&mut w, &serde_json::json!({"bundle": hex::encode(sealed)}))
        .map_err(|_| Attempt::Broken)?;
    // Wait for the receipt so the offer only closes on a delivered bundle.
    let done = read_line(&mut r).map_err(|_| Attempt::Broken)?;
    if done.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Err(Attempt::Broken);
    }
    Ok(name)
}

// ----- joining device -------------------------------------------------------

/// Find an open offer on the LAN for this code. Returns its TCP addresses.
pub fn discover(code: &str, timeout: Duration) -> Result<Vec<SocketAddr>> {
    let digits = normalize(code)?;
    let rv = &digits[0..3];
    let sock = UdpSocket::bind(("0.0.0.0", 0))?;
    sock.set_broadcast(true)?;
    let _ = sock.set_multicast_loop_v4(true);
    sock.set_read_timeout(Some(Duration::from_millis(300)))?;
    let query = format!("{QUERY} {rv}");
    let mut targets: Vec<SocketAddr> = vec![
        (PAIR_GROUP, PAIR_PORT).into(),
        (Ipv4Addr::BROADCAST, PAIR_PORT).into(),
        (Ipv4Addr::LOCALHOST, PAIR_PORT).into(),
    ];
    // Directed broadcast for each interface, assuming the common /24.
    for ip in crate::p2p::local_ipv4_addrs() {
        if let IpAddr::V4(v4) = ip {
            let o = v4.octets();
            targets.push((Ipv4Addr::new(o[0], o[1], o[2], 255), PAIR_PORT).into());
        }
    }
    let deadline = Instant::now() + timeout;
    let mut found: Vec<SocketAddr> = Vec::new();
    let mut next_send = Instant::now();
    let mut buf = [0u8; 256];
    while Instant::now() < deadline {
        if Instant::now() >= next_send {
            for t in &targets {
                let _ = sock.send_to(query.as_bytes(), t);
            }
            next_send = Instant::now() + Duration::from_millis(700);
        }
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            if !found.is_empty() {
                break;
            }
            continue;
        };
        let msg = String::from_utf8_lossy(&buf[..n]);
        let mut parts = msg.split_whitespace();
        if parts.next() == Some(ANSWER) && parts.next() == Some(rv) {
            if let Some(port) = parts.next().and_then(|p| p.parse::<u16>().ok()) {
                let addr = SocketAddr::new(from.ip(), port);
                if !found.contains(&addr) {
                    found.push(addr);
                }
            }
        }
    }
    if found.is_empty() {
        bail!(
            "no device offering code {} answered on this network; check the code, or type the address shown under it",
            code.trim()
        );
    }
    Ok(found)
}

/// Run the exchange with an offering device and return what it sent.
pub fn fetch(code: &str, my_name: &str, addr: SocketAddr) -> Result<Bundle> {
    let digits = normalize(code)?;
    let stream = TcpStream::connect_timeout(&addr, IO_TIMEOUT)
        .with_context(|| format!("cannot reach {addr}"))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut w = stream.try_clone()?;
    let mut r = BufReader::new(stream);
    let (ida, idb) = spake_ids();
    let (spake, msg_b) = Spake2::<Ed25519Group>::start_b(&Password::new(&digits), &ida, &idb);
    write_line(
        &mut w,
        &serde_json::json!({"v": 1, "name": my_name, "spake": hex::encode(msg_b)}),
    )?;
    let answer = read_line(&mut r)?;
    let msg_a = hex::decode(field(&answer, "spake")?)?;
    let key = session_key(
        &spake
            .finish(&msg_a)
            .map_err(|e| anyhow!("pairing failed: {e}"))?,
    )?;
    if field(&answer, "confirm")? != confirm(&key, "offer") {
        let _ = write_line(&mut w, &serde_json::json!({"error": "wrong code"}));
        bail!("wrong pairing code");
    }
    write_line(
        &mut w,
        &serde_json::json!({"confirm": confirm(&key, "join")}),
    )?;
    let sealed = hex::decode(field(&read_line(&mut r)?, "bundle")?)?;
    let plain = crypto::decrypt(
        &key.derive("pair-bundle", &[]),
        b"varsto-pair-bundle",
        &sealed,
    )?;
    let bundle: Bundle = serde_json::from_slice(&plain)?;
    write_line(&mut w, &serde_json::json!({"ok": true}))?;
    Ok(bundle)
}

/// Discover (unless `address` is given) and fetch.
pub fn receive(code: &str, my_name: &str, address: Option<&str>) -> Result<Bundle> {
    let addrs: Vec<SocketAddr> = match address.map(str::trim).filter(|a| !a.is_empty()) {
        Some(a) => {
            use std::net::ToSocketAddrs;
            a.to_socket_addrs()
                .with_context(|| format!("not an address: {a} (expected host:port)"))?
                .collect()
        }
        None => discover(code, Duration::from_secs(15))?,
    };
    let mut last = None;
    for a in addrs {
        match fetch(code, my_name, a) {
            Ok(b) => return Ok(b),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("no address to try")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> Bundle {
        Bundle {
            vault_id: "v".into(),
            vault_key: "k".repeat(64),
            from: "laptop".into(),
            storages: vec![BundleStorage {
                spec: StorageSpec::LocalDir {
                    name: "primary".into(),
                    path: "/nowhere".into(),
                    cold: false,
                    carrier: false,
                    place: String::new(),
                },
                secret: Some("s3cret".into()),
            }],
        }
    }

    fn addr(o: &Offer) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], o.status().port))
    }

    #[test]
    fn codes_normalize() {
        let c = new_code();
        assert_eq!(normalize(&c).unwrap().len(), 9);
        assert_eq!(normalize(" 123 456-789 ").unwrap(), "123456789");
        assert!(normalize("12345678").is_err());
        assert!(normalize("12345678x").is_err());
    }

    #[test]
    fn right_code_delivers_and_closes_the_offer() {
        let o = Offer::start(bundle()).unwrap();
        let code = o.status().code;
        let b = fetch(&code, "phone", addr(&o)).unwrap();
        assert_eq!(b.from, "laptop");
        assert_eq!(b.storages[0].secret.as_deref(), Some("s3cret"));
        std::thread::sleep(Duration::from_millis(300));
        let s = o.status();
        assert!(!s.open);
        assert_eq!(s.paired_with.as_deref(), Some("phone"));
        // Single use.
        assert!(fetch(&code, "other", addr(&o)).is_err());
    }

    #[test]
    fn wrong_codes_fail_and_burn_the_offer() {
        let o = Offer::start(bundle()).unwrap();
        let code = o.status().code;
        let wrong = if code.starts_with('0') {
            "111-111-111"
        } else {
            "000-000-000"
        };
        for _ in 0..MAX_ATTEMPTS {
            let e = fetch(wrong, "mallory", addr(&o)).err().unwrap();
            assert!(e.to_string().contains("wrong pairing code"), "{e}");
        }
        std::thread::sleep(Duration::from_millis(300));
        let s = o.status();
        assert!(!s.open);
        assert_eq!(s.failed_attempts, MAX_ATTEMPTS);
        assert!(fetch(&code, "phone", addr(&o)).is_err());
    }

    #[test]
    fn discovery_finds_the_offer_on_this_host() {
        let o = Offer::start(bundle()).unwrap();
        let code = o.status().code;
        let found = discover(&code, Duration::from_secs(5)).unwrap();
        assert!(
            found.iter().any(|a| a.port() == o.status().port),
            "{found:?}"
        );
        let b = receive(&code, "phone", None).unwrap();
        assert_eq!(b.from, "laptop");
    }
}
