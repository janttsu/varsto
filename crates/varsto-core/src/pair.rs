// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Pairing: add a device to a vault from the interface with a one-time code.
//!
//! The device that already holds the vault opens an offer and shows a code of
//! nine digits. The new device finds it on the LAN (a query to the multicast
//! group and the broadcast address, answered by unicast) or at an address the
//! user types, and the two run SPAKE2 keyed by the code. A wrong code yields a
//! different key, so each connection is one online guess and nothing a
//! listener records can be checked against guesses offline. The exchange is
//! that of storage format 3 (`v3`): the joining device's hello carries its
//! K6 and K8 public keys and name, bound into both key confirmations; the
//! offering device shows the name and the six-word fingerprint of the keys,
//! asks its person, writes the grants of the folders they ticked, and only
//! then sends its storage settings, secrets included, sealed under the
//! shared key, with the vault key sealed to the joiner's K8 inside. An offer
//! serves one device, lasts ten minutes and closes after three failed
//! attempts.
//!
//! Discovery matches on a 10-bit tag derived from the code
//! (`v3::rendezvous`); it only tells concurrent offers apart. The password is
//! all nine digits.

use crate::crypto::{self, SecretKey};
use crate::storage::StorageSpec;
use anyhow::{anyhow, bail, Context, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use spake2::Identity;
use std::io::{BufRead, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
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
/// How long one address gets to accept the connection before the next is tried.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// How long the search of the local network runs when no address worked.
pub const DISCOVER_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_LINE: u64 = 1 << 20;
const QUERY: &str = "VARSTO-PAIR?";
const ANSWER: &str = "VARSTO-PAIR!";

/// What a new device receives: everything it needs to join. Pairing sends
/// it with `vault_key` empty (the vault key travels sealed to the joiner's
/// K8, `v3`); the joining side puts the opened key back in.
#[derive(Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub vault_id: String,
    pub vault_key: String,
    /// Name of the device that sent it.
    pub from: String,
    pub storages: Vec<BundleStorage>,
    /// Every vault key epoch the sending device holds, so that a joining
    /// device can be set up without reaching a storage (the rest of
    /// joining is finished when one can be reached). Like `vault_key` it is
    /// empty on the wire (`v3` seals each key to the joiner's K8 and the
    /// joining side puts the opened keys back in). `None`: the sender does
    /// not offer an offline join (an organization's approval).
    #[serde(default)]
    pub vault_epochs: Option<Vec<BundleEpoch>>,
}

crate::redacted_debug!(Bundle { vault_id, from, storages ; vault_key, vault_epochs });

impl Drop for Bundle {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.vault_key.zeroize();
    }
}

/// The vault key K3 of one epoch, hex.
#[derive(Clone, Serialize, Deserialize)]
pub struct BundleEpoch {
    pub epoch: u32,
    pub key: String,
}

crate::redacted_debug!(BundleEpoch { epoch ; key });

impl Drop for BundleEpoch {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BundleStorage {
    pub spec: StorageSpec,
    /// The S3 secret access key, when the storage needs one.
    #[serde(default)]
    pub secret: Option<String>,
}

crate::redacted_debug!(BundleStorage { spec ; secret });

impl Drop for BundleStorage {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(s) = self.secret.as_mut() {
            s.zeroize();
        }
    }
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
    /// The offer is registered at the rendezvous service and its control
    /// connection is up: it works across networks (section 83.9).
    pub rendezvous: bool,
    /// The token of the link's `rv=` parameter (hex), while the offer uses
    /// the rendezvous.
    pub rendezvous_token: Option<String>,
    /// The rendezvous base URL the offer is registered at, when it is not
    /// the default service: the link's `rvu=` parameter (section 51).
    pub rendezvous_url: Option<String>,
}

impl OfferStatus {
    /// The pairing link of this offer (code, addresses, `rv=` token).
    pub fn link(&self) -> crate::qr::Link {
        crate::qr::Link::Pair {
            code: self.code.clone(),
            addresses: self.addresses.clone(),
            rendezvous: self
                .rendezvous_token
                .as_deref()
                .and_then(crate::rendezvous::keys::parse_token),
            rendezvous_url: self
                .rendezvous_token
                .as_ref()
                .and(self.rendezvous_url.clone()),
        }
    }
}

/// A pairing connection: TCP from the LAN, or a session relayed by the
/// rendezvous service (section 83.7). The exchange is the same on both.
pub trait PairStream: Read + Write + Send {
    /// Read and write timeouts of the stream.
    fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> std::io::Result<()>;
}

impl PairStream for TcpStream {
    fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> std::io::Result<()> {
        self.set_nonblocking(false)?;
        self.set_read_timeout(read)?;
        self.set_write_timeout(write)
    }
}

impl PairStream for crate::rendezvous::RelayStream {
    fn set_timeouts(
        &self,
        read: Option<Duration>,
        _write: Option<Duration>,
    ) -> std::io::Result<()> {
        self.set_read_timeout(read)
    }
}

/// The `rvu=` value of a pairing link for an offer registered at `url`:
/// `None` for the default service (a link stays as short as it can be and
/// readable by every client), the URL without a trailing slash otherwise.
pub fn url_for_link(url: Option<&str>) -> Option<String> {
    let u = url?.trim().trim_end_matches('/');
    let default = crate::rendezvous::proto::DEFAULT_URL.trim_end_matches('/');
    (!u.eq_ignore_ascii_case(default)).then(|| u.to_string())
}

/// The exchange an offer runs on each connection.
type Exchange = dyn Fn(Box<dyn PairStream>, &str) -> Result<String, Attempt> + Send;

struct OfferInner {
    status: OfferStatus,
    expires: Instant,
}

pub struct Offer {
    inner: Arc<Mutex<OfferInner>>,
    stop: Arc<AtomicBool>,
}

impl Offer {
    /// An offer whose discovery answers to `rendezvous(digits)` and whose
    /// connections run `exchange` (`Offer::start_v3`). Discovery is best
    /// effort: when the UDP port is taken the offer still works through a
    /// typed address. With `rv` (a rendezvous base URL) the offer is also
    /// registered there in the background (section 83.9) and a joiner
    /// elsewhere reaches it through the relay; nothing waits for it.
    fn start_with(
        rendezvous: &dyn Fn(&str) -> String,
        rv: Option<&str>,
        exchange: impl Fn(Box<dyn PairStream>, &str) -> Result<String, Attempt> + Send + 'static,
    ) -> Result<Offer> {
        let code = new_code();
        let digits = normalize(&code)?;
        let listener = TcpListener::bind(("0.0.0.0", 0)).context("cannot open a pairing port")?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        // Every usable interface address, the one most likely reachable
        // first (spec section 68); the interface shows the first and the
        // pairing link carries them all.
        let addresses: Vec<String> = crate::netif::candidates()
            .into_iter()
            .map(|c| format!("{}:{port}", c.ip))
            .collect();
        let rv_url_given = rv;
        let rv = rv.and_then(|url| match crate::rendezvous::RvClient::new(url) {
            Ok(c) => Some(c),
            Err(e) => {
                log::warn!("pairing: rendezvous {url} not used: {e:#}");
                None
            }
        });
        let token = rv
            .as_ref()
            .map(|_| crate::rendezvous::proto::random_token());
        // A joiner asks the default service unless the link names another.
        let rv_url = url_for_link(rv_url_given);
        let inner = Arc::new(Mutex::new(OfferInner {
            status: OfferStatus {
                open: true,
                code,
                port,
                addresses: addresses.clone(),
                expires_in_secs: OFFER_TTL.as_secs(),
                failed_attempts: 0,
                paired_with: None,
                closed_reason: None,
                rendezvous: false,
                rendezvous_token: token.map(hex::encode),
                rendezvous_url: rv_url.filter(|_| token.is_some()),
            },
            expires: Instant::now() + OFFER_TTL,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        if let Ok(sock) = discovery_socket() {
            let (stop, rv) = (stop.clone(), rendezvous(&digits));
            std::thread::Builder::new()
                .name("pair-discovery".into())
                .spawn(move || answer_queries(sock, &rv, port, &stop))?;
        }
        let (relayed_tx, relayed_rx) = std::sync::mpsc::channel();
        if let (Some(rv), Some(token)) = (rv, token) {
            let (inner, stop, digits) = (inner.clone(), stop.clone(), digits.clone());
            std::thread::Builder::new()
                .name("pair-rendezvous".into())
                .spawn(move || {
                    rendezvous_offer(&rv, &digits, token, addresses, &inner, &stop, relayed_tx)
                })?;
        }
        {
            let (inner, stop) = (inner.clone(), stop.clone());
            std::thread::Builder::new()
                .name("pair-offer".into())
                .spawn(move || serve(listener, relayed_rx, &digits, &exchange, &inner, &stop))?;
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
    for f in crate::netif::interfaces() {
        if f.up && !f.loopback {
            let _ = sock.join_multicast_v4(&PAIR_GROUP, &f.ip);
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
    relayed: std::sync::mpsc::Receiver<crate::rendezvous::RelayStream>,
    digits: &str,
    exchange: &Exchange,
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
        // A joiner on the LAN, or one elsewhere through the rendezvous relay.
        let stream: Box<dyn PairStream> = match listener.accept() {
            Ok((s, _)) => Box::new(s),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => match relayed.try_recv() {
                Ok(s) => Box::new(s),
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
            },
            Err(_) => continue,
        };
        match exchange(stream, digits) {
            Ok(name) => {
                close(None, Some(name));
                return;
            }
            Err(Attempt::Declined(name)) => {
                close(Some(&format!("declined {name}")), None);
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

/// Keep an offer at the rendezvous service while it is open (section
/// 83.9): register it under the link token and the code's tag (sealed
/// addresses, an ephemeral owner key), hold a control connection with both
/// claimed so a joiner elsewhere can ask for a relay, hand every relayed
/// session to the offer's loop, and withdraw it when the offer closes. A
/// code tag another offer holds is skipped (the link token still works).
/// Every failure is logged; the LAN side of the offer never waits for this.
fn rendezvous_offer(
    rv: &crate::rendezvous::RvClient,
    digits: &str,
    token: crate::rendezvous::Token,
    addresses: Vec<String>,
    inner: &Mutex<OfferInner>,
    stop: &AtomicBool,
    relayed: std::sync::mpsc::Sender<crate::rendezvous::RelayStream>,
) {
    use crate::rendezvous::{keys, now, proto, Control, RelayStream};
    let log = |what: &str| log::info!("pairing: rendezvous {what}");
    let owner = keys::ephemeral_owner();
    let expires = now() + OFFER_TTL.as_secs();
    let mut addrs = addresses;
    addrs.truncate(proto::MAX_OFFER_ADDRS);
    let offer = proto::PairOffer {
        v: proto::VERSION,
        addrs,
        expires,
        relay: true,
    };
    // The token tag first: it is random and never taken.
    let mut tags = Vec::new();
    for (what, k) in [
        ("link token", keys::pair_token_keys(&token, digits)),
        ("code", keys::pair_code_keys(digits)),
    ] {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        let k = match k {
            Ok(k) => k,
            Err(e) => {
                log(&format!("{what}: {e:#}"));
                continue;
            }
        };
        let put = match k.seal(&offer) {
            Ok(blob) => proto::PutSlot::sign(
                proto::Kind::Pair,
                k.tag,
                proto::PAIR_SLOT,
                &owner,
                now(),
                OFFER_TTL.as_secs() as u32,
                blob,
            ),
            Err(e) => {
                log(&format!("{what}: {e:#}"));
                continue;
            }
        };
        match rv.put(&put) {
            Ok(_) => tags.push(k.tag),
            Err(e) => log(&format!("offer not registered by {what}: {e}")),
        }
    }
    if tags.is_empty() {
        return;
    }
    let withdraw = |tags: &[crate::rendezvous::Tag]| {
        for t in tags {
            let d = proto::DeleteSlot::sign(*t, proto::PAIR_SLOT, &owner, now());
            if let Err(e) = rv.delete(&d) {
                log::debug!("pairing: rendezvous offer not withdrawn: {e}");
            }
        }
    };
    let set_on = |on: bool| inner.lock().unwrap().status.rendezvous = on;
    let mut wait = Duration::from_secs(5);
    while !stop.load(Ordering::SeqCst) && now() < expires {
        let run = || -> Result<()> {
            let mut c = Control::open(rv.base())?;
            let claims = tags
                .iter()
                .map(|t| c.claim(*t, proto::PAIR_SLOT, &owner))
                .collect();
            let w = c.hello(claims, Duration::from_secs(5))?;
            if w.claimed.is_empty() {
                bail!("the rendezvous took no claim of the offer");
            }
            set_on(true);
            log("offer registered; it works across networks");
            let mut last_ping = Instant::now();
            while !stop.load(Ordering::SeqCst) && now() < expires {
                if last_ping.elapsed() >= Duration::from_secs(25) {
                    last_ping = Instant::now();
                    c.send(&proto::ToServer::Ping { id: 1 })?;
                }
                if let Some(proto::ToClient::RelayOffer { token, tag, .. }) =
                    c.recv(Duration::from_millis(300))?
                {
                    if !tags.contains(&tag.0) {
                        continue;
                    }
                    match RelayStream::open(rv.base(), &token.0) {
                        Ok(s) => {
                            log("a device asks through the relay");
                            let _ = relayed.send(s);
                        }
                        Err(e) => log(&format!("relay not taken: {e:#}")),
                    }
                }
            }
            c.close();
            Ok(())
        };
        if let Err(e) = run() {
            set_on(false);
            log(&format!("control connection: {e:#}"));
            let until = Instant::now() + wait;
            while Instant::now() < until && !stop.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(200));
            }
            wait = (wait * 2).min(Duration::from_secs(60));
        }
    }
    set_on(false);
    withdraw(&tags);
}

enum Attempt {
    Wrong,
    Broken,
    /// The person at the offering device said no to this device.
    Declined(String),
}

// ----- joining device -------------------------------------------------------

/// Find an open offer on the LAN for this code. Returns its TCP addresses.
/// The query goes out of every usable interface (multicast and the subnet's
/// directed broadcast), not only the one the OS prefers: with a VPN on the
/// default route the Wi-Fi would otherwise never hear it.
pub fn discover(code: &str, timeout: Duration) -> Result<Vec<SocketAddr>> {
    v3::discover(code, timeout)
}

/// `discover` for the rendezvous id `rv`.
fn discover_rv(code: &str, rv: &str, timeout: Duration) -> Result<Vec<SocketAddr>> {
    let query = format!("{QUERY} {rv}");
    // One socket per interface (bound to its address, so the packet leaves
    // there) and one unbound, for the default route and the loopback.
    let mut socks: Vec<(UdpSocket, Vec<SocketAddr>)> = Vec::new();
    let open = |bind: Ipv4Addr| -> Result<UdpSocket> {
        use socket2::{Domain, Protocol, Socket, Type};
        let raw = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        raw.bind(&SocketAddr::from((bind, 0)).into())?;
        raw.set_broadcast(true)?;
        let _ = raw.set_multicast_loop_v4(true);
        if !bind.is_unspecified() {
            let _ = raw.set_multicast_if_v4(&bind);
        }
        let sock: UdpSocket = raw.into();
        sock.set_nonblocking(true)?;
        Ok(sock)
    };
    if let Ok(sock) = open(Ipv4Addr::UNSPECIFIED) {
        socks.push((
            sock,
            vec![
                (PAIR_GROUP, PAIR_PORT).into(),
                (Ipv4Addr::BROADCAST, PAIR_PORT).into(),
                (Ipv4Addr::LOCALHOST, PAIR_PORT).into(),
            ],
        ));
    }
    for c in crate::netif::candidates() {
        if let Ok(sock) = open(c.ip) {
            socks.push((
                sock,
                vec![
                    (PAIR_GROUP, PAIR_PORT).into(),
                    (Ipv4Addr::BROADCAST, PAIR_PORT).into(),
                    (crate::netif::broadcast_of(&c), PAIR_PORT).into(),
                ],
            ));
        }
    }
    if socks.is_empty() {
        bail!("cannot open a socket to look for the other device");
    }
    let deadline = Instant::now() + timeout;
    let mut found: Vec<SocketAddr> = Vec::new();
    let mut next_send = Instant::now();
    let mut buf = [0u8; 256];
    while Instant::now() < deadline {
        if Instant::now() >= next_send {
            for (sock, targets) in &socks {
                for t in targets {
                    let _ = sock.send_to(query.as_bytes(), t);
                }
            }
            next_send = Instant::now() + Duration::from_millis(700);
        }
        let mut heard = false;
        for (sock, _) in &socks {
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                heard = true;
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
        }
        if !found.is_empty() {
            // Give the other answers of the same round a moment, then go.
            std::thread::sleep(Duration::from_millis(150));
            break;
        }
        if !heard {
            std::thread::sleep(Duration::from_millis(50));
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

/// The offering device answered and the code did not match. Retrying with
/// other addresses would only burn the offer's three attempts.
#[derive(Debug)]
pub struct WrongCode;

impl std::fmt::Display for WrongCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("wrong pairing code")
    }
}

impl std::error::Error for WrongCode {}

/// One address that was tried, and how it failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Tried {
    pub what: String,
    /// `no answer`, `refused`, `unreachable`, `connection closed` or `not an address`.
    pub why: String,
}

/// Nothing worked: what was tried, for the message the user reads.
#[derive(Debug)]
pub struct NotFound {
    pub tried: Vec<Tried>,
    /// How many offers the search of the local network found.
    pub found: usize,
}

impl std::fmt::Display for NotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Could not reach the device showing the code.")?;
        if !self.tried.is_empty() {
            let list: Vec<String> = self
                .tried
                .iter()
                .map(|t| format!("{} ({})", t.what, t.why))
                .collect();
            write!(f, " Tried {}.", list.join(", "))?;
        }
        if self.found == 0 {
            write!(f, " Looked for it on the network: nothing answered.")?;
        }
        write!(
            f,
            " Check that both devices are on the same Wi-Fi network, that the router does not isolate wireless clients (guest network, client isolation) and that no VPN or firewall is in the way."
        )
    }
}

impl std::error::Error for NotFound {}

/// What the joining device is doing, for the progress line of the interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Connecting to this address.
    Trying(SocketAddr),
    /// No address worked (or none was given): searching the local network.
    Looking,
    /// Nothing on this network: looking the offer up at the rendezvous
    /// service (section 83.9).
    Rendezvous,
    /// The offer's addresses did not answer: pairing through the
    /// rendezvous relay.
    RendezvousRelay,
}

/// An offer the rendezvous service holds for a code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RvFound {
    /// The tag it was found under (the link token's or the code's).
    pub tag: crate::rendezvous::Tag,
    pub offer: crate::rendezvous::PairOffer,
}

/// The network side of joining, so that the order of attempts can be tested.
pub trait Connector {
    /// The bundle with the opened vault key in `vault_key`.
    fn fetch(&self, code: &str, keys: &v3::JoinKeys<'_>, addr: SocketAddr) -> Result<Bundle>;
    fn discover(&self, code: &str, timeout: Duration) -> Result<Vec<SocketAddr>>;
    fn own_interfaces(&self) -> Vec<crate::netif::Iface>;
    /// Whether a rendezvous service is to be asked at all.
    fn has_rendezvous(&self) -> bool {
        false
    }
    /// Look the offer up at the rendezvous: by the link's token first, then
    /// by the code. `Ok(None)`: it holds no offer for them.
    fn rendezvous(
        &self,
        _code: &str,
        _token: Option<&crate::rendezvous::Token>,
    ) -> Result<Option<RvFound>> {
        Ok(None)
    }
    /// Run the exchange through the rendezvous relay with the offer found
    /// under `found.tag`.
    fn fetch_relayed(
        &self,
        _code: &str,
        _keys: &v3::JoinKeys<'_>,
        _found: &RvFound,
    ) -> Result<Bundle> {
        bail!("no rendezvous")
    }
}

/// The real network.
pub struct Lan;

impl Connector for Lan {
    fn fetch(&self, code: &str, keys: &v3::JoinKeys<'_>, addr: SocketAddr) -> Result<Bundle> {
        let (mut bundle, key) = v3::fetch(code, keys, addr)?;
        bundle.vault_key = key.to_hex();
        crate::logging::register_secret(&bundle.vault_key);
        Ok(bundle)
    }
    fn discover(&self, code: &str, timeout: Duration) -> Result<Vec<SocketAddr>> {
        discover(code, timeout)
    }
    fn own_interfaces(&self) -> Vec<crate::netif::Iface> {
        crate::netif::interfaces()
    }
}

/// The real network with a rendezvous service (section 83.9): the LAN as
/// [`Lan`], then the offer looked up at the service and its relay.
pub struct Net {
    pub rendezvous: Option<Arc<crate::rendezvous::RvClient>>,
}

impl Net {
    /// The network with the rendezvous at `url` (none: LAN only). A URL
    /// that does not parse is logged and left out.
    pub fn new(url: Option<&str>) -> Net {
        Net {
            rendezvous: url.and_then(|u| match crate::rendezvous::RvClient::new(u) {
                Ok(c) => Some(c),
                Err(e) => {
                    log::warn!("pairing: rendezvous {u} not used: {e:#}");
                    None
                }
            }),
        }
    }
}

impl Connector for Net {
    fn fetch(&self, code: &str, keys: &v3::JoinKeys<'_>, addr: SocketAddr) -> Result<Bundle> {
        Lan.fetch(code, keys, addr)
    }
    fn discover(&self, code: &str, timeout: Duration) -> Result<Vec<SocketAddr>> {
        Lan.discover(code, timeout)
    }
    fn own_interfaces(&self) -> Vec<crate::netif::Iface> {
        Lan.own_interfaces()
    }
    fn has_rendezvous(&self) -> bool {
        self.rendezvous.is_some()
    }
    fn rendezvous(
        &self,
        code: &str,
        token: Option<&crate::rendezvous::Token>,
    ) -> Result<Option<RvFound>> {
        let Some(rv) = &self.rendezvous else {
            return Ok(None);
        };
        let digits = normalize(code)?;
        Ok(crate::rendezvous::find_pair_offer(rv, &digits, token)?
            .map(|(k, offer)| RvFound { tag: k.tag, offer }))
    }
    fn fetch_relayed(
        &self,
        code: &str,
        keys: &v3::JoinKeys<'_>,
        found: &RvFound,
    ) -> Result<Bundle> {
        use crate::rendezvous::{proto, Control, RelayStream};
        let rv = self
            .rendezvous
            .as_ref()
            .ok_or_else(|| anyhow!("no rendezvous"))?;
        let mut c = Control::open(rv.base())?;
        c.hello(Vec::new(), Duration::from_secs(5))?;
        c.send(&proto::ToServer::Relay {
            id: 1,
            tag: proto::Hex(found.tag),
            slot: proto::Hex(proto::PAIR_SLOT),
        })?;
        let until = Instant::now() + Duration::from_secs(5);
        let token = loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                bail!("the rendezvous did not answer the relay request");
            }
            match c.recv(left)? {
                Some(proto::ToClient::RelayReady { token, .. }) => break token.0,
                Some(proto::ToClient::Error { error, .. }) => {
                    bail!("the rendezvous refused the relay: {error}")
                }
                _ => {}
            }
        };
        let stream = RelayStream::open(rv.base(), &token)?;
        c.close();
        let (mut bundle, key) = v3::fetch_over(code, keys, Box::new(stream))?;
        bundle.vault_key = key.to_hex();
        crate::logging::register_secret(&bundle.vault_key);
        Ok(bundle)
    }
}

fn why(e: &anyhow::Error) -> &'static str {
    match e
        .root_cause()
        .downcast_ref::<std::io::Error>()
        .map(|e| e.kind())
    {
        Some(std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock) => "no answer",
        Some(std::io::ErrorKind::ConnectionRefused) => "refused",
        Some(std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset) => {
            "connection closed"
        }
        Some(_) => "unreachable",
        None => "connection closed",
    }
}

/// Longest a typed host name may take to resolve.
const RESOLVE_WITHIN: Duration = Duration::from_secs(5);

/// `host:port` (or an address) as socket addresses, giving up after
/// `limit`: a resolver on a dead network can hold a call for minutes. The
/// lookup runs on its own thread, which is left to finish alone on a timeout.
fn resolve_within(host: &str, limit: Duration) -> Result<Vec<SocketAddr>, String> {
    use std::net::ToSocketAddrs;
    let (tx, rx) = std::sync::mpsc::channel();
    let owned = host.to_string();
    std::thread::spawn(move || {
        let _ = tx.send(
            owned
                .to_socket_addrs()
                .map(|it| it.collect::<Vec<_>>())
                .map_err(|_| "not an address".to_string()),
        );
    });
    match rx.recv_timeout(limit) {
        Ok(r) => r,
        Err(_) => Err(format!(
            "the name did not resolve within {} s",
            limit.as_secs()
        )),
    }
}

/// Join: the typed address first (when given), then the addresses of the
/// pairing link (those on a subnet this device is on first), then the other
/// device is looked for on the local network by its code. Each attempt has a
/// short timeout; `progress` is told before each. A wrong code, or the
/// person at the other device saying no, ends it at once. When nothing
/// works the error is a [`NotFound`] naming every attempt.
pub fn join(
    code: &str,
    keys: &v3::JoinKeys<'_>,
    typed: Option<&str>,
    offered: &[String],
    progress: &mut dyn FnMut(Step),
    net: &dyn Connector,
) -> Result<Bundle> {
    join_with(code, keys, typed, offered, None, progress, net)
}

/// `join`, and when the network has a rendezvous service and nothing on
/// this network answered: the offer looked up there (by the link's
/// `token` first, then by the code), its addresses tried, and last the
/// exchange through the rendezvous relay (section 83.9).
pub fn join_with(
    code: &str,
    keys: &v3::JoinKeys<'_>,
    typed: Option<&str>,
    offered: &[String],
    token: Option<&crate::rendezvous::Token>,
    progress: &mut dyn FnMut(Step),
    net: &dyn Connector,
) -> Result<Bundle> {
    normalize(code)?;
    let mut tried: Vec<Tried> = Vec::new();
    let mut seen: Vec<SocketAddr> = Vec::new();
    let mut first: Vec<SocketAddr> = Vec::new();
    if let Some(t) = typed.map(str::trim).filter(|t| !t.is_empty()) {
        match resolve_within(t, RESOLVE_WITHIN) {
            Ok(addrs) => first.extend(addrs),
            Err(why) => tried.push(Tried {
                what: t.to_string(),
                why,
            }),
        }
    }
    let mut linked: Vec<SocketAddr> = offered.iter().filter_map(|a| a.parse().ok()).collect();
    crate::netif::sort_by_reach(&mut linked, &net.own_interfaces());
    // Tries one address; Ok(Some) is the bundle, Err a wrong code.
    let mut attempt = |a: SocketAddr, progress: &mut dyn FnMut(Step)| -> Result<Option<Bundle>> {
        if seen.contains(&a) {
            return Ok(None);
        }
        seen.push(a);
        progress(Step::Trying(a));
        match net.fetch(code, keys, a) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.downcast_ref::<WrongCode>().is_some() => Err(e),
            Err(e) if e.downcast_ref::<v3::Declined>().is_some() => Err(e),
            Err(e) => {
                tried.push(Tried {
                    what: a.to_string(),
                    why: why(&e).into(),
                });
                Ok(None)
            }
        }
    };
    for a in first.into_iter().chain(linked) {
        if let Some(b) = attempt(a, progress)? {
            return Ok(b);
        }
    }
    progress(Step::Looking);
    let mut found = 0;
    if let Ok(mut addrs) = net.discover(code, DISCOVER_TIMEOUT) {
        crate::netif::sort_by_reach(&mut addrs, &net.own_interfaces());
        found = addrs.len();
        for a in addrs {
            if let Some(b) = attempt(a, progress)? {
                return Ok(b);
            }
        }
    }
    if net.has_rendezvous() {
        progress(Step::Rendezvous);
        match net.rendezvous(code, token) {
            Ok(Some(rv)) => {
                found += 1;
                let mut addrs: Vec<SocketAddr> = rv
                    .offer
                    .addrs
                    .iter()
                    .filter_map(|a| a.parse().ok())
                    .collect();
                crate::netif::sort_by_reach(&mut addrs, &net.own_interfaces());
                for a in addrs {
                    if let Some(b) = attempt(a, progress)? {
                        return Ok(b);
                    }
                }
                if rv.offer.relay {
                    progress(Step::RendezvousRelay);
                    match net.fetch_relayed(code, keys, &rv) {
                        Ok(b) => return Ok(b),
                        Err(e) if e.downcast_ref::<WrongCode>().is_some() => return Err(e),
                        Err(e) if e.downcast_ref::<v3::Declined>().is_some() => return Err(e),
                        Err(e) => {
                            log::info!("pairing: rendezvous relay failed: {e:#}");
                            tried.push(Tried {
                                what: "the rendezvous relay".into(),
                                why: why(&e).into(),
                            });
                        }
                    }
                }
            }
            Ok(None) => tried.push(Tried {
                what: "the rendezvous service".into(),
                why: "no offer for this code".into(),
            }),
            Err(e) => {
                log::info!("pairing: rendezvous lookup failed: {e:#}");
                tried.push(Tried {
                    what: "the rendezvous service".into(),
                    why: "not reached".into(),
                });
            }
        }
    }
    Err(NotFound { tried, found }.into())
}

/// Join with the address the user typed (if any) and the addresses of a
/// pairing link, reporting each step. The bundle carries the opened vault
/// key in `vault_key`.
pub fn receive_with_progress(
    code: &str,
    keys: &v3::JoinKeys<'_>,
    address: Option<&str>,
    offered: &[String],
    progress: &mut dyn FnMut(Step),
) -> Result<Bundle> {
    join(code, keys, address, offered, progress, &Lan)
}

/// `receive_with_progress` with the rendezvous service at `rendezvous`
/// (`rendezvous::for_joining`; `None`: LAN only) and the link's `rv=`
/// token, if the joiner has the link.
pub fn receive_with_rendezvous(
    code: &str,
    keys: &v3::JoinKeys<'_>,
    address: Option<&str>,
    offered: &[String],
    rendezvous: Option<&str>,
    token: Option<&crate::rendezvous::Token>,
    progress: &mut dyn FnMut(Step),
) -> Result<Bundle> {
    join_with(
        code,
        keys,
        address,
        offered,
        token,
        progress,
        &Net::new(rendezvous),
    )
}

/// Join: the typed address if any, then the search of the network.
pub fn receive(code: &str, keys: &v3::JoinKeys<'_>, address: Option<&str>) -> Result<Bundle> {
    receive_with_progress(code, keys, address, &[], &mut |_| {})
}

pub mod v3;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_typed_address_resolves_within_a_limit() {
        let a = resolve_within("127.0.0.1:4242", Duration::from_secs(5)).unwrap();
        assert_eq!(a, vec!["127.0.0.1:4242".parse::<SocketAddr>().unwrap()]);
        // No port: not an address, answered at once.
        assert!(resolve_within("not an address", Duration::from_secs(5)).is_err());
    }

    pub(super) fn bundle() -> Bundle {
        Bundle {
            vault_id: "v".into(),
            vault_key: "k".repeat(64),
            from: "laptop".into(),
            vault_epochs: None,
            storages: vec![BundleStorage {
                spec: StorageSpec::LocalDir {
                    name: "primary".into(),
                    path: "/nowhere".into(),
                    cold: false,
                    carrier: false,
                    place: String::new(),
                    min_free: None,
                },
                secret: Some("s3cret".into()),
            }],
        }
    }

    fn addr(o: &Offer) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], o.status().port))
    }

    /// Every offer binds the discovery port (UDP `PAIR_PORT`, shared with
    /// SO_REUSEPORT, which hands each unicast query to one of the sockets
    /// by the sender's address): an offer of a test running alongside
    /// would get the queries meant for another and ignore them. The tests
    /// that start an offer here and in `v3` take turns.
    pub(super) fn port_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// An offer whose person lets every device join.
    fn open_offer() -> Offer {
        Offer::start_v3(
            bundle(),
            SecretKey::random(),
            std::sync::Arc::new(|_: &v3::Joiner| true),
        )
        .unwrap()
    }

    /// A joining device called `name` with fresh keys.
    fn fetch(code: &str, name: &str, addr: SocketAddr) -> Result<Bundle> {
        let keys = v3::PairingKeys::generate();
        Lan.fetch(code, &keys.join_keys(name), addr)
    }

    #[test]
    fn bundle_debug_hides_the_vault_key_and_storage_secret() {
        let b = bundle();
        let shown = format!("{b:?}");
        assert!(
            shown.contains("laptop") && shown.contains("primary"),
            "{shown}"
        );
        assert!(!shown.contains(&"k".repeat(64)), "{shown}");
        assert!(!shown.contains("s3cret"), "{shown}");
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
        let _port = port_lock();
        let o = open_offer();
        let code = o.status().code;
        let b = fetch(&code, "phone", addr(&o)).unwrap();
        assert_eq!(b.from, "laptop");
        // The vault key arrived sealed to this device's K8 and is opened.
        assert_eq!(b.vault_key.len(), 64);
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
        let _port = port_lock();
        let o = open_offer();
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
        let _port = port_lock();
        let o = open_offer();
        let code = o.status().code;
        let found = discover(&code, Duration::from_secs(5)).unwrap();
        assert!(
            found.iter().any(|a| a.port() == o.status().port),
            "{found:?}"
        );
        let keys = v3::PairingKeys::generate();
        let b = receive(&code, &keys.join_keys("phone"), None).unwrap();
        assert_eq!(b.from, "laptop");
    }

    /// A network where chosen addresses answer, with a log of what was tried.
    struct FakeNet {
        /// The address that answers with a bundle.
        good: Option<SocketAddr>,
        /// An address that answers but with the wrong code.
        wrong: Option<SocketAddr>,
        /// An address whose person says no.
        declined: Option<SocketAddr>,
        /// What the search of the network finds.
        found: Vec<SocketAddr>,
        own: Vec<crate::netif::Iface>,
        log: std::sync::Mutex<Vec<String>>,
    }

    impl FakeNet {
        fn new() -> FakeNet {
            FakeNet {
                good: None,
                wrong: None,
                declined: None,
                found: Vec::new(),
                own: vec![crate::netif::Iface {
                    name: "en0".into(),
                    ip: Ipv4Addr::new(192, 168, 1, 40),
                    prefix: 24,
                    up: true,
                    loopback: false,
                }],
                log: Default::default(),
            }
        }
        fn log(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }

    impl Connector for FakeNet {
        fn fetch(&self, _code: &str, _keys: &v3::JoinKeys<'_>, addr: SocketAddr) -> Result<Bundle> {
            self.log.lock().unwrap().push(format!("fetch {addr}"));
            if Some(addr) == self.declined {
                return Err(v3::Declined.into());
            }
            if Some(addr) == self.wrong {
                return Err(WrongCode.into());
            }
            if Some(addr) == self.good {
                return Ok(bundle());
            }
            Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
                .with_context(|| format!("cannot reach {addr}"))
        }
        fn discover(&self, _code: &str, _t: Duration) -> Result<Vec<SocketAddr>> {
            self.log.lock().unwrap().push("discover".into());
            if self.found.is_empty() {
                bail!("nobody answered");
            }
            Ok(self.found.clone())
        }
        fn own_interfaces(&self) -> Vec<crate::netif::Iface> {
            self.own.clone()
        }
    }

    /// `FakeNet` with a rendezvous that holds `found` and whose relay
    /// works when `relay_ok`.
    struct RvNet {
        lan: FakeNet,
        found: Option<RvFound>,
        relay_ok: bool,
    }

    impl Connector for RvNet {
        fn fetch(&self, code: &str, keys: &v3::JoinKeys<'_>, addr: SocketAddr) -> Result<Bundle> {
            self.lan.fetch(code, keys, addr)
        }
        fn discover(&self, code: &str, t: Duration) -> Result<Vec<SocketAddr>> {
            self.lan.discover(code, t)
        }
        fn own_interfaces(&self) -> Vec<crate::netif::Iface> {
            self.lan.own_interfaces()
        }
        fn has_rendezvous(&self) -> bool {
            true
        }
        fn rendezvous(
            &self,
            _code: &str,
            token: Option<&crate::rendezvous::Token>,
        ) -> Result<Option<RvFound>> {
            self.lan
                .log
                .lock()
                .unwrap()
                .push(format!("rendezvous token={}", token.is_some()));
            Ok(self.found.clone())
        }
        fn fetch_relayed(&self, _c: &str, _k: &v3::JoinKeys<'_>, _f: &RvFound) -> Result<Bundle> {
            self.lan.log.lock().unwrap().push("relay".into());
            if self.relay_ok {
                Ok(bundle())
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset).into())
            }
        }
    }

    #[test]
    fn the_rendezvous_comes_after_the_lan_its_addresses_before_its_relay() {
        let offer = |addrs: &[&str], relay: bool| RvFound {
            tag: [1; 16],
            offer: crate::rendezvous::PairOffer {
                v: 1,
                addrs: addrs.iter().map(|s| s.to_string()).collect(),
                expires: u64::MAX,
                relay,
            },
        };
        let keys = v3::PairingKeys::generate();
        let go = |net: &RvNet, token: Option<&crate::rendezvous::Token>| {
            let mut steps = Vec::new();
            let r = join_with(
                "123-456-789",
                &keys.join_keys("phone"),
                Some("10.8.0.2:4000"),
                &[],
                token,
                &mut |s| steps.push(s),
                net,
            );
            (r, steps)
        };
        // The offer's own address answers (a public one, as with a port
        // forwarded): no relay.
        let mut lan = FakeNet::new();
        lan.good = Some(sa("203.0.113.9:4000"));
        let net = RvNet {
            lan,
            found: Some(offer(&["10.8.0.2:4000", "203.0.113.9:4000"], true)),
            relay_ok: true,
        };
        let (r, steps) = go(&net, Some(&[7; 16]));
        assert!(r.is_ok());
        assert_eq!(
            net.lan.log(),
            [
                "fetch 10.8.0.2:4000",
                "discover",
                "rendezvous token=true",
                "fetch 203.0.113.9:4000"
            ],
            "typed, LAN search, rendezvous; an address tried already is not tried again"
        );
        assert_eq!(steps[1], Step::Looking);
        assert_eq!(steps[2], Step::Rendezvous);
        // Nothing answers: the relay.
        let net = RvNet {
            lan: FakeNet::new(),
            found: Some(offer(&["203.0.113.9:4000"], true)),
            relay_ok: true,
        };
        let (r, steps) = go(&net, None);
        assert!(r.is_ok());
        assert_eq!(net.lan.log().last().map(String::as_str), Some("relay"));
        assert_eq!(steps.last(), Some(&Step::RendezvousRelay));
        // An offer without a control connection is not asked for a relay;
        // a failed relay and no offer at all are named in the error.
        for (found, relay_ok, why) in [
            (Some(offer(&[], false)), true, None),
            (Some(offer(&[], true)), false, Some("connection closed")),
            (None, true, Some("no offer for this code")),
        ] {
            let net = RvNet {
                lan: FakeNet::new(),
                found,
                relay_ok,
            };
            let e = go(&net, None).0.unwrap_err();
            let nf = e.downcast_ref::<NotFound>().unwrap();
            match why {
                Some(w) => assert!(nf.tried.iter().any(|t| t.why == w), "{:?}", nf.tried),
                None => assert!(!net.lan.log().contains(&"relay".to_string())),
            }
        }
        // Without a rendezvous nothing of it is tried or shown.
        let (_, steps) = run(&FakeNet::new(), None, &[]);
        assert!(!steps.contains(&Step::Rendezvous));
    }

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn run(net: &FakeNet, typed: Option<&str>, offered: &[&str]) -> (Result<Bundle>, Vec<Step>) {
        let offered: Vec<String> = offered.iter().map(|s| s.to_string()).collect();
        let mut steps = Vec::new();
        let keys = v3::PairingKeys::generate();
        let r = join(
            "123-456-789",
            &keys.join_keys("phone"),
            typed,
            &offered,
            &mut |s| steps.push(s),
            net,
        );
        (r, steps)
    }

    #[test]
    fn a_wrong_typed_address_falls_back_to_the_link_addresses() {
        let mut net = FakeNet::new();
        net.good = Some(sa("192.168.1.23:4000"));
        // The typed address is a VPN one; the link lists it, a bridge one
        // and the Wi-Fi one last: the one on our subnet is tried first.
        let (r, steps) = run(
            &net,
            Some("10.8.0.2:4000"),
            &["10.8.0.2:4000", "172.17.0.1:4000", "192.168.1.23:4000"],
        );
        assert_eq!(r.unwrap().from, "laptop");
        assert_eq!(
            net.log(),
            ["fetch 10.8.0.2:4000", "fetch 192.168.1.23:4000"],
            "typed first, then the link's own-subnet address; no repeat"
        );
        assert_eq!(
            steps,
            [
                Step::Trying(sa("10.8.0.2:4000")),
                Step::Trying(sa("192.168.1.23:4000"))
            ]
        );
    }

    #[test]
    fn without_a_working_address_the_search_runs_last() {
        let mut net = FakeNet::new();
        net.found = vec![sa("192.168.1.23:4001")];
        net.good = Some(sa("192.168.1.23:4001"));
        let (r, steps) = run(&net, Some("10.8.0.2:4000"), &["172.17.0.1:4000"]);
        assert!(r.is_ok());
        assert_eq!(
            net.log(),
            [
                "fetch 10.8.0.2:4000",
                "fetch 172.17.0.1:4000",
                "discover",
                "fetch 192.168.1.23:4001"
            ]
        );
        assert_eq!(steps[2], Step::Looking);
        // Nothing typed and nothing in a link: straight to the search.
        let (r, steps) = run(&net, None, &[]);
        assert!(r.is_ok());
        assert_eq!(steps[0], Step::Looking);
    }

    #[test]
    fn an_address_found_by_the_search_is_not_tried_twice() {
        let mut net = FakeNet::new();
        net.found = vec![sa("192.168.1.23:4000")];
        let (r, _) = run(&net, Some("192.168.1.23:4000"), &[]);
        let e = r.err().unwrap();
        assert_eq!(net.log(), ["fetch 192.168.1.23:4000", "discover"], "{e}");
        let nf = e.downcast_ref::<NotFound>().unwrap();
        assert_eq!(nf.found, 1);
    }

    #[test]
    fn a_device_declined_by_the_other_side_stops_at_once() {
        let mut net = FakeNet::new();
        net.declined = Some(sa("192.168.1.23:4000"));
        net.found = vec![sa("192.168.1.99:4000")];
        let (r, _) = run(&net, Some("192.168.1.23:4000"), &["192.168.1.24:4000"]);
        let e = r.err().unwrap();
        assert!(e.downcast_ref::<v3::Declined>().is_some(), "{e}");
        assert_eq!(net.log(), ["fetch 192.168.1.23:4000"]);
    }

    #[test]
    fn a_wrong_code_stops_at_once() {
        let mut net = FakeNet::new();
        net.wrong = Some(sa("192.168.1.23:4000"));
        net.found = vec![sa("192.168.1.99:4000")];
        let (r, _) = run(&net, Some("192.168.1.23:4000"), &["192.168.1.24:4000"]);
        let e = r.err().unwrap();
        assert!(e.downcast_ref::<WrongCode>().is_some());
        assert!(e.to_string().contains("wrong pairing code"));
        assert_eq!(net.log(), ["fetch 192.168.1.23:4000"]);
    }

    #[test]
    fn the_final_error_names_everything_tried() {
        let net = FakeNet::new();
        let (r, _) = run(&net, Some("not an address"), &["192.168.1.23:4000"]);
        let e = r.err().unwrap();
        let nf = e.downcast_ref::<NotFound>().unwrap();
        assert_eq!(
            nf.tried,
            [
                Tried {
                    what: "not an address".into(),
                    why: "not an address".into()
                },
                Tried {
                    what: "192.168.1.23:4000".into(),
                    why: "no answer".into()
                }
            ]
        );
        let msg = e.to_string();
        for part in [
            "192.168.1.23:4000 (no answer)",
            "Looked for it on the network: nothing answered",
            "same Wi-Fi network",
            "client isolation",
        ] {
            assert!(msg.contains(part), "{part}: {msg}");
        }
    }

    #[test]
    fn a_refused_address_is_skipped_for_the_next_one() {
        let _port = port_lock();
        // A real port nobody listens on: connection refused is not fatal.
        let gone = {
            let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            l.local_addr().unwrap()
        };
        let o = open_offer();
        let code = o.status().code;
        let mut steps = Vec::new();
        let offered = [addr(&o).to_string()];
        let keys = v3::PairingKeys::generate();
        let b = receive_with_progress(
            &code,
            &keys.join_keys("phone"),
            Some(&gone.to_string()),
            &offered,
            &mut |s| steps.push(s),
        )
        .unwrap();
        assert_eq!(b.from, "laptop");
        assert_eq!(steps, [Step::Trying(gone), Step::Trying(addr(&o))]);
    }

    #[test]
    fn the_offer_lists_usable_addresses_only() {
        let _port = port_lock();
        let o = open_offer();
        for a in o.status().addresses {
            let ip: Ipv4Addr = a.rsplit_once(':').unwrap().0.parse().unwrap();
            assert!(!ip.is_loopback() && !ip.is_link_local(), "{a}");
        }
    }
}
