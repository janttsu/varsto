// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! QUIC transport for peer-to-peer transfer, the part that crosses NATs.
//!
//! One UDP socket per device carries everything: QUIC connections, STUN
//! queries and the small "punch" datagrams that open NAT mappings. The socket
//! is wrapped so that QUIC sees only QUIC packets and the other two kinds are
//! routed aside; the port number is the one the TCP listener uses.
//!
//! Identity is a self-signed certificate per device whose SHA-256 travels in
//! the signed peer record. A client pins the hash it expects from the
//! record; the server demands a client certificate and accepts only hashes
//! of the directory's devices, so a stranger cannot even complete the
//! handshake. Every request carries a token bound to the connection's TLS
//! exporter (`super::v3::Responder`) on top.
//!
//! Framing: one bidirectional stream per request. The client writes
//! `GET <path>\nX-Varsto-Auth: <token>\n\n` (or `REGISTER <device>\n...` to
//! become a relay registrant) and finishes its side; the server answers
//! `<status> <length>\n` followed by the body. A relay answers
//! `GET /p2p/via/<device>/<rest>` by opening a stream on that device's
//! registration connection and copying the answer back; it sees ciphertext.

use super::stun;
use super::traffic::{Direction, Traffic};
use super::{is_object, log, PeerInfo, Route, Snapshot};
use crate::ids::DeviceId;
use anyhow::{anyhow, bail, Context, Result};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use quinn::rustls::{self, client::danger as client_danger, server::danger as server_danger};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, IoSliceMut};
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// A punch datagram: eight bytes nobody answers; it only creates a NAT mapping.
pub const PUNCH_MAGIC: [u8; 8] = *b"VARSTOPU";
pub const CERT_FILE: &str = "p2p-cert.der";
/// The verb of the reachability self-probe (`Node::probe_self`).
const PROBE_VERB: &str = "PROBE";
pub const KEY_FILE: &str = "p2p-key.der";
const MAX_HEAD: usize = 32 * 1024;
/// Objects are at most one chunk plus overhead; relays copy whole bodies.
const MAX_BODY: usize = 64 * 1024 * 1024;
/// Streams a peer may have open on one connection (the fetch window is 32).
const MAX_STREAMS: u32 = 64;
/// Incoming connection attempts held at once.
const MAX_INCOMING: usize = 256;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);
/// How long punching toward a peer behind NAT goes on before giving up.
pub const PUNCH_TIMEOUT: Duration = Duration::from_secs(3);
const PUNCH_INTERVAL: Duration = Duration::from_millis(250);
/// How long a failed connection attempt keeps an address from being tried
/// again by requests (the background punching runs on its own schedule).
const FAILED_TTL: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Keeps NAT mappings of idle connections (relay registrations) alive.
const KEEP_ALIVE: Duration = Duration::from_secs(15);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Period of the keeper that punches toward every known public address.
pub const KEEPER_INTERVAL: Duration = Duration::from_secs(20);
/// How long an idle UDP mapping is assumed to survive in a NAT (Linux
/// conntrack drops an unanswered one after 30 s). Punching more often than
/// this keeps our port; a pause longer than this may have lost it.
const MAPPING_LAPSE: Duration = Duration::from_secs(30);

// ----- identity ------------------------------------------------------------

/// The device's self-signed certificate and key, as DER.
#[derive(Clone)]
pub struct Identity {
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
    /// Lower-case hex SHA-256 of the certificate: what peer records carry.
    pub sha256: String,
}

crate::redacted_debug!(Identity { sha256 ; key });

impl Identity {
    pub fn fingerprint(cert_der: &[u8]) -> String {
        hex::encode(Sha256::digest(cert_der))
    }

    /// A fresh ECDSA P-256 certificate; the subject is a constant because
    /// trust comes from the pinned hash, not from any name.
    pub fn generate() -> Result<Identity> {
        let key = rcgen::KeyPair::generate().context("generate p2p key")?;
        let params =
            rcgen::CertificateParams::new(vec!["varsto".to_string()]).context("certificate")?;
        let cert = params
            .self_signed(&key)
            .context("self-sign p2p certificate")?;
        let cert = cert.der().to_vec();
        Ok(Identity {
            sha256: Self::fingerprint(&cert),
            cert,
            key: key.serialize_der(),
        })
    }

    pub fn load(home: &Path) -> Result<Option<Identity>> {
        let (c, k) = (home.join(CERT_FILE), home.join(KEY_FILE));
        if !c.is_file() || !k.is_file() {
            return Ok(None);
        }
        let cert = std::fs::read(&c)?;
        let key = std::fs::read(&k)?;
        Ok(Some(Identity {
            sha256: Self::fingerprint(&cert),
            cert,
            key,
        }))
    }

    /// Load the stored identity or create and store one (`p2p enable`).
    pub fn load_or_create(home: &Path) -> Result<Identity> {
        if let Some(id) = Self::load(home)? {
            return Ok(id);
        }
        let id = Self::generate()?;
        crate::util::private_dir(home)?;
        crate::util::write_atomic(&home.join(CERT_FILE), &id.cert)?;
        crate::util::write_atomic(&home.join(KEY_FILE), &id.key)?;
        Ok(id)
    }
}

// ----- the shared UDP socket -------------------------------------------------

/// Datagrams that are not QUIC: STUN answers go to the side channel, punches
/// are dropped (their work is done by the time they arrive).
fn is_side_traffic(buf: &[u8]) -> bool {
    stun::is_stun(buf) || buf == PUNCH_MAGIC
}

/// One tokio socket wearing quinn's `AsyncUdpSocket` hat, driven through
/// quinn-udp's socket state so that every datagram carries its addresses:
/// `recv` reports the local address a packet arrived on (`IP_PKTINFO`) and
/// `send` puts that address back as the source of the reply. Without this a
/// socket bound to `0.0.0.0` on a multi-homed host (LAN plus VPN, Docker
/// bridges, a cloud machine with a private network) answers from whatever
/// address the routing table prefers for the client, and the client's QUIC
/// stack drops the answer as coming from a stranger. No GSO: one transmit is
/// one datagram, which keeps the filtering trivial.
#[derive(Debug)]
struct SharedSocket {
    io: tokio::net::UdpSocket,
    state: quinn::udp::UdpSocketState,
    side: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    /// True only while `Node::stun` waits for an answer: without an open
    /// request every STUN-looking datagram from the internet is dropped.
    probe_in_flight: std::sync::atomic::AtomicBool,
    /// Transaction id of the open request: only a datagram carrying it
    /// (bytes 8..20) is queued.
    expected_tx: Mutex<Option<[u8; 12]>>,
    /// STUN-looking datagrams dropped (no open request, wrong id, queue full).
    stun_dropped: std::sync::atomic::AtomicU64,
}

/// Capacity of the STUN side channel: a handful of answers is all one probe
/// can use.
const SIDE_QUEUE: usize = 64;

impl SharedSocket {
    fn new(
        std_sock: UdpSocket,
        side: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    ) -> io::Result<SharedSocket> {
        let state = quinn::udp::UdpSocketState::new((&std_sock).into())?;
        let io = tokio::net::UdpSocket::from_std(std_sock)?;
        Ok(SharedSocket {
            io,
            state,
            side,
            probe_in_flight: std::sync::atomic::AtomicBool::new(false),
            expected_tx: Mutex::new(None),
            stun_dropped: std::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Open a probe: from now on only the answer to `tx` is queued.
    fn begin_probe(&self, tx: [u8; 12]) {
        *self.expected_tx.lock().unwrap() = Some(tx);
        self.probe_in_flight
            .store(true, std::sync::atomic::Ordering::Release);
    }

    fn end_probe(&self) {
        self.probe_in_flight
            .store(false, std::sync::atomic::Ordering::Release);
        *self.expected_tx.lock().unwrap() = None;
    }

    /// Queue one STUN datagram when it answers the open request; everything
    /// else is dropped without allocating.
    fn offer_stun(&self, from: SocketAddr, seg: &[u8]) {
        use std::sync::atomic::Ordering;
        let wanted = self.probe_in_flight.load(Ordering::Acquire)
            && seg.len() >= 20
            && *self.expected_tx.lock().unwrap() == seg[8..20].try_into().ok();
        if !wanted || self.side.try_send((from, seg.to_vec())).is_err() {
            self.stun_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Route the segments of one received buffer that are not QUIC: STUN
    /// answers to the side channel, punches to the floor. True when the
    /// buffer was side traffic and quinn must not see it.
    fn divert(&self, buf: &[u8], meta: &quinn::udp::RecvMeta) -> bool {
        let stride = meta.stride.max(1);
        let first = &buf[..meta.len.min(stride)];
        if !is_side_traffic(first) {
            return false;
        }
        // GRO coalesces equal-sized datagrams from one sender: every
        // segment of a side-traffic buffer is side traffic as well.
        for seg in buf[..meta.len].chunks(stride) {
            if stun::is_stun(seg) {
                self.offer_stun(meta.addr, seg);
            }
        }
        true
    }
}

impl quinn::AsyncUdpSocket for SharedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(WritePoller(self))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> io::Result<()> {
        // max_transmit_segments() is 1, so one transmit is one datagram; the
        // state sends it with `src_ip` as the source when quinn set one.
        self.io.try_io(tokio::io::Interest::WRITABLE, || {
            self.state.send((&self.io).into(), transmit)
        })
    }

    fn poll_recv(
        &self,
        cx: &mut TaskContext,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            let Ok(n) = self.io.try_io(tokio::io::Interest::READABLE, || {
                self.state.recv((&self.io).into(), bufs, meta)
            }) else {
                continue; // a spurious readiness: wait again
            };
            // Keep the QUIC messages, compacted to the front, in order.
            let mut kept = 0;
            for i in 0..n {
                if self.divert(&bufs[i], &meta[i]) {
                    continue;
                }
                if kept != i {
                    let len = meta[i].len;
                    let (front, back) = bufs.split_at_mut(i);
                    front[kept][..len].copy_from_slice(&back[0][..len]);
                    meta[kept] = meta[i];
                }
                kept += 1;
            }
            if kept > 0 {
                return Poll::Ready(Ok(kept));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn max_receive_segments(&self) -> usize {
        self.state.gro_segments()
    }

    fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }
}

#[derive(Debug)]
struct WritePoller(Arc<SharedSocket>);

impl quinn::UdpPoller for WritePoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut TaskContext) -> Poll<io::Result<()>> {
        self.0.io.poll_send_ready(cx)
    }
}

// ----- certificate pinning ----------------------------------------------------

pub(super) fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

pub(super) fn rejected() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
}

/// Client side: the server must present the certificate whose hash the peer
/// record announced. Names, validity dates and chains are irrelevant.
#[derive(Debug)]
pub(super) struct PinnedServer {
    pub(super) expected: String,
    pub(super) algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl client_danger::ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<client_danger::ServerCertVerified, rustls::Error> {
        if Identity::fingerprint(end_entity) == self.expected {
            Ok(client_danger::ServerCertVerified::assertion())
        } else {
            Err(rejected())
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<client_danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<client_danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Server side: a client must present a certificate whose hash belongs to a
/// device of this vault (its peer record) or to this device itself (the
/// reachability self-probe). The set changes as records arrive.
#[derive(Debug)]
struct KnownClients {
    allowed: Arc<Mutex<BTreeSet<String>>>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
    /// Told about a refused certificate (`Responder::note_unknown`).
    responder: Arc<super::v3::Responder>,
}

impl server_danger::ClientCertVerifier for KnownClients {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<server_danger::ClientCertVerified, rustls::Error> {
        let hash = Identity::fingerprint(end_entity);
        if self.allowed.lock().unwrap().contains(&hash) {
            Ok(server_danger::ClientCertVerified::assertion())
        } else {
            self.responder.note_unknown();
            Err(rejected())
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<client_danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<client_danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(IDLE_TIMEOUT.try_into().ok());
    t.keep_alive_interval(Some(KEEP_ALIVE));
    // Requests are bidirectional streams the peer opens one per request, up
    // to the fetch window; nothing in the protocol uses a unidirectional one.
    t.max_concurrent_bidi_streams(MAX_STREAMS.into());
    t.max_concurrent_uni_streams(0u32.into());
    Arc::new(t)
}

/// The hash of the certificate the other end of `conn` presented.
fn peer_hash(conn: &quinn::Connection) -> Option<String> {
    let certs = conn
        .peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    certs.first().map(|c| Identity::fingerprint(c))
}

/// The TLS exporter value of `conn` that tokens are keyed with (the same
/// on both ends of the connection).
pub(crate) fn exporter(conn: &quinn::Connection) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, super::v3::EXPORTER_LABEL, b"")
        .ok()?;
    Some(out)
}

// ----- wire format ------------------------------------------------------------

fn request_bytes(verb: &str, target: &str, auth: &str) -> Vec<u8> {
    format!("{verb} {target}\nX-Varsto-Auth: {auth}\n\n").into_bytes()
}

/// The value of header line `name` in a request head.
fn header_value(head: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    let prefix = format!("{name}: ");
    text.lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()))
        .map(|v| v.trim().to_string())
}

/// `(verb, target, auth)` from a request head.
fn parse_request(head: &[u8]) -> Result<(String, String, String)> {
    let text = std::str::from_utf8(head).map_err(|_| anyhow!("request is not UTF-8"))?;
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("");
    let (verb, target) = first
        .split_once(' ')
        .ok_or_else(|| anyhow!("malformed request line"))?;
    let auth = lines
        .filter_map(|l| l.strip_prefix("X-Varsto-Auth: "))
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    Ok((verb.to_string(), target.to_string(), auth))
}

async fn write_response(send: &mut quinn::SendStream, status: u16, body: &[u8]) -> Result<()> {
    send.write_all(format!("{status} {}\n", body.len()).as_bytes())
        .await?;
    send.write_all(body).await?;
    send.finish()?;
    // Wait until the peer has read everything (or gone), so the stream is not
    // torn down with data in flight when the task ends.
    let _ = tokio::time::timeout(REQUEST_TIMEOUT, send.stopped()).await;
    Ok(())
}

/// The longest a response may go without a byte arriving: a slow link
/// keeps sending, a dead one stops. (A whole-response deadline failed any
/// 16 MiB block below about 4.5 Mbit/s.)
const RESPONSE_IDLE: Duration = Duration::from_secs(30);
/// The slowest pace a response may keep on average once its length is
/// known; with `RESPONSE_IDLE` added it bounds the whole response, so a
/// peer trickling a byte now and then cannot hold a request for ever.
const MIN_RATE: u64 = 16 * 1024;

/// One read from `recv` that must bring something within `RESPONSE_IDLE`
/// (and before `deadline`): `None` at the end of the stream.
async fn read_some(
    recv: &mut quinn::RecvStream,
    buf: &mut [u8],
    deadline: tokio::time::Instant,
) -> Result<Option<usize>> {
    let until = deadline.min(tokio::time::Instant::now() + RESPONSE_IDLE);
    match tokio::time::timeout_at(until, recv.read(buf)).await {
        Ok(r) => Ok(r?),
        Err(_) if until >= deadline => bail!("peer response too slow"),
        Err(_) => bail!(
            "peer response timed out (nothing for {} s)",
            RESPONSE_IDLE.as_secs()
        ),
    }
}

/// The deadline of a whole body of `len` bytes from now.
fn body_deadline(len: usize) -> tokio::time::Instant {
    tokio::time::Instant::now() + RESPONSE_IDLE + Duration::from_secs(len as u64 / MIN_RATE)
}

/// The head line of a response (`<status> <length>\n`) and the bytes of the
/// body that came with it.
async fn read_head(recv: &mut quinn::RecvStream) -> Result<(u16, usize, Vec<u8>)> {
    let mut raw: Vec<u8> = Vec::with_capacity(256);
    let mut buf = vec![0u8; 64 * 1024];
    let deadline = tokio::time::Instant::now() + RESPONSE_IDLE;
    let nl = loop {
        if let Some(i) = raw.iter().position(|b| *b == b'\n') {
            break i;
        }
        if raw.len() > 64 {
            bail!("malformed peer response");
        }
        match read_some(recv, &mut buf, deadline).await? {
            Some(n) => raw.extend_from_slice(&buf[..n]),
            None => bail!("malformed peer response"),
        }
    };
    let head = std::str::from_utf8(&raw[..nl]).map_err(|_| anyhow!("malformed peer response"))?;
    let mut parts = head.split_whitespace();
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("malformed status"))?;
    let len: usize = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("malformed length"))?;
    if len > MAX_BODY {
        bail!("peer answer of {len} bytes is too large");
    }
    let rest = raw.split_off(nl + 1);
    if rest.len() > len {
        bail!("peer response length mismatch");
    }
    Ok((status, len, rest))
}

/// A response, read with a per-chunk idle timeout (`RESPONSE_IDLE`) and a
/// floor on the average rate (`MIN_RATE`) instead of one deadline for the
/// whole answer.
async fn read_response(mut recv: quinn::RecvStream) -> Result<(u16, Vec<u8>)> {
    let (status, len, mut body) = read_head(&mut recv).await?;
    body.reserve(len.saturating_sub(body.len()));
    let mut buf = vec![0u8; 64 * 1024];
    let deadline = body_deadline(len);
    loop {
        match read_some(&mut recv, &mut buf, deadline).await? {
            Some(n) => {
                if body.len() + n > len {
                    bail!("peer response length mismatch");
                }
                body.extend_from_slice(&buf[..n]);
            }
            None => break,
        }
    }
    if body.len() != len {
        bail!("peer response length mismatch");
    }
    Ok((status, body))
}

/// One request on a fresh stream of `conn`.
async fn request_on(
    conn: &quinn::Connection,
    verb: &str,
    target: &str,
    auth: &str,
) -> Result<(u16, Vec<u8>)> {
    request_on_for(conn, verb, target, auth, None).await
}

/// `request_on`, with `X-Varsto-For: <device>` when a relay asks for
/// another device.
async fn request_on_for(
    conn: &quinn::Connection,
    verb: &str,
    target: &str,
    auth: &str,
    for_device: Option<&DeviceId>,
) -> Result<(u16, Vec<u8>)> {
    let mut head = request_bytes(verb, target, auth);
    if let Some(d) = for_device {
        head.pop(); // the blank line goes after the extra header
        head.extend_from_slice(format!("X-Varsto-For: {d}\n\n").as_bytes());
    }
    let (_send, recv) = open_request(conn, &head).await?;
    read_response(recv).await
}

/// Open a stream on `conn` and send the request `head` on it. Opening
/// waits for a free stream (at most `MAX_STREAMS` per connection), but not
/// for longer than `RESPONSE_IDLE`.
async fn open_request(
    conn: &quinn::Connection,
    head: &[u8],
) -> Result<(quinn::SendStream, quinn::RecvStream)> {
    let (mut send, recv) = tokio::time::timeout(RESPONSE_IDLE, conn.open_bi())
        .await
        .map_err(|_| anyhow!("no stream free on the connection"))?
        .context("open stream")?;
    tokio::time::timeout(RESPONSE_IDLE, send.write_all(head))
        .await
        .map_err(|_| anyhow!("request not sent"))??;
    send.finish()?;
    Ok((send, recv))
}

// ----- the node ---------------------------------------------------------------

/// What the serving side needs, shared by every connection task.
struct Serving {
    me: DeviceId,
    /// Hash of this device's own certificate (see `serve_connection`).
    own_cert: String,
    snapshot: Arc<Mutex<Option<Arc<Snapshot>>>>,
    /// Known devices of the vault: name, certificate hash and addresses.
    known: Mutex<Vec<PeerInfo>>,
    /// Client certificate hashes the handshake accepts.
    allowed: Arc<Mutex<BTreeSet<String>>>,
    /// Devices behind NAT that keep a connection open with us (we relay for them).
    registrants: Mutex<HashMap<DeviceId, quinn::Connection>>,
    /// Connections we already serve streams on (so a registration is served once).
    served: Mutex<BTreeSet<usize>>,
    traffic: Arc<Traffic>,
    /// Requests are authenticated by the certificate and a token bound to
    /// the connection.
    v3: Arc<super::v3::Responder>,
}

impl Serving {
    /// How a request on `conn` reached us: through the relay `via` (a
    /// registration connection) or directly from its remote address.
    fn path_label(&self, conn: &quinn::Connection, via: Option<&DeviceId>) -> String {
        let remote = conn.remote_address();
        match via {
            Some(relay) => {
                let name = self
                    .known
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|p| &p.device == relay)
                    .map(|p| p.name.clone())
                    .unwrap_or_default();
                Route::Relay(relay.clone(), name, remote).label()
            }
            None => Route::Quic(remote).label(),
        }
    }
}

/// The QUIC endpoint of a device: a tokio runtime of its own, so the rest
/// of Varsto stays synchronous and calls blocking methods.
pub struct Node {
    rt: tokio::runtime::Runtime,
    endpoint: quinn::Endpoint,
    sock: Arc<SharedSocket>,
    side_rx: tokio::sync::Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    identity: Identity,
    serving: Arc<Serving>,
    /// Open connections by address, reused across requests.
    conns: tokio::sync::Mutex<HashMap<SocketAddr, quinn::Connection>>,
    /// One connection attempt per address at a time: requests in flight
    /// together wait for it and then share the connection it opened.
    connecting: tokio::sync::Mutex<HashMap<SocketAddr, Arc<tokio::sync::Mutex<()>>>>,
    /// Addresses whose last connection attempt failed, and when. Requests
    /// that queued behind that attempt (a download asks many blocks at
    /// once) give up at once instead of each waiting out its own timeout.
    failed: Mutex<HashMap<SocketAddr, Instant>>,
    /// How long the last handshake with each host took: the connect
    /// timeout adapts to it (`v3::tls::handshake_timeout`).
    handshakes: Mutex<HashMap<std::net::IpAddr, Duration>>,
    /// Connections this node opened as a client (for tests and diagnostics).
    opened: std::sync::atomic::AtomicUsize,
    /// Relays we are registered with (device -> connection).
    relays: Mutex<BTreeMap<DeviceId, quinn::Connection>>,
    /// The addresses the keeper punched last round, to log changes only.
    punched: Mutex<Vec<SocketAddr>>,
    /// When the keeper last ran, to notice a pause (sleep, suspended process).
    last_round: Mutex<Option<Instant>>,
    /// Set when our NAT mapping may have changed: a punched connect failed,
    /// or the keeper paused long enough for the mapping to lapse. The
    /// service then asks STUN again instead of waiting for the next period.
    restun: std::sync::atomic::AtomicBool,
    pub local_addr: SocketAddr,
}

impl Node {
    /// Bind `addr` and start serving (design section 8): ALPN
    /// `varsto-p2p/3`; the handshake admits only certificates of the
    /// responder's directory (and this device's own for the reachability
    /// self-probe alone), and every request is checked by `responder`.
    /// `snapshot` is shared with the TCP listener; a `None` snapshot
    /// answers 503 to objects.
    pub fn start_v3(
        addr: SocketAddr,
        identity: Identity,
        responder: Arc<super::v3::Responder>,
        snapshot: Arc<Mutex<Option<Arc<Snapshot>>>>,
        traffic: Arc<Traffic>,
    ) -> Result<Arc<Node>> {
        let std_sock = UdpSocket::bind(addr).with_context(|| format!("bind p2p UDP {addr}"))?;
        Self::start_v3_on(std_sock, identity, responder, snapshot, traffic)
    }

    /// `start_v3` on a socket bound already.
    pub fn start_v3_on(
        std_sock: UdpSocket,
        identity: Identity,
        responder: Arc<super::v3::Responder>,
        snapshot: Arc<Mutex<Option<Arc<Snapshot>>>>,
        traffic: Arc<Traffic>,
    ) -> Result<Arc<Node>> {
        let node = Self::start_inner(std_sock, identity, snapshot, traffic, responder.clone())?;
        node.set_known(responder.directory().infos());
        Ok(node)
    }

    fn start_inner(
        std_sock: UdpSocket,
        identity: Identity,
        snapshot: Arc<Mutex<Option<Arc<Snapshot>>>>,
        traffic: Arc<Traffic>,
        responder: Arc<super::v3::Responder>,
    ) -> Result<Arc<Node>> {
        let alpn = super::v3::ALPN;
        let me = responder.me().clone();
        std_sock.set_nonblocking(true)?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("p2p-quic")
            .enable_all()
            .build()
            .context("p2p runtime")?;
        // The handshake admits this device's own certificate for one thing
        // only, the reachability self-probe (`serve_connection` answers
        // nothing else on such a connection).
        let allowed = Arc::new(Mutex::new(BTreeSet::from([identity.sha256.clone()])));
        let prov = provider();
        let mut tls = rustls::ServerConfig::builder_with_provider(prov.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("tls versions")?
            .with_client_cert_verifier(Arc::new(KnownClients {
                responder: responder.clone(),
                allowed: allowed.clone(),
                algs: prov.signature_verification_algorithms,
            }))
            .with_single_cert(
                vec![CertificateDer::from(identity.cert.clone())],
                PrivateKeyDer::Pkcs8(identity.key.clone().into()),
            )
            .context("p2p server certificate")?;
        tls.alpn_protocols = vec![alpn.to_vec()];
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).context("quic server config")?,
        ));
        server.transport_config(transport());
        // Connection attempts waiting to be accepted: a flood of handshakes
        // is refused beyond this instead of queued without end.
        server.max_incoming(MAX_INCOMING);

        let (side_tx, side_rx) = mpsc::channel(SIDE_QUEUE);
        let _enter = rt.enter(); // tokio::net and the endpoint driver need the context
        let sock = Arc::new(SharedSocket::new(std_sock, side_tx)?);
        let local_addr = sock.io.local_addr()?;
        let endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server),
            sock.clone(),
            Arc::new(quinn::TokioRuntime),
        )
        .context("quic endpoint")?;
        let serving = Arc::new(Serving {
            own_cert: identity.sha256.clone(),
            me,
            snapshot,
            known: Mutex::new(Vec::new()),
            allowed,
            registrants: Mutex::new(HashMap::new()),
            served: Mutex::new(BTreeSet::new()),
            traffic,
            v3: responder,
        });
        let (ep, sv) = (endpoint.clone(), serving.clone());
        rt.spawn(async move {
            while let Some(incoming) = ep.accept().await {
                let sv = sv.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        serve_connection(conn, sv, None).await;
                    }
                });
            }
        });
        drop(_enter);
        Ok(Arc::new(Node {
            rt,
            endpoint,
            sock,
            side_rx: tokio::sync::Mutex::new(side_rx),
            identity,
            serving,
            conns: tokio::sync::Mutex::new(HashMap::new()),
            connecting: tokio::sync::Mutex::new(HashMap::new()),
            failed: Mutex::new(HashMap::new()),
            handshakes: Mutex::new(HashMap::new()),
            opened: std::sync::atomic::AtomicUsize::new(0),
            relays: Mutex::new(BTreeMap::new()),
            punched: Mutex::new(Vec::new()),
            last_round: Mutex::new(None),
            restun: std::sync::atomic::AtomicBool::new(false),
            local_addr,
        }))
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn me(&self) -> &DeviceId {
        &self.serving.me
    }

    /// The counters this node serves and relays into; the peer table
    /// built on it counts its downloads there as well.
    pub fn traffic(&self) -> &Arc<Traffic> {
        &self.serving.traffic
    }

    /// The devices of the directory as their records describe them:
    /// refreshes which client certificates the server accepts and whom the
    /// keeper punches. The responder's directory is set by the caller
    /// (`Responder::set_directory`) from the same read.
    pub fn set_known(&self, peers: Vec<PeerInfo>) {
        let mut allowed = self.serving.allowed.lock().unwrap();
        allowed.clear();
        allowed.insert(self.identity.sha256.clone()); // the self-probe only
        allowed.extend(
            peers
                .iter()
                .filter(|p| !p.cert_sha256.is_empty() && p.cert_sha256 != self.identity.sha256)
                .map(|p| p.cert_sha256.clone()),
        );
        *self.serving.known.lock().unwrap() = peers;
    }

    /// Send one datagram outside QUIC (STUN request or punch).
    pub fn send_raw(&self, addr: SocketAddr, bytes: &[u8]) {
        let _ = self.sock.io.try_send_to(bytes, addr);
    }

    pub fn punch(&self, addr: SocketAddr) {
        self.send_raw(addr, &PUNCH_MAGIC);
    }

    /// Punch toward every known peer's public UDP addresses: keeps our own
    /// NAT mapping alive and opens a path for peers that try to reach us.
    pub fn keeper_round(&self) {
        // A long pause (laptop asleep, process stopped) lets our mapping
        // lapse; peers punching the old port in the meantime make a Linux
        // NAT hand us a new one. Ask STUN again rather than trust the record.
        let mut last = self.last_round.lock().unwrap();
        if let Some(t) = *last {
            let gap = t.elapsed();
            if gap > KEEPER_INTERVAL + MAPPING_LAPSE {
                log(&format!(
                    "keeper paused for {} s; the NAT mapping may have changed",
                    gap.as_secs()
                ));
                self.request_restun();
            }
        }
        *last = Some(Instant::now());
        drop(last);
        let known = self.serving.known.lock().unwrap().clone();
        let mut addrs: Vec<SocketAddr> = Vec::new();
        for p in known {
            for a in p.udp.iter().filter(|a| !super::is_lan(a.ip())) {
                if !addrs.contains(a) {
                    addrs.push(*a);
                }
            }
        }
        let mut punched = self.punched.lock().unwrap();
        if *punched != addrs {
            log(&format!(
                "punching toward {} every {} s",
                if addrs.is_empty() {
                    "nobody".to_string()
                } else {
                    addrs
                        .iter()
                        .map(|a| a.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                },
                KEEPER_INTERVAL.as_secs()
            ));
            *punched = addrs.clone();
        }
        drop(punched);
        for a in addrs {
            self.punch(a);
        }
    }

    /// Start the keeper on the node's runtime; it stops with the node.
    pub fn start_keeper(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        self.rt.spawn(async move {
            let mut tick = tokio::time::interval(KEEPER_INTERVAL);
            loop {
                tick.tick().await;
                let Some(node) = weak.upgrade() else { break };
                node.keeper_round();
            }
        });
    }

    fn request_restun(&self) {
        self.restun
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Should STUN be asked again now? Clears the request.
    pub fn take_restun(&self) -> bool {
        self.restun
            .swap(false, std::sync::atomic::Ordering::Relaxed)
    }

    /// STUN through the shared socket: what the internet sees of our port.
    pub fn stun(&self, servers: &[String], timeout: Duration) -> stun::Probe {
        let ipv6 = self.local_addr.is_ipv6();
        self.rt.block_on(async {
            let mut rx = self.side_rx.lock().await;
            let mut mapped = Vec::new();
            for s in servers {
                let Some(server) = stun::resolve(s, ipv6).into_iter().next() else {
                    continue;
                };
                while rx.try_recv().is_ok() {} // stale answers
                let tx = stun::new_transaction_id();
                self.sock.begin_probe(tx);
                self.send_raw(server, &stun::encode_binding_request(&tx));
                let deadline = tokio::time::Instant::now() + timeout;
                loop {
                    let Ok(Some((_, buf))) = tokio::time::timeout_at(deadline, rx.recv()).await
                    else {
                        break;
                    };
                    if let Ok(a) = stun::parse_binding_response(&buf, &tx) {
                        mapped.push(a);
                        break;
                    }
                }
                if mapped.len() >= 2 {
                    break;
                }
            }
            self.sock.end_probe();
            let nat = stun::classify(&super::local_ipv4_addrs(), &mapped);
            stun::Probe { mapped, nat }
        })
    }

    fn client_config(&self, expected: &str) -> Result<quinn::ClientConfig> {
        let prov = provider();
        let mut tls = rustls::ClientConfig::builder_with_provider(prov.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("tls versions")?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServer {
                expected: expected.to_string(),
                algs: prov.signature_verification_algorithms,
            }))
            .with_client_auth_cert(
                vec![CertificateDer::from(self.identity.cert.clone())],
                PrivateKeyDer::Pkcs8(self.identity.key.clone().into()),
            )
            .context("p2p client certificate")?;
        tls.alpn_protocols = vec![super::v3::ALPN.to_vec()];
        let mut cfg = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).context("quic client config")?,
        ));
        cfg.transport_config(transport());
        Ok(cfg)
    }

    /// An open connection to `addr` whose certificate hashes to `expected`,
    /// reused when one exists. With `punch`, punch datagrams go out every
    /// quarter second while the handshake is pending, for up to three seconds.
    async fn connect(
        &self,
        addr: SocketAddr,
        expected: &str,
        punch: bool,
    ) -> Result<quinn::Connection> {
        if let Some(c) = self.reusable(addr, expected).await {
            return Ok(c);
        }
        let gate = self
            .connecting
            .lock()
            .await
            .entry(addr)
            .or_default()
            .clone();
        let _one_at_a_time = gate.lock().await;
        if let Some(c) = self.reusable(addr, expected).await {
            return Ok(c);
        }
        if let Some(when) = self.failed.lock().unwrap().get(&addr) {
            if when.elapsed() < FAILED_TTL {
                bail!(
                    "quic {addr}: no answer {} s ago; not asked again yet",
                    when.elapsed().as_secs()
                );
            }
        }
        if expected.is_empty() {
            bail!("peer has no certificate hash yet");
        }
        if expected == self.identity.sha256 {
            bail!("quic {addr}: that certificate is this device's own");
        }
        // A LAN address has no NAT between us: no punching, a short wait.
        let punch = punch && !super::is_lan(addr.ip());
        let cfg = self.client_config(expected)?;
        let connecting = self
            .endpoint
            .connect_with(cfg, addr, "varsto")
            .with_context(|| format!("connect {addr}"))?;
        let mut connecting = Box::pin(connecting);
        let started = Instant::now();
        // Three times the last handshake with that host (a long round
        // trip), at least the LAN or punching figure, at most six seconds;
        // beyond the LAN the wait is given once more before giving up, so
        // one lost packet does not rest the device.
        let base = if punch {
            PUNCH_TIMEOUT
        } else {
            CONNECT_TIMEOUT
        };
        let last = self.handshakes.lock().unwrap().get(&addr.ip()).copied();
        let wait = super::v3::tls::handshake_timeout(base, last);
        let mut deadline = started + wait;
        let mut extended = super::is_lan(addr.ip());
        let mut tick = tokio::time::interval(PUNCH_INTERVAL);
        let mut punches = 0u32;
        let outcome = loop {
            tokio::select! {
                r = &mut connecting => break r.with_context(|| format!("quic {addr}")),
                _ = tick.tick() => {
                    if punch {
                        self.punch(addr);
                        punches += 1;
                    }
                    if Instant::now() >= deadline && !extended {
                        extended = true;
                        deadline += wait;
                        log(&format!(
                            "quic {addr}: no answer in {} ms; waiting once more",
                            started.elapsed().as_millis()
                        ));
                    }
                    if Instant::now() >= deadline {
                        break Err(anyhow!(
                            "quic {addr}: no answer in {} ms{}",
                            started.elapsed().as_millis(),
                            if punch { format!(" ({punches} punches sent)") } else { String::new() }
                        ));
                    }
                }
            }
        };
        let conn = match outcome {
            Ok(c) => c,
            Err(e) => {
                self.failed.lock().unwrap().insert(addr, Instant::now());
                log(&format!("quic connect {addr} failed: {e:#}"));
                if punch {
                    // Our own mapping may be stale; have the record corrected.
                    self.request_restun();
                }
                return Err(e);
            }
        };
        log(&format!(
            "quic connect {addr} ok in {} ms{}",
            started.elapsed().as_millis(),
            if punch {
                format!(" ({punches} punches sent)")
            } else {
                String::new()
            }
        ));
        self.failed.lock().unwrap().remove(&addr);
        self.handshakes
            .lock()
            .unwrap()
            .insert(addr.ip(), started.elapsed());
        self.conns.lock().await.insert(addr, conn.clone());
        self.opened
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(conn)
    }

    /// An open connection to `addr` with the certificate we expect.
    async fn reusable(&self, addr: SocketAddr, expected: &str) -> Option<quinn::Connection> {
        let conns = self.conns.lock().await;
        let c = conns.get(&addr)?;
        (c.close_reason().is_none() && peer_hash(c).as_deref() == Some(expected)).then(|| c.clone())
    }

    /// How many connections this node has opened as a client.
    pub fn connections_opened(&self) -> usize {
        self.opened.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// One request to the peer at `addr` (direct) or, with a `/p2p/via/`
    /// path, through the relay at `addr`, with the token made for the
    /// connection the request goes out on, from its TLS exporter value.
    pub fn request_with(
        &self,
        addr: SocketAddr,
        cert_sha256: &str,
        path: &str,
        punch: bool,
        token: &dyn Fn(&[u8; 32]) -> String,
    ) -> Result<(u16, Vec<u8>)> {
        self.request_auth(addr, cert_sha256, path, punch, &|c: &quinn::Connection| {
            exporter(c).map(|e| token(&e)).unwrap_or_default()
        })
    }

    fn request_auth(
        &self,
        addr: SocketAddr,
        cert_sha256: &str,
        path: &str,
        punch: bool,
        auth_for: &dyn Fn(&quinn::Connection) -> String,
    ) -> Result<(u16, Vec<u8>)> {
        self.rt.block_on(async {
            let reused = self.reusable(addr, cert_sha256).await.is_some();
            let conn = self.connect(addr, cert_sha256, punch).await?;
            match request_on(&conn, "GET", path, &auth_for(&conn)).await {
                Ok(r) => Ok(r),
                // A kept connection can outlive the other end (it restarted,
                // or its address changed): open a new one and ask again once,
                // instead of falling back to a slower route for good.
                Err(e) if reused => {
                    log(&format!(
                        "quic {addr}: kept connection failed ({e:#}); reconnecting"
                    ));
                    conn.close(0u32.into(), b"stale");
                    self.forget(addr, &conn).await;
                    let conn = self.connect(addr, cert_sha256, punch).await?;
                    request_on(&conn, "GET", path, &auth_for(&conn)).await
                }
                Err(e) => Err(e),
            }
        })
    }

    /// Drop `conn` from the cache unless another request already replaced it.
    async fn forget(&self, addr: SocketAddr, conn: &quinn::Connection) {
        let mut conns = self.conns.lock().await;
        if conns.get(&addr).map(|c| c.stable_id()) == Some(conn.stable_id()) {
            conns.remove(&addr);
        }
    }

    /// Does our own public address lead back to us? True means other devices
    /// can connect directly, so the record may say `reachable`.
    ///
    /// The probe is a path of its own, not a request to a peer: a fresh
    /// connection pinned to this device's own certificate (which `connect`
    /// refuses for every other purpose), never kept or counted, carrying
    /// one `PROBE <nonce>` that only a connection presenting our own
    /// certificate may send and that the server answers by echoing the
    /// nonce. Reaching our own listener through the public address and
    /// getting our nonce back is the proof.
    pub fn probe_self(&self, addr: SocketAddr) -> bool {
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let nonce = hex::encode(nonce);
        let result = self.rt.block_on(async {
            let cfg = self.client_config(&self.identity.sha256)?;
            let connecting = self
                .endpoint
                .connect_with(cfg, addr, "varsto")
                .with_context(|| format!("connect {addr}"))?;
            let conn = tokio::time::timeout(CONNECT_TIMEOUT, connecting)
                .await
                .map_err(|_| anyhow!("self-probe {addr}: no answer"))??;
            let r = request_on(&conn, PROBE_VERB, &nonce, "").await;
            conn.close(0u32.into(), b"probed");
            r
        });
        match result {
            Ok((200, body)) => body == nonce.as_bytes(),
            Ok((status, _)) => {
                log(&format!("self-probe {addr}: answered {status}"));
                false
            }
            Err(e) => {
                log(&format!("self-probe {addr}: {e:#}"));
                false
            }
        }
    }

    /// Register with the relay `relay` (a reachable device of the vault):
    /// connect, send `REGISTER`, and serve the streams it opens on that
    /// connection from now on. The first address that answers wins.
    pub fn register_with(
        &self,
        relay: &DeviceId,
        addrs: &[SocketAddr],
        cert_sha256: &str,
    ) -> Result<()> {
        let path = format!("/p2p/register/{}", self.serving.me);
        let r = self.serving.v3.clone();
        let auth_for = |conn: &quinn::Connection| -> String {
            exporter(conn)
                .map(|e| r.token(&e, relay, &path))
                .unwrap_or_default()
        };
        self.rt.block_on(async {
            let mut last = anyhow!("relay has no address");
            for addr in addrs {
                log(&format!(
                    "registering with relay {} at {addr}",
                    relay.short()
                ));
                let conn = match self.connect(*addr, cert_sha256, true).await {
                    Ok(c) => c,
                    Err(e) => {
                        last = e;
                        continue;
                    }
                };
                let (status, body) = request_on(
                    &conn,
                    "REGISTER",
                    self.serving.me.as_str(),
                    &auth_for(&conn),
                )
                .await?;
                if status != 200 {
                    bail!(
                        "relay refused registration: {status} {}",
                        String::from_utf8_lossy(&body)
                    );
                }
                self.relays
                    .lock()
                    .unwrap()
                    .insert(relay.clone(), conn.clone());
                // The relay opens streams toward us on this connection.
                let sv = self.serving.clone();
                if sv.served.lock().unwrap().insert(conn.stable_id()) {
                    let via = relay.clone();
                    tokio::spawn(async move { serve_connection(conn, sv, Some(via)).await });
                }
                return Ok(());
            }
            Err(last)
        })
    }

    /// Relays whose registration connection is still open.
    pub fn registered_relays(&self) -> Vec<DeviceId> {
        let mut relays = self.relays.lock().unwrap();
        relays.retain(|_, c| c.close_reason().is_none());
        relays.keys().cloned().collect()
    }

    /// The address a device registered with us as its relay connects from.
    pub fn registrant_addr(&self, dev: &DeviceId) -> Option<SocketAddr> {
        let regs = self.serving.registrants.lock().unwrap();
        regs.get(dev)
            .filter(|c| c.close_reason().is_none())
            .map(|c| c.remote_address())
    }

    /// Ask a device that keeps its relay registration with us, on that
    /// connection, with a token bound to it. We are its relay, so there is
    /// no third device to go through, and a device behind a symmetric NAT
    /// cannot be dialled.
    pub fn request_registrant_with(
        &self,
        dev: &DeviceId,
        path: &str,
        token: &dyn Fn(&[u8; 32]) -> String,
    ) -> Result<(u16, Vec<u8>)> {
        self.registrant_auth(dev, path, &|c: &quinn::Connection| {
            exporter(c).map(|e| token(&e)).unwrap_or_default()
        })
    }

    fn registrant_auth(
        &self,
        dev: &DeviceId,
        path: &str,
        auth_for: &dyn Fn(&quinn::Connection) -> String,
    ) -> Result<(u16, Vec<u8>)> {
        let conn = self
            .serving
            .registrants
            .lock()
            .unwrap()
            .get(dev)
            .cloned()
            .ok_or_else(|| anyhow!("not registered here"))?;
        // Bounded by the per-chunk idle timeout of the response, not by a
        // deadline for the whole answer (a large block on a slow link).
        let auth = auth_for(&conn);
        match self.rt.block_on(request_on(&conn, "GET", path, &auth)) {
            Ok(x) => Ok(x),
            Err(e) => {
                if conn.close_reason().is_some() {
                    self.serving.registrants.lock().unwrap().remove(dev);
                }
                Err(e)
            }
        }
    }

    /// Devices registered with us as their relay.
    pub fn registrants(&self) -> Vec<DeviceId> {
        let mut regs = self.serving.registrants.lock().unwrap();
        regs.retain(|_, c| c.close_reason().is_none());
        regs.keys().cloned().collect()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"bye");
    }
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

// ----- serving ------------------------------------------------------------------

/// Accept streams on `conn` until it closes; each stream is one request.
/// `via` is the relay when `conn` is our registration with it: requests
/// arriving there come from other devices through that relay.
async fn serve_connection(conn: quinn::Connection, sv: Arc<Serving>, via: Option<DeviceId>) {
    let hash = peer_hash(&conn);
    // A client holding this device's own certificate is this device (or a
    // copy of its identity): not a peer, so the connection is dropped.
    if via.is_none() && hash.as_deref() == Some(sv.own_cert.as_str()) {
        // The one thing it may do is the reachability self-probe.
        answer_self_probe(&conn).await;
        conn.close(0u32.into(), b"self");
        return;
    }
    sv.served.lock().unwrap().insert(conn.stable_id());
    loop {
        let Ok((send, recv)) = conn.accept_bi().await else {
            break;
        };
        let (sv, conn, via) = (sv.clone(), conn.clone(), via.clone());
        tokio::spawn(async move {
            let _ = serve_stream(send, recv, conn, sv, via).await;
        });
    }
}

/// On a connection that presented our own certificate: answer one
/// `PROBE <nonce>` by echoing the nonce; anything else gets a refusal.
async fn answer_self_probe(conn: &quinn::Connection) {
    let Ok(Ok((mut send, mut recv))) =
        tokio::time::timeout(CONNECT_TIMEOUT, conn.accept_bi()).await
    else {
        return;
    };
    let Ok(Ok(head)) = tokio::time::timeout(REQUEST_TIMEOUT, recv.read_to_end(MAX_HEAD)).await
    else {
        return;
    };
    let (status, body) = match parse_request(&head) {
        Ok((verb, nonce, _)) if verb == PROBE_VERB && nonce.len() == 32 => {
            (200, nonce.into_bytes())
        }
        _ => (403, super::SELF_ANSWER.to_vec()),
    };
    let _ = write_response(&mut send, status, &body).await;
}

async fn serve_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    conn: quinn::Connection,
    sv: Arc<Serving>,
    via: Option<DeviceId>,
) -> Result<()> {
    let head = tokio::time::timeout(REQUEST_TIMEOUT, recv.read_to_end(MAX_HEAD))
        .await
        .map_err(|_| anyhow!("request head timed out"))??;
    let path_label = sv.path_label(&conn, via.as_ref());
    let r = sv.v3.clone();
    let ci = super::v3::ConnInfo::of_quic(&conn, via.is_some());
    // A request to relay is answered as the registrant's answer arrives.
    if let Ok((verb, target, auth)) = parse_request(&head) {
        if let (true, Some(rest)) = (verb == "GET", target.strip_prefix("/p2p/via/")) {
            return relay_stream(&mut send, &sv, &r, &ci, &target, rest, &auth).await;
        }
    }
    let (status, body, peer, target) = serve_v3(&sv, &r, &ci, &head, &conn).await;
    // The device the answer goes to, once its token checked out, and the
    // path asked for: the traffic counters charge the answer to it.
    let to = peer.map(|p| (p, target));
    answer_counted(&mut send, &sv, &conn, &path_label, to, status, &body).await
}

/// Write the answer; when it went to an authenticated device, count it.
async fn answer_counted(
    send: &mut quinn::SendStream,
    sv: &Serving,
    conn: &quinn::Connection,
    path_label: &str,
    served: Option<(DeviceId, String)>,
    status: u16,
    body: &[u8],
) -> Result<()> {
    let Some((peer, target)) = served else {
        return write_response(send, status, body).await;
    };
    let _active = sv.traffic.begin(&peer);
    let result = write_response(send, status, body).await;
    if result.is_ok() {
        sv.traffic.record(
            &peer,
            Direction::Out,
            body.len() as u64,
            is_object(&target, status),
            path_label,
            Some(conn.remote_address()),
        );
    }
    result
}

/// One request on `conn`, checked by `r`: `(status, body, the device it
/// was for when it was authenticated, the path)`.
async fn serve_v3(
    sv: &Arc<Serving>,
    r: &Arc<super::v3::Responder>,
    ci: &super::v3::ConnInfo,
    head: &[u8],
    conn: &quinn::Connection,
) -> (u16, Vec<u8>, Option<DeviceId>, String) {
    let Ok((verb, target, auth)) = parse_request(head) else {
        return (400, b"bad request".to_vec(), None, String::new());
    };
    let for_device = header_value(head, "X-Varsto-For").unwrap_or_default();
    match verb.as_str() {
        "GET" => {
            // `/p2p/via/` is relayed before this (`relay_stream`).
            let snap = sv.snapshot.lock().unwrap().clone();
            let (r, ci, t) = (r.clone(), ci.clone(), target.clone());
            let (status, body, peer) = tokio::task::spawn_blocking(move || {
                r.handle(snap.as_deref(), &ci, &t, &auth, &for_device)
            })
            .await
            .unwrap_or_else(|_| (500, b"internal error".to_vec(), None));
            (status, body, peer, target)
        }
        "REGISTER" => {
            let Ok(dev) = DeviceId::from_hex(&target) else {
                return (400, b"bad device".to_vec(), None, target);
            };
            let path = format!("/p2p/register/{dev}");
            match r.authorize(ci, &auth, &path) {
                Ok(asker) if asker == dev => {
                    log(&format!(
                        "relay: {} registered from {}",
                        dev.short(),
                        conn.remote_address()
                    ));
                    sv.registrants.lock().unwrap().insert(dev, conn.clone());
                    (200, Vec::new(), None, target)
                }
                Ok(_) => (
                    403,
                    b"certificate does not match the device record".to_vec(),
                    None,
                    target,
                ),
                Err((status, body)) => (status, body, None, target),
            }
        }
        _ => (405, b"unknown verb".to_vec(), None, target),
    }
}

/// The relay: the asker's token is bound to its connection with us, so it
/// cannot travel on; we check it and ask the registrant on our own
/// connection with it, with a token of ours and `X-Varsto-For` naming the
/// asker (the registrant trusts us as a device of its directory).
///
/// The registrant's answer is passed on as it arrives, its head line first
/// and then the body chunk by chunk, so neither leg waits for the other to
/// finish and a large block on a slow link is not cut off (each leg has the
/// per-chunk idle timeout of `read_response`).
async fn relay_stream(
    send: &mut quinn::SendStream,
    sv: &Serving,
    r: &super::v3::Responder,
    ci: &super::v3::ConnInfo,
    target: &str,
    rest: &str,
    auth: &str,
) -> Result<()> {
    let Some((device, inner)) = rest.split_once('/') else {
        return write_response(send, 400, b"bad relay path").await;
    };
    let Ok(dev) = DeviceId::from_hex(device) else {
        return write_response(send, 400, b"bad device").await;
    };
    let inner = format!("/{inner}");
    let asker = match r.authorize(ci, auth, target) {
        Ok(a) => a,
        Err((status, body)) => return write_response(send, status, &body).await,
    };
    let reg = sv.registrants.lock().unwrap().get(&dev).cloned();
    let Some(reg) = reg else {
        return write_response(send, 502, b"device is not registered with this relay").await;
    };
    let Some(exp) = exporter(&reg) else {
        return write_response(send, 502, b"relay: no exporter on the registration").await;
    };
    let token = r.token(&exp, &dev, &inner);
    let _active = sv.traffic.begin_relay(&dev, &asker);
    let mut head = request_bytes("GET", &inner, &token);
    head.pop(); // the blank line goes after the extra header
    head.extend_from_slice(format!("X-Varsto-For: {asker}\n\n").as_bytes());
    let asked = match open_request(&reg, &head).await {
        Ok((reg_send, mut recv)) => read_head(&mut recv).await.map(|h| (reg_send, recv, h)),
        Err(e) => Err(e),
    };
    let (_reg_send, mut recv, (status, len, first)) = match asked {
        Ok(x) => x,
        Err(e) => {
            if reg.close_reason().is_some() {
                sv.registrants.lock().unwrap().remove(&dev);
            }
            let msg = format!("relay: {e}");
            return write_response(send, 502, msg.as_bytes()).await;
        }
    };
    // From here on the answer is the registrant's, passed on as it comes.
    send.write_all(format!("{status} {len}\n").as_bytes())
        .await?;
    send.write_all(&first).await?;
    let mut passed = first.len();
    let mut buf = vec![0u8; 64 * 1024];
    let deadline = body_deadline(len);
    while passed < len {
        match read_some(&mut recv, &mut buf, deadline).await {
            Ok(Some(n)) if passed + n <= len => {
                send.write_all(&buf[..n]).await?;
                passed += n;
            }
            Ok(Some(_)) => break,
            Ok(None) => break,
            Err(e) => {
                let _ = send.reset(0u32.into());
                return Err(e.context("relay: the registrant's answer stalled"));
            }
        }
    }
    if passed != len {
        // The asker sees a stream reset, never a short body taken as whole.
        let _ = send.reset(0u32.into());
        bail!("relay: the registrant's answer did not match its length");
    }
    send.finish()?;
    sv.traffic
        .record_relay(&dev, &asker, len as u64, is_object(&inner, status));
    let _ = tokio::time::timeout(REQUEST_TIMEOUT, send.stopped()).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_on_disk_and_fingerprinted() {
        let dir = tempfile::tempdir().unwrap();
        let a = Identity::load_or_create(dir.path()).unwrap();
        let b = Identity::load_or_create(dir.path()).unwrap();
        assert_eq!(a.sha256, b.sha256);
        assert_eq!(a.sha256.len(), 64);
        assert_eq!(a.sha256, Identity::fingerprint(&a.cert));
        assert_ne!(Identity::generate().unwrap().sha256, a.sha256);
    }

    #[test]
    fn the_self_probe_reaches_us_while_dialling_our_own_certificate_stays_refused() {
        let id = Identity::generate().unwrap();
        let own = id.sha256.clone();
        let node = Node::start_v3(
            "127.0.0.1:0".parse().unwrap(),
            id.clone(),
            super::super::v3::Responder::new(DeviceId::random(), &own),
            Arc::default(),
            Arc::default(),
        )
        .unwrap();
        let addr = node.local_addr;
        assert!(node.probe_self(addr), "our own listener answers the probe");
        assert_eq!(
            node.connections_opened(),
            0,
            "the probe is no peer connection"
        );
        // An ordinary request pinned to our own certificate is refused.
        let e = node
            .request_with(addr, &own, "/p2p/info", false, &|_| "x".into())
            .err()
            .unwrap();
        assert!(e.to_string().contains("own"), "{e:#}");
        // Nothing answers at an address where we do not listen.
        let gone = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(!node.probe_self(gone));
        // Another device's listener does not echo our probe: it refuses our
        // certificate (unknown to it), so the probe fails.
        let other_id = Identity::generate().unwrap();
        let other = Node::start_v3(
            "127.0.0.1:0".parse().unwrap(),
            other_id.clone(),
            super::super::v3::Responder::new(DeviceId::random(), &other_id.sha256),
            Arc::default(),
            Arc::default(),
        )
        .unwrap();
        assert!(!node.probe_self(other.local_addr));
    }

    #[test]
    fn request_heads_parse() {
        let head = request_bytes("GET", "/p2p/object/ab", "dev:1:mac");
        assert_eq!(
            parse_request(&head).unwrap(),
            ("GET".into(), "/p2p/object/ab".into(), "dev:1:mac".into())
        );
        assert!(parse_request(b"nonsense").is_err());
        assert!(!is_side_traffic(&head));
        assert!(is_side_traffic(&PUNCH_MAGIC));
        assert!(is_side_traffic(&stun::encode_binding_request(&[0u8; 12])));
    }

    fn test_socket() -> (SharedSocket, mpsc::Receiver<(SocketAddr, Vec<u8>)>) {
        let (tx, rx) = mpsc::channel(SIDE_QUEUE);
        let std_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        std_sock.set_nonblocking(true).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _enter = rt.enter();
        let sock = SharedSocket::new(std_sock, tx).unwrap();
        std::mem::forget(rt); // the socket needs its reactor alive for the test
        (sock, rx)
    }

    #[test]
    fn unsolicited_stun_flood_is_not_queued() {
        use std::sync::atomic::Ordering;
        let (sock, mut rx) = test_socket();
        let from: SocketAddr = "203.0.113.9:3478".parse().unwrap();
        let fake = stun::encode_binding_request(&[7u8; 12]);
        for _ in 0..10_000 {
            sock.offer_stun(from, &fake);
        }
        assert!(rx.try_recv().is_err());
        assert_eq!(sock.stun_dropped.load(Ordering::Relaxed), 10_000);
        // An open request still only admits its own transaction id, and the
        // queue stays bounded however many copies arrive.
        sock.begin_probe([1u8; 12]);
        for _ in 0..10_000 {
            sock.offer_stun(from, &fake);
        }
        assert!(rx.try_recv().is_err());
        let ours = stun::encode_binding_request(&[1u8; 12]);
        for _ in 0..1_000 {
            sock.offer_stun(from, &ours);
        }
        let mut queued = 0;
        while rx.try_recv().is_ok() {
            queued += 1;
        }
        assert_eq!(queued, SIDE_QUEUE);
        sock.end_probe();
        sock.offer_stun(from, &ours);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn answer_to_the_open_request_goes_through() {
        let (sock, mut rx) = test_socket();
        let from: SocketAddr = "203.0.113.9:3478".parse().unwrap();
        sock.begin_probe([9u8; 12]);
        sock.offer_stun(from, &stun::encode_binding_request(&[9u8; 12]));
        let (addr, buf) = rx.try_recv().unwrap();
        assert_eq!(addr, from);
        assert_eq!(&buf[8..20], &[9u8; 12]);
    }
}
