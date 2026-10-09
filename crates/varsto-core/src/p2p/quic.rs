// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! QUIC transport for peer-to-peer transfer, the part that crosses NATs.
//!
//! One UDP socket per device carries everything: QUIC connections, STUN
//! queries and the small "punch" datagrams that open NAT mappings. The socket
//! is wrapped so that QUIC sees only QUIC packets and the other two kinds are
//! routed aside; the port number is the one the TCP listener uses.
//!
//! Identity is a self-signed certificate per device whose SHA-256 travels in
//! the peer record. A client pins the hash it expects from the record; the
//! server demands a client certificate and accepts only hashes of known
//! devices, so a stranger cannot even complete the handshake. The request
//! header check of the TCP transport stays as a second layer on top.
//!
//! Framing: one bidirectional stream per request. The client writes
//! `GET <path>\nX-Varsto-Auth: <token>\n\n` (or `REGISTER <device>\n...` to
//! become a relay registrant) and finishes its side; the server answers
//! `<status> <length>\n` followed by the body. A relay answers
//! `GET /p2p/via/<device>/<rest>` by opening a stream on that device's
//! registration connection and copying the answer back; it sees ciphertext.

use super::stun;
use super::{auth_header, handle, log, verify_auth, PeerInfo, Snapshot};
use crate::crypto::SecretKey;
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

pub const ALPN: &[u8] = b"varsto-p2p/1";
/// A punch datagram: eight bytes nobody answers; it only creates a NAT mapping.
pub const PUNCH_MAGIC: [u8; 8] = *b"VARSTOPU";
pub const CERT_FILE: &str = "p2p-cert.der";
pub const KEY_FILE: &str = "p2p-key.der";
const MAX_HEAD: usize = 8 * 1024;
/// Objects are at most one chunk plus overhead; relays copy whole bodies.
const MAX_BODY: usize = 64 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_millis(1500);
/// How long punching toward a peer behind NAT goes on before giving up.
pub const PUNCH_TIMEOUT: Duration = Duration::from_secs(3);
const PUNCH_INTERVAL: Duration = Duration::from_millis(250);
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
        std::fs::create_dir_all(home)?;
        crate::util::write_atomic(&home.join(CERT_FILE), &id.cert)?;
        crate::util::write_atomic(&home.join(KEY_FILE), &id.key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(home.join(KEY_FILE), std::fs::Permissions::from_mode(0o600))?;
        }
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
    side: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
}

impl SharedSocket {
    fn new(
        std_sock: UdpSocket,
        side: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    ) -> io::Result<SharedSocket> {
        let state = quinn::udp::UdpSocketState::new((&std_sock).into())?;
        let io = tokio::net::UdpSocket::from_std(std_sock)?;
        Ok(SharedSocket { io, state, side })
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
                let _ = self.side.send((meta.addr, seg.to_vec()));
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

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn rejected() -> rustls::Error {
    rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
}

/// Client side: the server must present the certificate whose hash the peer
/// record announced. Names, validity dates and chains are irrelevant.
#[derive(Debug)]
struct PinnedServer {
    expected: String,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
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

// ----- wire format ------------------------------------------------------------

fn request_bytes(verb: &str, target: &str, auth: &str) -> Vec<u8> {
    format!("{verb} {target}\nX-Varsto-Auth: {auth}\n\n").into_bytes()
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

async fn read_response(mut recv: quinn::RecvStream) -> Result<(u16, Vec<u8>)> {
    let raw = tokio::time::timeout(REQUEST_TIMEOUT, recv.read_to_end(MAX_BODY + 64))
        .await
        .map_err(|_| anyhow!("peer response timed out"))??;
    let nl = raw
        .iter()
        .position(|b| *b == b'\n')
        .ok_or_else(|| anyhow!("malformed peer response"))?;
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
    let body = &raw[nl + 1..];
    if body.len() != len {
        bail!("peer response length mismatch");
    }
    Ok((status, body.to_vec()))
}

/// One request on a fresh stream of `conn`.
async fn request_on(
    conn: &quinn::Connection,
    verb: &str,
    target: &str,
    auth: &str,
) -> Result<(u16, Vec<u8>)> {
    let (mut send, recv) = conn.open_bi().await.context("open stream")?;
    send.write_all(&request_bytes(verb, target, auth)).await?;
    send.finish()?;
    read_response(recv).await
}

// ----- the node ---------------------------------------------------------------

/// What the serving side needs, shared by every connection task.
struct Serving {
    me: DeviceId,
    peer_key: SecretKey,
    snapshot: Arc<Mutex<Option<Arc<Snapshot>>>>,
    /// Known devices of the vault: name, certificate hash and addresses.
    known: Mutex<Vec<PeerInfo>>,
    /// Client certificate hashes the handshake accepts.
    allowed: Arc<Mutex<BTreeSet<String>>>,
    /// Devices behind NAT that keep a connection open with us (we relay for them).
    registrants: Mutex<HashMap<DeviceId, quinn::Connection>>,
    /// Connections we already serve streams on (so a registration is served once).
    served: Mutex<BTreeSet<usize>>,
}

/// The QUIC endpoint of a device: a tokio runtime of its own, so the rest
/// of Varsto stays synchronous and calls blocking methods.
pub struct Node {
    rt: tokio::runtime::Runtime,
    endpoint: quinn::Endpoint,
    sock: Arc<SharedSocket>,
    side_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>>,
    identity: Identity,
    serving: Arc<Serving>,
    /// Open connections by address, reused across requests.
    conns: tokio::sync::Mutex<HashMap<SocketAddr, quinn::Connection>>,
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
    /// Bind `addr` and start serving. `snapshot` is shared with the TCP
    /// listener; a `None` snapshot answers 503 to objects.
    pub fn start(
        addr: SocketAddr,
        identity: Identity,
        me: DeviceId,
        peer_key: SecretKey,
        snapshot: Arc<Mutex<Option<Arc<Snapshot>>>>,
    ) -> Result<Arc<Node>> {
        let std_sock = UdpSocket::bind(addr).with_context(|| format!("bind p2p UDP {addr}"))?;
        Self::start_on(std_sock, identity, me, peer_key, snapshot)
    }

    pub fn start_on(
        std_sock: UdpSocket,
        identity: Identity,
        me: DeviceId,
        peer_key: SecretKey,
        snapshot: Arc<Mutex<Option<Arc<Snapshot>>>>,
    ) -> Result<Arc<Node>> {
        std_sock.set_nonblocking(true)?;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("p2p-quic")
            .enable_all()
            .build()
            .context("p2p runtime")?;
        let allowed = Arc::new(Mutex::new(BTreeSet::from([identity.sha256.clone()])));
        let prov = provider();
        let mut tls = rustls::ServerConfig::builder_with_provider(prov.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("tls versions")?
            .with_client_cert_verifier(Arc::new(KnownClients {
                allowed: allowed.clone(),
                algs: prov.signature_verification_algorithms,
            }))
            .with_single_cert(
                vec![CertificateDer::from(identity.cert.clone())],
                PrivateKeyDer::Pkcs8(identity.key.clone().into()),
            )
            .context("p2p server certificate")?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).context("quic server config")?,
        ));
        server.transport_config(transport());

        let (side_tx, side_rx) = mpsc::unbounded_channel();
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
            me,
            peer_key,
            snapshot,
            known: Mutex::new(Vec::new()),
            allowed,
            registrants: Mutex::new(HashMap::new()),
            served: Mutex::new(BTreeSet::new()),
        });
        let (ep, sv) = (endpoint.clone(), serving.clone());
        rt.spawn(async move {
            while let Some(incoming) = ep.accept().await {
                let sv = sv.clone();
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        serve_connection(conn, sv).await;
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

    /// The devices of the vault as their records describe them: refreshes
    /// which client certificates the server accepts and whom the keeper punches.
    pub fn set_known(&self, peers: Vec<PeerInfo>) {
        let mut allowed = self.serving.allowed.lock().unwrap();
        allowed.clear();
        allowed.insert(self.identity.sha256.clone());
        allowed.extend(
            peers
                .iter()
                .filter(|p| !p.cert_sha256.is_empty())
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
        tls.alpn_protocols = vec![ALPN.to_vec()];
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
        if let Some(c) = self.conns.lock().await.get(&addr) {
            if c.close_reason().is_none() && peer_hash(c).as_deref() == Some(expected) {
                return Ok(c.clone());
            }
        }
        if expected.is_empty() {
            bail!("peer has no certificate hash yet");
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
        let deadline = started
            + if punch {
                PUNCH_TIMEOUT
            } else {
                CONNECT_TIMEOUT
            };
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
        self.conns.lock().await.insert(addr, conn.clone());
        Ok(conn)
    }

    /// One request to the peer at `addr` (direct) or, with a `/p2p/via/`
    /// path, through the relay at `addr`.
    pub fn request(
        &self,
        addr: SocketAddr,
        cert_sha256: &str,
        path: &str,
        auth: &str,
        punch: bool,
    ) -> Result<(u16, Vec<u8>)> {
        self.rt.block_on(async {
            let conn = self.connect(addr, cert_sha256, punch).await?;
            request_on(&conn, "GET", path, auth).await
        })
    }

    /// Does our own public address lead back to us? True means other devices
    /// can connect directly, so the record may say `reachable`.
    pub fn probe_self(&self, addr: SocketAddr) -> bool {
        let path = "/p2p/info";
        let auth = auth_header(&self.serving.peer_key, &self.serving.me, path);
        matches!(
            self.request(addr, &self.identity.sha256, path, &auth, false),
            Ok((200, _))
        )
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
        let auth = auth_header(&self.serving.peer_key, &self.serving.me, &path);
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
                let (status, body) =
                    request_on(&conn, "REGISTER", self.serving.me.as_str(), &auth).await?;
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
                    tokio::spawn(async move { serve_connection(conn, sv).await });
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
async fn serve_connection(conn: quinn::Connection, sv: Arc<Serving>) {
    let hash = peer_hash(&conn);
    sv.served.lock().unwrap().insert(conn.stable_id());
    loop {
        let Ok((send, recv)) = conn.accept_bi().await else {
            break;
        };
        let (sv, conn, hash) = (sv.clone(), conn.clone(), hash.clone());
        tokio::spawn(async move {
            let _ = serve_stream(send, recv, conn, hash, sv).await;
        });
    }
}

async fn serve_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    conn: quinn::Connection,
    client_hash: Option<String>,
    sv: Arc<Serving>,
) -> Result<()> {
    let head = tokio::time::timeout(REQUEST_TIMEOUT, recv.read_to_end(MAX_HEAD))
        .await
        .map_err(|_| anyhow!("request head timed out"))??;
    let (status, body) = match parse_request(&head) {
        Err(_) => (400, b"bad request".to_vec()),
        Ok((verb, target, auth)) => match verb.as_str() {
            "GET" => match target.strip_prefix("/p2p/via/") {
                Some(rest) => relay_request(&sv, rest, &auth).await,
                None => {
                    let snap = sv.snapshot.lock().unwrap().clone();
                    handle(snap.as_deref(), &target, &auth)
                }
            },
            "REGISTER" => register(&sv, &target, &auth, client_hash.as_deref(), conn),
            _ => (405, b"unknown verb".to_vec()),
        },
    };
    write_response(&mut send, status, &body).await
}

/// `REGISTER <device>`: the client must hold the certificate the device's
/// record announces and a valid token for `/p2p/register/<device>`.
fn register(
    sv: &Serving,
    device: &str,
    auth: &str,
    client_hash: Option<&str>,
    conn: quinn::Connection,
) -> (u16, Vec<u8>) {
    let Ok(dev) = DeviceId::from_hex(device) else {
        return (400, b"bad device".to_vec());
    };
    let path = format!("/p2p/register/{dev}");
    if verify_auth(&sv.peer_key, auth, &path).as_ref() != Some(&dev) {
        return (403, b"forbidden".to_vec());
    }
    let expected = sv
        .known
        .lock()
        .unwrap()
        .iter()
        .find(|p| p.device == dev)
        .map(|p| p.cert_sha256.clone());
    if expected.is_none() || expected.as_deref() != client_hash {
        return (
            403,
            b"certificate does not match the device record".to_vec(),
        );
    }
    log(&format!(
        "relay: {} registered from {}",
        dev.short(),
        conn.remote_address()
    ));
    sv.registrants.lock().unwrap().insert(dev, conn);
    (200, Vec::new())
}

/// `GET /p2p/via/<device>/<rest>`: forward `/<rest>` on the device's
/// registration connection. The token is checked here too, so an
/// unauthenticated client cannot make us open streams toward registrants.
async fn relay_request(sv: &Serving, rest: &str, auth: &str) -> (u16, Vec<u8>) {
    let Some((device, inner)) = rest.split_once('/') else {
        return (400, b"bad relay path".to_vec());
    };
    let Ok(dev) = DeviceId::from_hex(device) else {
        return (400, b"bad device".to_vec());
    };
    let inner = format!("/{inner}");
    if verify_auth(&sv.peer_key, auth, &inner).is_none() {
        return (403, b"forbidden".to_vec());
    }
    let target = sv.registrants.lock().unwrap().get(&dev).cloned();
    let Some(target) = target else {
        log(&format!(
            "relay: request for {} but it is not registered here",
            dev.short()
        ));
        return (502, b"device is not registered with this relay".to_vec());
    };
    match request_on(&target, "GET", &inner, auth).await {
        Ok(r) => r,
        Err(e) => {
            // The registrant is gone; forget it so the next try fails fast.
            if target.close_reason().is_some() {
                sv.registrants.lock().unwrap().remove(&dev);
            }
            log(&format!(
                "relay: forwarding to {} failed: {e:#}",
                dev.short()
            ));
            (502, format!("relay: {e}").into_bytes())
        }
    }
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
}
