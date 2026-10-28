// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! TLS 1.3 over TCP for format 3 (design section 8: "Plain HTTP over TCP is
//! gone"): the same self-signed certificates, pins and client
//! authentication as QUIC, ALPN `varsto-p2p/3`, and the same request lines
//! inside the session as before. A client that does not open with a TLS
//! handshake gets an alert and the connection closes; no byte of the
//! protocol is ever sent in the clear.
//!
//! The server admits a client certificate only when the responder's
//! directory names it (an accepted peer record of a trusted full device);
//! this device's own certificate is refused both ways.

use super::{ConnInfo, Responder, ALPN, EXPORTER_LABEL};
use crate::p2p::quic::{self, Identity, PinnedServer};
use crate::p2p::{RequestHeaders, Snapshot};
use anyhow::{anyhow, bail, Context, Result};
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use quinn::rustls::{self, client::danger as client_danger, server::danger as server_danger};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long the TLS handshake of an accepted connection may take.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(5);

/// The server side of a TLS session over TCP.
pub type ServerStream = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;
/// The client side.
pub type ClientStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn sha256(cert: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(cert).into()
}

/// Server side: the client certificate must be in the directory.
#[derive(Debug)]
struct DirectoryClients {
    responder: Arc<Responder>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl server_danger::ClientCertVerifier for DirectoryClients {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<server_danger::ClientCertVerified, rustls::Error> {
        if self.responder.admits(&sha256(end_entity)) {
            Ok(server_danger::ClientCertVerified::assertion())
        } else {
            Err(quic::rejected())
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

/// The TLS side of the TCP listener.
pub struct TcpTls {
    config: Arc<rustls::ServerConfig>,
    responder: Arc<Responder>,
}

impl std::fmt::Debug for TcpTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpTls").finish_non_exhaustive()
    }
}

impl TcpTls {
    pub fn new(identity: &Identity, responder: Arc<Responder>) -> Result<Arc<TcpTls>> {
        let prov = quic::provider();
        let mut tls = rustls::ServerConfig::builder_with_provider(prov.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("tls versions")?
            .with_client_cert_verifier(Arc::new(DirectoryClients {
                responder: responder.clone(),
                algs: prov.signature_verification_algorithms,
            }))
            .with_single_cert(
                vec![CertificateDer::from(identity.cert.clone())],
                PrivateKeyDer::Pkcs8(identity.key.clone().into()),
            )
            .context("p2p server certificate")?;
        tls.alpn_protocols = vec![ALPN.to_vec()];
        Ok(Arc::new(TcpTls {
            config: Arc::new(tls),
            responder,
        }))
    }

    pub fn responder(&self) -> &Arc<Responder> {
        &self.responder
    }

    /// Run the handshake on an accepted connection, then hand the session
    /// and the request handler to `run` (the connection loop of the TCP
    /// server). A client that fails the handshake (no TLS, a certificate
    /// nobody named, the wrong protocol) gets the alert rustls sends and is
    /// closed.
    pub(crate) fn serve(
        &self,
        sock: TcpStream,
        remote: SocketAddr,
        run: impl FnOnce(ServerStream, &crate::p2p::Handler<'_>) -> Result<()>,
    ) -> Result<()> {
        self.serve_stream(sock, remote, HANDSHAKE_DEADLINE, run)
    }

    /// `serve` on any byte stream (a TCP connection, or a rendezvous relay
    /// session, `alpha-0-format.md` section 83.7): the same certificates,
    /// pins and request handler. The stream's reads must time out now and
    /// then (the handshake watches `deadline`, the connection loop its
    /// idle limits). `remote` names the other end in the log.
    pub(crate) fn serve_stream<S: Read + Write + ShutdownWrite>(
        &self,
        mut sock: S,
        remote: SocketAddr,
        deadline: Duration,
        run: impl FnOnce(
            rustls::StreamOwned<rustls::ServerConnection, S>,
            &crate::p2p::Handler<'_>,
        ) -> Result<()>,
    ) -> Result<()> {
        let mut conn = rustls::ServerConnection::new(self.config.clone())?;
        let started = Instant::now();
        while conn.is_handshaking() {
            if started.elapsed() > deadline {
                bail!("{remote}: TLS handshake took too long");
            }
            match conn.complete_io(&mut sock) {
                Ok(_) => {}
                Err(e) if is_timeout(&e) => {}
                Err(e) => {
                    sock.shutdown_write();
                    return Err(anyhow!("{remote}: TLS handshake failed: {e}"));
                }
            }
        }
        let cert = conn
            .peer_certificates()
            .and_then(|c| c.first())
            .map(|c| sha256(c));
        let exporter = conn
            .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(b""))
            .ok();
        let ci = ConnInfo {
            cert,
            exporter,
            registration: false,
        };
        let responder = self.responder.clone();
        let handler = move |snap: Option<&Snapshot>, path: &str, h: &RequestHeaders| {
            responder.handle(snap, &ci, path, &h.auth, &h.for_device)
        };
        run(rustls::StreamOwned::new(conn, sock), &handler)
    }
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// An error that is (or was caused by) a socket timeout.
fn timed_out(e: &anyhow::Error) -> bool {
    e.chain()
        .any(|c| c.downcast_ref::<std::io::Error>().is_some_and(is_timeout))
}

/// Ending the sending side of the byte stream under a TLS session, so that
/// what was written reaches the other end before the stream closes.
pub trait ShutdownWrite {
    fn shutdown_write(&mut self);
}

impl ShutdownWrite for TcpStream {
    fn shutdown_write(&mut self) {
        let _ = self.shutdown(std::net::Shutdown::Write);
    }
}

impl ShutdownWrite for crate::rendezvous::RelayStream {
    fn shutdown_write(&mut self) {
        self.shutdown();
    }
}

impl<S: Read + Write + ShutdownWrite> crate::p2p::CloseWrite
    for rustls::StreamOwned<rustls::ServerConnection, S>
{
    fn close_write(&mut self) {
        self.conn.send_close_notify();
        let _ = self.conn.complete_io(&mut self.sock);
        self.sock.shutdown_write();
    }
}

/// A client TLS configuration that pins `expected` (hex SHA-256) and
/// presents `identity`.
pub fn client_config(identity: &Identity, expected: &str) -> Result<Arc<rustls::ClientConfig>> {
    if expected.is_empty() {
        bail!("no certificate to pin: the device has no accepted peer record");
    }
    if expected == identity.sha256 {
        bail!("that certificate is this device's own");
    }
    let prov = quic::provider();
    let mut tls = rustls::ClientConfig::builder_with_provider(prov.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("tls versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServer {
            expected: expected.to_string(),
            algs: prov.signature_verification_algorithms,
        }))
        .with_client_auth_cert(
            vec![CertificateDer::from(identity.cert.clone())],
            PrivateKeyDer::Pkcs8(identity.key.clone().into()),
        )
        .context("p2p client certificate")?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(tls))
}

/// Connect to `addr`, run the handshake pinning `expected`, and return the
/// session with its exporter value.
pub fn connect(
    identity: &Identity,
    addr: SocketAddr,
    expected: &str,
    timeout: Duration,
) -> Result<(ClientStream, [u8; 32])> {
    let cfg = client_config(identity, expected)?;
    let mut sock = TcpStream::connect_timeout(&addr, timeout)?;
    sock.set_nodelay(true)?;
    // The handshake is a few round trips: a listener that accepted and
    // then says nothing does not hold us for the response timeout.
    sock.set_read_timeout(Some((timeout * 2).max(Duration::from_secs(3))))?;
    sock.set_write_timeout(Some(timeout))?;
    let name = ServerName::try_from("varsto").map_err(|e| anyhow!("server name: {e}"))?;
    let mut conn = rustls::ClientConnection::new(cfg, name)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)
            .with_context(|| format!("TLS handshake with {addr}"))?;
    }
    // Then each read of the answer may wait this long (an idle timeout per
    // chunk, not a deadline for the whole answer).
    sock.set_read_timeout(Some(RESPONSE_IDLE))?;
    let exp = conn
        .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(b""))
        .map_err(|e| anyhow!("TLS exporter: {e}"))?;
    Ok((rustls::StreamOwned::new(conn, sock), exp))
}

/// Run the client handshake pinning `expected` over a byte stream that is
/// open already (a rendezvous relay session, section 83.7), and return the
/// session with its exporter value. The stream's read timeout bounds each
/// step.
pub fn connect_stream<S: Read + Write>(
    identity: &Identity,
    mut sock: S,
    expected: &str,
) -> Result<(rustls::StreamOwned<rustls::ClientConnection, S>, [u8; 32])> {
    let cfg = client_config(identity, expected)?;
    let name = ServerName::try_from("varsto").map_err(|e| anyhow!("server name: {e}"))?;
    let mut conn = rustls::ClientConnection::new(cfg, name)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut sock)
            .context("TLS handshake over the rendezvous relay")?;
    }
    let exp = conn
        .export_keying_material([0u8; 32], EXPORTER_LABEL, Some(b""))
        .map_err(|e| anyhow!("TLS exporter: {e}"))?;
    Ok((rustls::StreamOwned::new(conn, sock), exp))
}

/// Each read of an answer over TLS may wait this long.
pub const RESPONSE_IDLE: Duration = Duration::from_secs(30);
/// The longest a connection attempt waits, however slow the link was.
pub const HANDSHAKE_MAX: Duration = Duration::from_secs(6);

/// How long to wait for a connection to a peer: `base` (the LAN figure),
/// or three times the time the last handshake with that host took, up to
/// `HANDSHAKE_MAX`. On a link with a long round trip one lost packet then
/// costs a retransmission instead of a failed attempt and a resting peer.
pub fn handshake_timeout(base: Duration, last: Option<Duration>) -> Duration {
    match last {
        Some(t) => (t * 3).clamp(base, HANDSHAKE_MAX.max(base)),
        None => base,
    }
}

/// Kept-alive TLS sessions to peers, per (address, pinned certificate).
#[derive(Default)]
pub struct TlsPool {
    idle: Mutex<BTreeMap<(SocketAddr, String), Vec<Kept>>>,
    /// How long the last handshake with each host took.
    handshakes: Mutex<BTreeMap<std::net::IpAddr, Duration>>,
}

/// An idle session: the stream, its exporter value, since when idle.
type Kept = (ClientStream, [u8; 32], Instant);

impl std::fmt::Debug for TlsPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsPool").finish_non_exhaustive()
    }
}

const POOL_IDLE: Duration = Duration::from_secs(20);
const POOL_PER_ADDR: usize = 32;

impl TlsPool {
    fn take(&self, key: &(SocketAddr, String)) -> Option<(ClientStream, [u8; 32])> {
        let mut idle = self.idle.lock().unwrap();
        let v = idle.get_mut(key)?;
        while let Some((s, e, at)) = v.pop() {
            if at.elapsed() < POOL_IDLE {
                return Some((s, e));
            }
        }
        None
    }

    fn give_back(&self, key: (SocketAddr, String), s: ClientStream, e: [u8; 32]) {
        let mut idle = self.idle.lock().unwrap();
        let v = idle.entry(key).or_default();
        v.retain(|(_, _, at)| at.elapsed() < POOL_IDLE);
        if v.len() < POOL_PER_ADDR {
            v.push((s, e, Instant::now()));
        }
    }

    /// GET `path` from the device at `addr` whose certificate is
    /// `expected`, on a kept session or a new one; `token` makes the
    /// request's token from the session's exporter value.
    pub fn get(
        &self,
        identity: &Identity,
        addr: SocketAddr,
        expected: &str,
        path: &str,
        timeout: Duration,
        token: &dyn Fn(&[u8; 32]) -> String,
    ) -> Result<(u16, Vec<u8>)> {
        let key = (addr, expected.to_string());
        let ask = |s: ClientStream, e: [u8; 32]| {
            let headers = format!("X-Varsto-Auth: {}\r\n", token(&e));
            crate::p2p::exchange(s, addr, path, &headers).map(|r| (r, e))
        };
        if let Some(Ok(((status, body, keep), e))) = self.take(&key).map(|(s, e)| ask(s, e)) {
            if let Some(s) = keep {
                self.give_back(key, s, e);
            }
            return Ok((status, body));
        }
        let last = self.handshakes.lock().unwrap().get(&addr.ip()).copied();
        let wait = handshake_timeout(timeout, last);
        let started = Instant::now();
        let (s, e) = match connect(identity, addr, expected, wait) {
            Ok(x) => x,
            // Beyond the LAN a timeout may be one lost packet: once more,
            // with twice the wait.
            Err(err) if timed_out(&err) && !crate::p2p::is_lan(addr.ip()) => {
                connect(identity, addr, expected, (wait * 2).min(HANDSHAKE_MAX))?
            }
            Err(err) => return Err(err),
        };
        self.handshakes
            .lock()
            .unwrap()
            .insert(addr.ip(), started.elapsed());
        let ((status, body, keep), e) = ask(s, e)?;
        if let Some(s) = keep {
            self.give_back(key, s, e);
        }
        Ok((status, body))
    }
}

/// A plain client that writes `request` and returns every byte the server
/// sends back before it closes (tests: what a client without TLS sees).
pub fn plain_probe(addr: SocketAddr, request: &[u8]) -> Result<Vec<u8>> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    s.set_read_timeout(Some(Duration::from_secs(8)))?;
    s.write_all(request)?;
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    Ok(out)
}
