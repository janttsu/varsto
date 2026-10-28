// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The client side of the rendezvous service (spec 83): HTTP calls, the
//! control WebSocket and the relay stream, all blocking.
//!
//! Blocking on purpose: the peer transport it carries (TLS 1.3 over a
//! stream, `p2p::v3::tls`) and the pairing exchange (`pair::v3`) are
//! blocking code on threads, and HTTP elsewhere in the core is `ureq` 3.
//! The control channel is one thread of its own in the service; a relay
//! stream is used by the thread that fetches over it. The WebSocket is
//! `tungstenite` (the same version `axum` uses on the server, so one copy in
//! the lock file) without its TLS features: TLS is the core's own `rustls`
//! with the ring provider and the `webpki-roots` that `ureq` already uses.
//!
//! Every call has a short timeout and is meant to run in the background:
//! a failure is logged by the caller and never stops LAN, direct or
//! storage paths (the offline-first rule, spec 79).

use super::proto::{
    self, Claim, DeleteSlot, ErrorAnswer, ErrorCode, Info, Lookup, LookupAnswer, PutAnswer,
    PutSlot, SlotEntry, Tag, ToClient, ToServer, Token,
};
use anyhow::{anyhow, bail, Context, Result};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Connect, resolve and first-byte timeout of every HTTP call.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(5);
/// Whole-call limit of an HTTP call.
pub const HTTP_CALL_LIMIT: Duration = Duration::from_secs(15);
/// How long `/info` is kept.
pub const INFO_MAX_AGE: Duration = Duration::from_secs(3600);
/// How long a WebSocket connect (TCP, TLS and upgrade) may take.
pub const WS_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

/// An error answer of the server, or a transport failure.
#[derive(Debug, thiserror::Error)]
pub enum RvError {
    /// The server refused the request.
    #[error("rendezvous refused: {code}{}", if .message.is_empty() { String::new() } else { format!(" ({})", .message) })]
    Refused { code: ErrorCode, message: String },
    /// No answer, a broken connection, an answer that does not parse.
    #[error("rendezvous not reached: {0:#}")]
    Transport(anyhow::Error),
}

impl RvError {
    /// The server's refusal code, if it was one.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            RvError::Refused { code, .. } => Some(*code),
            RvError::Transport(_) => None,
        }
    }
}

/// A parsed base URL: `https://host[:port][/prefix]` or, for tests and
/// self-hosting on one machine, `http://` to a loopback address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseUrl {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    /// The path prefix without a trailing slash (`/rv`, or empty).
    pub prefix: String,
}

impl BaseUrl {
    /// Parse and check a configured URL. Plain `http://` is allowed only to
    /// a loopback or private address (a lab, a server on the same LAN): the
    /// tags and blobs are no secret from the server, but a third party on
    /// the path should not see them either.
    pub fn parse(url: &str) -> Result<BaseUrl> {
        let url = url.trim();
        let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            bail!("a rendezvous URL starts with https://");
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.is_empty() || authority.contains('@') {
            bail!("a rendezvous URL needs a host and no login");
        }
        if path.contains(['?', '#']) {
            bail!("a rendezvous URL has no query or fragment");
        }
        let (host, port) = split_host_port(authority, if tls { 443 } else { 80 })?;
        if !tls {
            let local = host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback() || crate::p2p::is_lan(ip))
                .unwrap_or(host == "localhost");
            if !local {
                bail!("plain http:// is allowed only to a loopback or LAN address; use https://");
            }
        }
        Ok(BaseUrl {
            tls,
            host,
            port,
            prefix: path.trim_end_matches('/').to_string(),
        })
    }

    /// `scheme://host:port<prefix><path>` for HTTP.
    pub fn http(&self, path: &str) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!(
            "{scheme}://{}:{}{}{path}",
            self.host, self.port, self.prefix
        )
    }

    /// The same for the WebSocket (`wss`/`ws`).
    pub fn ws(&self, path: &str) -> String {
        let scheme = if self.tls { "wss" } else { "ws" };
        format!(
            "{scheme}://{}:{}{}{path}",
            self.host, self.port, self.prefix
        )
    }
}

fn split_host_port(authority: &str, default: u16) -> Result<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            bail!("unclosed IPv6 address");
        };
        let host = format!("[{}]", &rest[..end]);
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().context("port")?,
            None if after.is_empty() => default,
            None => bail!("junk after the address"),
        };
        return Ok((host, port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => Ok((h.to_string(), p.parse().context("port")?)),
        None => Ok((authority.to_string(), default)),
    }
}

/// The HTTP side: info, put, delete, lookup, health.
pub struct RvClient {
    base: BaseUrl,
    agent: ureq::Agent,
    info: Mutex<Option<(Info, Instant)>>,
}

impl std::fmt::Debug for RvClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RvClient")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl RvClient {
    pub fn new(url: &str) -> Result<Arc<RvClient>> {
        let base = BaseUrl::parse(url)?;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_resolve(Some(HTTP_TIMEOUT))
            .timeout_connect(Some(HTTP_TIMEOUT))
            .timeout_recv_response(Some(HTTP_TIMEOUT))
            .timeout_global(Some(HTTP_CALL_LIMIT))
            .user_agent(concat!("varsto/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Ok(Arc::new(RvClient {
            base,
            agent,
            info: Mutex::new(None),
        }))
    }

    pub fn base(&self) -> &BaseUrl {
        &self.base
    }

    fn post<T: serde::Serialize, A: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<A, RvError> {
        let text = serde_json::to_vec(body).map_err(|e| RvError::Transport(e.into()))?;
        let resp = self
            .agent
            .post(&self.base.http(path))
            .header("Content-Type", "application/json")
            .send(&text[..])
            .map_err(|e| RvError::Transport(e.into()))?;
        answer(resp)
    }

    /// `GET /info`, kept for an hour.
    pub fn info(&self) -> Result<Info, RvError> {
        if let Some((i, at)) = self.info.lock().unwrap().as_ref() {
            if at.elapsed() < INFO_MAX_AGE {
                return Ok(i.clone());
            }
        }
        let resp = self
            .agent
            .get(&self.base.http(proto::PATH_INFO))
            .call()
            .map_err(|e| RvError::Transport(e.into()))?;
        let info: Info = answer(resp)?;
        if info.v != proto::VERSION {
            return Err(RvError::Refused {
                code: ErrorCode::Version,
                message: format!("server speaks version {}", info.v),
            });
        }
        *self.info.lock().unwrap() = Some((info.clone(), Instant::now()));
        Ok(info)
    }

    /// Forget the cached info (after the server answered `version`, or the
    /// URL changed).
    pub fn forget_info(&self) {
        *self.info.lock().unwrap() = None;
    }

    /// The server's UDP observe endpoints from `/info`, resolved (IPv4
    /// first: the QUIC socket is IPv4). A name that does not resolve is
    /// skipped.
    pub fn udp_addrs(&self) -> Result<Vec<SocketAddr>, RvError> {
        let info = self.info()?;
        let mut out: Vec<SocketAddr> = Vec::new();
        for e in &info.udp {
            let resolved = crate::p2p::stun::resolve_within(e, false, HTTP_TIMEOUT);
            for a in resolved {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
        out.sort_by_key(|a| !a.is_ipv4());
        Ok(out)
    }

    /// `POST /v1/put`.
    pub fn put(&self, req: &PutSlot) -> Result<PutAnswer, RvError> {
        self.post(proto::PATH_PUT, req)
    }

    /// `POST /v1/delete`.
    pub fn delete(&self, req: &DeleteSlot) -> Result<(), RvError> {
        let _: serde_json::Value = self.post(proto::PATH_DELETE, req)?;
        Ok(())
    }

    /// `POST /v1/lookup`: every live slot of `tag` (empty for an unknown
    /// tag).
    pub fn lookup(&self, tag: &Tag) -> Result<Vec<SlotEntry>, RvError> {
        let a: LookupAnswer = self.post(proto::PATH_LOOKUP, &Lookup::new(*tag))?;
        Ok(a.slots)
    }

    /// `GET /health`: the counters line.
    pub fn health(&self) -> Result<proto::Health, RvError> {
        let mut resp = self
            .agent
            .get(&self.base.http(proto::PATH_HEALTH))
            .call()
            .map_err(|e| RvError::Transport(e.into()))?;
        let text = resp
            .body_mut()
            .with_config()
            .limit(4096)
            .read_to_string()
            .map_err(|e| RvError::Transport(e.into()))?;
        proto::Health::parse(text.trim())
            .ok_or_else(|| RvError::Transport(anyhow!("health line does not parse")))
    }
}

fn answer<A: serde::de::DeserializeOwned>(
    mut resp: ureq::http::Response<ureq::Body>,
) -> Result<A, RvError> {
    let status = resp.status().as_u16();
    let bytes = resp
        .body_mut()
        .with_config()
        .limit(2 * proto::MAX_BODY as u64)
        .read_to_vec()
        .map_err(|e| RvError::Transport(e.into()))?;
    if status == 200 {
        return serde_json::from_slice(&bytes).map_err(|e| RvError::Transport(e.into()));
    }
    match serde_json::from_slice::<ErrorAnswer>(&bytes) {
        Ok(e) => Err(RvError::Refused {
            code: e.error,
            message: e.message,
        }),
        Err(_) => Err(RvError::Transport(anyhow!("HTTP {status}"))),
    }
}

// ---------------------------------------------------------------------------
// WebSocket transport.

/// The byte stream under a WebSocket: TLS to the server, or plain TCP to a
/// loopback/LAN server.
pub enum Conn {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Conn {
    fn tcp(&self) -> &TcpStream {
        match self {
            Conn::Plain(s) => s,
            Conn::Tls(s) => &s.sock,
        }
    }
    /// Set the read timeout of the socket under the stream.
    pub fn set_read_timeout(&self, t: Option<Duration>) -> std::io::Result<()> {
        self.tcp().set_read_timeout(t)
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.read(buf),
            Conn::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Conn::Plain(s) => s.write(buf),
            Conn::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Conn::Plain(s) => s.flush(),
            Conn::Tls(s) => s.flush(),
        }
    }
}

/// The TLS client configuration for the server: webpki roots, TLS 1.2
/// and 1.3, ring.
fn tls_config() -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("tls versions")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Open a WebSocket to `path` of the server.
pub fn ws_connect(base: &BaseUrl, path: &str) -> Result<tungstenite::WebSocket<Conn>> {
    let host = base.host.trim_matches(['[', ']']).to_string();
    let addrs: Vec<SocketAddr> = (host.as_str(), base.port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {}", base.host))?
        .collect();
    let started = Instant::now();
    let mut last = None;
    let mut tcp = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, WS_CONNECT_TIMEOUT) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let tcp = match (tcp, last) {
        (Some(t), _) => t,
        (None, Some(e)) => return Err(e).context("connect to the rendezvous"),
        (None, None) => bail!("{} has no address", base.host),
    };
    tcp.set_nodelay(true)?;
    tcp.set_read_timeout(Some(WS_CONNECT_TIMEOUT))?;
    tcp.set_write_timeout(Some(WS_CONNECT_TIMEOUT))?;
    let conn = if base.tls {
        let name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| anyhow!("server name: {e}"))?;
        let c = rustls::ClientConnection::new(tls_config()?, name)?;
        Conn::Tls(Box::new(rustls::StreamOwned::new(c, tcp)))
    } else {
        Conn::Plain(tcp)
    };
    let url = base.ws(path);
    let (ws, resp) = tungstenite::client::client(url.as_str(), conn)
        .map_err(|e| anyhow!("websocket upgrade at {path}: {e}"))?;
    if started.elapsed() > WS_CONNECT_TIMEOUT * 2 {
        bail!("websocket connect took too long");
    }
    log::debug!("rendezvous websocket {path}: {}", resp.status());
    Ok(ws)
}

fn is_timeout(e: &tungstenite::Error) -> bool {
    matches!(e, tungstenite::Error::Io(io) if matches!(io.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut))
}

// ---------------------------------------------------------------------------
// Control channel.

/// The answer to `hello`/`claim`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Welcome {
    pub udp_token: Token,
    pub claimed: Vec<(Tag, proto::Slot)>,
}

/// One control connection (`/v1/control`). Not thread-safe: the service
/// keeps it on a thread of its own, pings every 25 s and forwards the
/// server's messages (spec 83.6).
pub struct Control {
    ws: tungstenite::WebSocket<Conn>,
    challenge: [u8; 32],
    server_time: u64,
}

impl std::fmt::Debug for Control {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Control").finish_non_exhaustive()
    }
}

impl Control {
    /// Connect and read the server's challenge.
    pub fn open(base: &BaseUrl) -> Result<Control> {
        let mut ws = ws_connect(base, proto::PATH_CONTROL)?;
        let first = read_text(&mut ws)?;
        match proto::parse_to_client(&first).map_err(|e| anyhow!("challenge: {e}"))? {
            ToClient::Challenge { v, nonce, time } if v == proto::VERSION => Ok(Control {
                ws,
                challenge: nonce.0,
                server_time: time,
            }),
            ToClient::Challenge { v, .. } => bail!("server speaks version {v}"),
            other => bail!("expected a challenge, got {other:?}"),
        }
    }

    /// The nonce claims are signed over.
    pub fn challenge(&self) -> &[u8; 32] {
        &self.challenge
    }

    /// The server's clock at connect time.
    pub fn server_time(&self) -> u64 {
        self.server_time
    }

    /// A claim of (`tag`, `slot`) with its owner key, for this connection.
    pub fn claim(&self, tag: Tag, slot: proto::Slot, owner: &ed25519_dalek::SigningKey) -> Claim {
        Claim::sign(&self.challenge, tag, slot, owner)
    }

    /// Send `hello` and wait (up to `timeout`) for `welcome`; messages of
    /// another kind that arrive meanwhile are returned in `early`.
    pub fn hello(&mut self, claims: Vec<Claim>, timeout: Duration) -> Result<Welcome> {
        self.send(&ToServer::Hello {
            v: proto::VERSION,
            claims,
        })?;
        self.wait_welcome(timeout)
    }

    /// Send further claims and wait for the new `welcome`.
    pub fn add_claims(&mut self, claims: Vec<Claim>, timeout: Duration) -> Result<Welcome> {
        self.send(&ToServer::Claim { claims })?;
        self.wait_welcome(timeout)
    }

    fn wait_welcome(&mut self, timeout: Duration) -> Result<Welcome> {
        let until = Instant::now() + timeout;
        while Instant::now() < until {
            match self.recv(until.saturating_duration_since(Instant::now()))? {
                Some(ToClient::Welcome { udp_token, claimed }) => {
                    return Ok(Welcome {
                        udp_token: udp_token.0,
                        claimed: claimed.into_iter().map(|(t, s)| (t.0, s.0)).collect(),
                    })
                }
                Some(ToClient::Error { error, message, .. }) => {
                    return Err(RvError::Refused {
                        code: error,
                        message,
                    }
                    .into())
                }
                Some(_) | None => {}
            }
        }
        bail!("no welcome from the rendezvous")
    }

    /// Send one message.
    pub fn send(&mut self, m: &ToServer) -> Result<()> {
        let text = serde_json::to_string(m)?;
        self.ws
            .send(tungstenite::Message::text(text))
            .map_err(|e| anyhow!("control send: {e}"))
    }

    /// The next server message, waiting at most `timeout`; `None` when the
    /// time ran out. A closed connection is an error.
    pub fn recv(&mut self, timeout: Duration) -> Result<Option<ToClient>> {
        self.ws
            .get_ref()
            .set_read_timeout(Some(timeout.max(Duration::from_millis(10))))?;
        loop {
            match self.ws.read() {
                Ok(tungstenite::Message::Text(t)) => {
                    return proto::parse_to_client(t.as_str())
                        .map(Some)
                        .map_err(|e| anyhow!("control message: {e}"))
                }
                Ok(tungstenite::Message::Close(_)) => {
                    bail!("the rendezvous closed the control channel")
                }
                Ok(_) => continue,
                Err(e) if is_timeout(&e) => {
                    // Answer pings that tungstenite queued.
                    let _ = self.ws.flush();
                    return Ok(None);
                }
                Err(e) => bail!("control channel: {e}"),
            }
        }
    }

    /// Close politely.
    pub fn close(mut self) {
        let _ = self.ws.close(None);
        let _ = self.ws.flush();
    }
}

fn read_text(ws: &mut tungstenite::WebSocket<Conn>) -> Result<String> {
    loop {
        match ws.read().map_err(|e| anyhow!("websocket read: {e}"))? {
            tungstenite::Message::Text(t) => return Ok(t.as_str().to_string()),
            tungstenite::Message::Close(_) => bail!("closed"),
            _ => continue,
        }
    }
}

// ---------------------------------------------------------------------------
// Relay stream.

/// One side of a relay session as a byte stream (`Read + Write`): the
/// pinned peer TLS session (`p2p::v3::tls`) or the pairing exchange runs on
/// it unchanged. Each write is one binary frame of at most
/// [`proto::MAX_RELAY_FRAME`] bytes.
pub struct RelayStream {
    ws: tungstenite::WebSocket<Conn>,
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl std::fmt::Debug for RelayStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayStream").finish_non_exhaustive()
    }
}

impl RelayStream {
    /// Open `/v1/relay/<token>`. The server holds the stream until the
    /// other side arrives (at most [`proto::RELAY_JOIN_SECS`]) and then
    /// splices the two.
    pub fn open(base: &BaseUrl, token: &Token) -> Result<RelayStream> {
        let ws = ws_connect(base, &proto::relay_path(token))?;
        ws.get_ref()
            .set_read_timeout(Some(Duration::from_secs(proto::RELAY_JOIN_SECS + 15)))?;
        Ok(RelayStream {
            ws,
            buf: Vec::new(),
            pos: 0,
            eof: false,
        })
    }

    /// The read timeout of the stream (an idle limit per read).
    pub fn set_read_timeout(&self, t: Option<Duration>) -> std::io::Result<()> {
        self.ws.get_ref().set_read_timeout(t)
    }

    /// End the session.
    pub fn close(mut self) {
        let _ = self.ws.close(None);
        let _ = self.ws.flush();
    }
}

fn io_err(e: tungstenite::Error) -> std::io::Error {
    match e {
        tungstenite::Error::Io(io) => io,
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
            std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "relay closed")
        }
        other => std::io::Error::other(other.to_string()),
    }
}

impl Read for RelayStream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.pos >= self.buf.len() {
            if self.eof {
                return Ok(0);
            }
            match self.ws.read() {
                Ok(tungstenite::Message::Binary(b)) => {
                    self.buf = b.to_vec();
                    self.pos = 0;
                }
                Ok(tungstenite::Message::Close(_)) => {
                    self.eof = true;
                }
                Ok(_) => {}
                Err(tungstenite::Error::ConnectionClosed) => self.eof = true,
                Err(e) => return Err(io_err(e)),
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Write for RelayStream {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let n = data.len().min(proto::MAX_RELAY_FRAME);
        self.ws
            .send(tungstenite::Message::binary(data[..n].to_vec()))
            .map_err(io_err)?;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.ws.flush().map_err(io_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_urls_parse_with_and_without_a_prefix() {
        let b = BaseUrl::parse("https://varsto.net/rv").unwrap();
        assert_eq!(
            b,
            BaseUrl {
                tls: true,
                host: "varsto.net".into(),
                port: 443,
                prefix: "/rv".into()
            }
        );
        assert_eq!(b.http(proto::PATH_INFO), "https://varsto.net:443/rv/info");
        assert_eq!(
            b.ws(proto::PATH_CONTROL),
            "wss://varsto.net:443/rv/v1/control"
        );
        let l = BaseUrl::parse("http://127.0.0.1:8080/").unwrap();
        assert_eq!(l.prefix, "");
        assert_eq!(l.http(proto::PATH_PUT), "http://127.0.0.1:8080/v1/put");
        let v6 = BaseUrl::parse("https://[2001:db8::1]:8443/x").unwrap();
        assert_eq!(v6.host, "[2001:db8::1]");
        assert_eq!(v6.port, 8443);
        assert!(
            BaseUrl::parse("http://rv.example.org").is_err(),
            "plain http to the internet"
        );
        assert!(BaseUrl::parse("ftp://x").is_err());
        assert!(BaseUrl::parse("https://u:p@rv.example.org").is_err());
        assert!(BaseUrl::parse("https://rv.example.org/?a=1").is_err());
        assert!(BaseUrl::parse("http://localhost:9/").is_ok());
        assert!(BaseUrl::parse("http://192.168.1.5:9").is_ok());
    }
}
