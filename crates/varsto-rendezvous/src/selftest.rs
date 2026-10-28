// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto-rendezvous --self-test`: the binary starts a server of its own on
//! loopback and plays two devices against it over real sockets: register,
//! lookup, a refused overwrite, UDP observe, the control channel with
//! claims, a relay session with bytes both ways, `/health`. It proves that
//! the binary you are about to deploy works on this machine (static
//! linking, sockets, the clock); it says nothing about your proxy or
//! firewall (see `docs/rendezvous.md`, "Checking it").
//!
//! The helpers ([`Ctl`], [`http`], [`relay_open`]) are public so the load
//! tests can use them.

use crate::proto::{
    self, Claim, ErrorAnswer, ErrorCode, Health, Hex, Info, Kind, Lookup, LookupAnswer, PutSlot,
    Slot, Tag, ToClient, ToServer, Token,
};
use crate::{limits::RateConfig, Config, Server};
use anyhow::{bail, ensure, Context, Result};
use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One plain HTTP/1.1 request (`Connection: close`): status and body.
pub async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<(u16, String)> {
    let mut s = TcpStream::connect(addr).await?;
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(body).await?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").context("no HTTP header")?;
    let status: u16 = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .context("no HTTP status")?;
    Ok((status, body.to_string()))
}

/// POST a JSON value.
pub async fn post<T: serde::Serialize>(
    addr: SocketAddr,
    path: &str,
    v: &T,
) -> Result<(u16, String)> {
    http(addr, "POST", path, &serde_json::to_vec(v)?).await
}

/// A control connection speaking the protocol.
pub struct Ctl {
    ws: WebSocketStream<TcpStream>,
    pub challenge: [u8; 32],
    pub udp_token: Token,
}

impl Ctl {
    /// Connect and read the challenge.
    pub async fn connect(addr: SocketAddr) -> Result<Ctl> {
        let tcp = TcpStream::connect(addr).await?;
        let (ws, _) =
            tokio_tungstenite::client_async(format!("ws://{addr}{}", proto::PATH_CONTROL), tcp)
                .await?;
        let mut c = Ctl {
            ws,
            challenge: [0; 32],
            udp_token: [0; 16],
        };
        match c.recv().await? {
            ToClient::Challenge { nonce, .. } => c.challenge = nonce.0,
            other => bail!("expected a challenge, got {other:?}"),
        }
        Ok(c)
    }

    pub async fn send(&mut self, m: &ToServer) -> Result<()> {
        self.ws
            .send(Message::text(serde_json::to_string(m)?))
            .await?;
        Ok(())
    }

    /// The next control message (pings are answered by the library).
    pub async fn recv(&mut self) -> Result<ToClient> {
        loop {
            match self.ws.next().await.context("connection closed")?? {
                Message::Text(t) => {
                    return proto::parse_to_client(t.as_str())
                        .map_err(|e| anyhow::anyhow!("bad message: {e:?}"))
                }
                Message::Close(_) => bail!("closed by the server"),
                _ => {}
            }
        }
    }

    /// `hello` with the given claims: the server's `welcome` (UDP token).
    pub async fn hello(&mut self, claims: Vec<(Tag, Slot, &SigningKey)>) -> Result<usize> {
        let claims = claims
            .into_iter()
            .map(|(t, s, k)| Claim::sign(&self.challenge, t, s, k))
            .collect();
        self.send(&ToServer::Hello { v: 1, claims }).await?;
        match self.recv().await? {
            ToClient::Welcome { udp_token, claimed } => {
                self.udp_token = udp_token.0;
                Ok(claimed.len())
            }
            other => bail!("expected a welcome, got {other:?}"),
        }
    }

    pub async fn close(mut self) {
        let _ = self.ws.close(None).await;
    }
}

/// Open a relay stream for `token`.
pub async fn relay_open(addr: SocketAddr, token: &Token) -> Result<WebSocketStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await?;
    let (ws, _) =
        tokio_tungstenite::client_async(format!("ws://{addr}{}", proto::relay_path(token)), tcp)
            .await?;
    Ok(ws)
}

/// Receive the next binary frame.
pub async fn recv_binary(ws: &mut WebSocketStream<TcpStream>) -> Result<Vec<u8>> {
    loop {
        match ws.next().await.context("relay closed")?? {
            Message::Binary(b) => return Ok(b.to_vec()),
            Message::Close(_) => bail!("relay closed"),
            _ => {}
        }
    }
}

/// Run the self-test: the names of the steps that passed.
pub fn run() -> Result<Vec<String>> {
    let cfg = Config {
        listen: ([127, 0, 0, 1], 0).into(),
        udp: Some(([127, 0, 0, 1], 0).into()),
        rates: RateConfig::unlimited(),
        grace: Duration::from_secs(1),
        ..Config::default()
    };
    let handle = Server::spawn(cfg).context("start a server on loopback")?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let http = handle.http;
    let udp = handle.udp.context("no UDP socket")?;
    let steps = rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(30), steps(http, udp))
            .await
            .context("the self-test took more than 30 seconds")?
    });
    handle.stop();
    steps
}

async fn steps(http_addr: SocketAddr, udp: SocketAddr) -> Result<Vec<String>> {
    let mut done = Vec::new();
    let tag: Tag = proto::random_token();
    let (s1, s2): (Slot, Slot) = (proto::random_token(), proto::random_token());
    let k1 = SigningKey::from_bytes(&rand_bytes());
    let k2 = SigningKey::from_bytes(&rand_bytes());

    // Info.
    let (st, body) = http(http_addr, "GET", "/info", b"").await?;
    ensure!(st == 200, "/info answered {st}");
    let info: Info = serde_json::from_str(&body)?;
    ensure!(info.v == proto::VERSION, "protocol version {}", info.v);
    ensure!(
        info.udp == vec![udp.to_string()],
        "udp endpoint {:?}",
        info.udp
    );
    ensure!(info.relay, "the relay is off");
    ensure!(now().abs_diff(info.time) < 5, "clock differs");
    done.push("info".to_string());

    // Register two devices, look them up, refuse a stranger's overwrite.
    for (k, slot) in [(&k1, s1), (&k2, s2)] {
        let p = PutSlot::sign(Kind::Peer, tag, slot, k, now(), 600, vec![slot[0]; 64]);
        let (st, body) = post(http_addr, proto::PATH_PUT, &p).await?;
        ensure!(st == 200, "put answered {st}: {body}");
    }
    let (st, body) = post(http_addr, proto::PATH_LOOKUP, &Lookup::new(tag)).await?;
    ensure!(st == 200, "lookup answered {st}");
    let l: LookupAnswer = serde_json::from_str(&body)?;
    ensure!(l.slots.len() == 2, "lookup found {} slots", l.slots.len());
    let steal = PutSlot::sign(Kind::Peer, tag, s1, &k2, now() + 1, 600, vec![0; 8]);
    let (st, body) = post(http_addr, proto::PATH_PUT, &steal).await?;
    ensure!(st == 403, "an overwrite by another key answered {st}");
    ensure!(
        serde_json::from_str::<ErrorAnswer>(&body)?.error == ErrorCode::NotOwner,
        "wrong refusal"
    );
    done.push("register and lookup".to_string());

    // Observe.
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    sock.send_to(&proto::encode_observe(&[9; 12], None), udp)
        .await?;
    let mut buf = [0u8; 128];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .context("no observe answer")??;
    ensure!(
        proto::parse_observed(&buf[..n], &[9; 12]) == Some(sock.local_addr()?),
        "observed address is wrong"
    );
    done.push("observe".to_string());

    // Control channel and relay.
    let mut a = Ctl::connect(http_addr).await?;
    let mut b = Ctl::connect(http_addr).await?;
    ensure!(a.hello(vec![(tag, s1, &k1)]).await? == 1, "claim refused");
    ensure!(b.hello(vec![(tag, s2, &k2)]).await? == 1, "claim refused");
    done.push("control and claims".to_string());
    a.send(&ToServer::Relay {
        id: 1,
        tag: Hex(tag),
        slot: Hex(s2),
    })
    .await?;
    let ToClient::RelayReady { token: ta, .. } = a.recv().await? else {
        bail!("no relay_ready");
    };
    let ToClient::RelayOffer { token: tb, .. } = b.recv().await? else {
        bail!("no relay_offer");
    };
    let mut ra = relay_open(http_addr, &ta.0).await?;
    let mut rb = relay_open(http_addr, &tb.0).await?;
    ra.send(Message::binary(b"hello from a".to_vec())).await?;
    ensure!(recv_binary(&mut rb).await? == b"hello from a", "a to b");
    let big = vec![0x5a; 100_000];
    for chunk in big.chunks(16 * 1024) {
        rb.send(Message::binary(chunk.to_vec())).await?;
    }
    let mut got = Vec::new();
    while got.len() < big.len() {
        got.extend(recv_binary(&mut ra).await?);
    }
    ensure!(got == big, "b to a");
    done.push("relay".to_string());

    // Health: totals only.
    let (st, body) = http(http_addr, "GET", "/health", b"").await?;
    ensure!(st == 200, "/health answered {st}");
    let h = Health::parse(body.trim()).context("unreadable /health")?;
    ensure!(h.slots == 2 && h.controls == 2 && h.relays == 1, "{body}");
    ensure!(h.relay_bytes >= 100_012, "relay bytes {}", h.relay_bytes);
    ensure!(!body.contains(&hex::encode(tag)), "health names a tag");
    done.push("health".to_string());

    let _ = ra.close(None).await;
    let _ = rb.close(None).await;
    a.close().await;
    b.close().await;
    Ok(done)
}

fn rand_bytes() -> [u8; 32] {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_self_test_passes() {
        let steps = super::run().unwrap();
        assert_eq!(steps.len(), 6, "{steps:?}");
    }
}
