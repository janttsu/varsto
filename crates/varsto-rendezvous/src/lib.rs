// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The Varsto rendezvous service (`docs/spec/alpha-0-format.md` section 83,
//! `docs/rendezvous.md`): where devices of a vault find each other across
//! networks, coordinate UDP hole punching and, as the last route, relay
//! their end-to-end TLS sessions.
//!
//! Everything is in memory with TTLs: no database, no accounts, no logs of
//! tags or addresses. The server learns tags, IP addresses, timing and byte
//! counts; never vault ids, device ids, names, keys or content.
//!
//! - [`registry`]: tags → slots → blob, owner key, expiry.
//! - [`control`]: the control hub (claims, punch, relay requests).
//! - [`udp`]: observe datagrams.
//! - [`relay`]: relay tokens and the splicer.
//! - [`limits`]: rate limits.
//! - [`http`]: the axum front (HTTP + WebSocket) and the UDP loop.

#[path = "../../varsto-core/src/rendezvous/proto.rs"]
pub mod proto;

pub mod control;
pub mod http;
pub mod limits;
pub mod registry;
pub mod relay;
pub mod selftest;
pub mod udp;

use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::sync::Arc;

/// Everything the server is started with.
#[derive(Clone, Debug)]
pub struct Config {
    /// HTTP and WebSocket listener (behind Caddy: `127.0.0.1:<port>`).
    pub listen: SocketAddr,
    /// UDP observe socket; `None` runs without one (no punch coordination).
    pub udp: Option<SocketAddr>,
    /// UDP endpoints announced in `/info` (`host:port`). Empty: the bound
    /// UDP address, which is right only when it is public (tests, a
    /// server without NAT).
    pub public_udp: Vec<String>,
    /// Announced limits; `relay_rate`, `relay_idle`, `relay_per_tag` are
    /// also enforced from here.
    pub limits: proto::Limits,
    pub rates: limits::RateConfig,
    /// Take the client address from the last `X-Forwarded-For` entry when
    /// the connection comes from a loopback address (Caddy on the same
    /// host).
    pub trust_proxy: bool,
    /// Whether relay sessions are offered.
    pub relay: bool,
    /// Memory bounds of the registry.
    pub max_slots: usize,
    pub max_bytes: usize,
    /// Most control connections at once, and per client address.
    pub max_controls: usize,
    pub max_controls_per_ip: usize,
    /// Most relay sessions at once.
    pub max_relays: usize,
    /// Bytes per second all relay sessions together may move (0: no cap).
    pub relay_total_rate: u64,
    /// Relay bytes one tag may move per `relay_tag_window` (0: no cap).
    pub relay_tag_bytes: u64,
    pub relay_tag_window: std::time::Duration,
    /// A control connection that lets this many messages drop because it
    /// does not read them is closed.
    pub control_drop_max: u32,
    /// How often the server pings a control connection (proxies close
    /// connections that stay silent).
    pub control_ping: std::time::Duration,
    /// How long open connections get to finish on shutdown.
    pub grace: std::time::Duration,
    /// How often the totals are logged at info level (zero: never).
    pub stats_every: std::time::Duration,
    /// How often expired slots, relay tokens and rate buckets are swept.
    pub sweep_every: std::time::Duration,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            listen: ([127, 0, 0, 1], 8790).into(),
            udp: Some(([0, 0, 0, 0], proto::DEFAULT_UDP_PORT).into()),
            public_udp: Vec::new(),
            limits: proto::Limits::default(),
            rates: limits::RateConfig::default(),
            trust_proxy: true,
            relay: true,
            max_slots: 200_000,
            max_bytes: 1 << 30,
            max_controls: 50_000,
            max_controls_per_ip: 32,
            max_relays: 1_000,
            relay_total_rate: 32 << 20,
            relay_tag_bytes: 4 << 30,
            relay_tag_window: std::time::Duration::from_secs(3600),
            control_drop_max: 16,
            control_ping: std::time::Duration::from_secs(30),
            grace: std::time::Duration::from_secs(5),
            stats_every: std::time::Duration::from_secs(600),
            sweep_every: std::time::Duration::from_secs(30),
        }
    }
}

/// A running server.
pub struct Handle {
    pub http: SocketAddr,
    pub udp: Option<SocketAddr>,
    pub shared: Arc<http::Shared>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for Handle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Handle")
            .field("http", &self.http)
            .field("udp", &self.udp)
            .finish_non_exhaustive()
    }
}

impl Handle {
    /// Stop the server and wait for its thread.
    pub fn stop(mut self) {
        self.stop_inner();
    }

    fn stop_inner(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.stop_inner();
    }
}

/// Entry points.
pub struct Server;

impl Server {
    /// Start a server on a thread with its own runtime.
    pub fn spawn(cfg: Config) -> Result<Handle> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("rendezvous".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = ready_tx.send(Err(anyhow::Error::from(e)));
                        return;
                    }
                };
                rt.block_on(async move {
                    match http::bind(cfg).await {
                        Ok(bound) => {
                            let _ = ready_tx.send(Ok((
                                bound.http_addr,
                                bound.udp_addr,
                                bound.shared.clone(),
                            )));
                            bound
                                .run(async {
                                    let _ = stop_rx.await;
                                })
                                .await;
                        }
                        Err(e) => {
                            let _ = ready_tx.send(Err(e));
                        }
                    }
                });
            })
            .context("start the server thread")?;
        let (http, udp, shared) = ready_rx.recv().context("server thread")??;
        Ok(Handle {
            http,
            udp,
            shared,
            stop: Some(stop_tx),
            thread: Some(thread),
        })
    }

    /// A server on loopback with free ports and no rate limits: its base
    /// URL (`http://127.0.0.1:<port>`), its UDP address and the handle.
    pub fn spawn_for_tests() -> (String, SocketAddr, Handle) {
        Self::spawn_for_tests_with(|_| {})
    }

    /// `spawn_for_tests` with the configuration adjusted by `f`.
    pub fn spawn_for_tests_with(f: impl FnOnce(&mut Config)) -> (String, SocketAddr, Handle) {
        let mut cfg = Config {
            listen: ([127, 0, 0, 1], 0).into(),
            udp: Some(([127, 0, 0, 1], 0).into()),
            rates: limits::RateConfig::unlimited(),
            ..Config::default()
        };
        f(&mut cfg);
        let h = Self::spawn(cfg).expect("test rendezvous server");
        let url = format!("http://{}", h.http);
        let udp = h.udp.expect("udp socket");
        (url, udp, h)
    }
}
