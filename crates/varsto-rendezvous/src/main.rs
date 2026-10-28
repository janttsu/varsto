// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto-rendezvous`: the rendezvous server (docs/rendezvous.md).

use clap::Parser;
use std::net::SocketAddr;
use varsto_rendezvous::{http, limits::RateConfig, proto, Config};

/// The Varsto rendezvous service: devices of a vault find each other
/// across networks, punch through NATs and, as the last route, relay their
/// end-to-end encrypted sessions. Everything is kept in memory.
#[derive(Parser, Debug)]
#[command(name = "varsto-rendezvous", version)]
struct Args {
    /// HTTP and WebSocket listener (put Caddy or another TLS proxy in front).
    #[arg(long, default_value = "127.0.0.1:8790")]
    listen: SocketAddr,
    /// UDP socket for observe requests, or "off".
    #[arg(long, default_value = "0.0.0.0:17893")]
    udp: String,
    /// The UDP endpoint clients are told to use (`host:port`), when the
    /// bound address is not what the internet sees (a firewall port, NAT).
    /// May be given more than once.
    #[arg(long = "public-udp-addr")]
    public_udp: Vec<String>,
    /// Puts per minute per client address.
    #[arg(long, default_value_t = RateConfig::default().put_per_ip)]
    rate_put: u32,
    /// Lookups per minute per client address.
    #[arg(long, default_value_t = RateConfig::default().lookup_per_ip)]
    rate_lookup: u32,
    /// Punch and relay requests per minute per client address.
    #[arg(long, default_value_t = RateConfig::default().coordinate_per_ip)]
    rate_coordinate: u32,
    /// Observe datagrams per minute per client address.
    #[arg(long, default_value_t = RateConfig::default().udp_per_ip)]
    rate_udp: u32,
    /// Relay bytes per second per session and direction; 0 turns the relay off.
    #[arg(long, default_value_t = proto::Limits::default().relay_rate)]
    relay_rate: u64,
    /// Relay sessions at once per vault tag.
    #[arg(long, default_value_t = proto::Limits::default().relay_per_tag)]
    relay_per_tag: usize,
    /// Relay sessions at once in all.
    #[arg(long, default_value_t = 1000)]
    max_relays: usize,
    /// Do not offer the relay.
    #[arg(long)]
    no_relay: bool,
    /// Ignore X-Forwarded-For even from a proxy on loopback.
    #[arg(long)]
    no_trust_proxy: bool,
    /// Log level: error, warn, info or debug. Logs never name tags or
    /// client addresses.
    #[arg(long, default_value = "info")]
    log: String,
}

struct Stderr(log::LevelFilter);

impl log::Log for Stderr {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        m.level() <= self.0
    }
    fn log(&self, r: &log::Record<'_>) {
        if self.enabled(r.metadata()) {
            eprintln!("{} {}", r.level(), r.args());
        }
    }
    fn flush(&self) {}
}

fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    let level: log::LevelFilter = a.log.parse().unwrap_or(log::LevelFilter::Info);
    let _ = log::set_boxed_logger(Box::new(Stderr(level)));
    log::set_max_level(level);
    let udp = if a.udp == "off" {
        None
    } else {
        Some(a.udp.parse::<SocketAddr>()?)
    };
    let mut cfg = Config {
        listen: a.listen,
        udp,
        public_udp: a.public_udp,
        trust_proxy: !a.no_trust_proxy,
        relay: !a.no_relay && a.relay_rate > 0,
        max_relays: a.max_relays,
        ..Config::default()
    };
    cfg.rates.put_per_ip = a.rate_put;
    cfg.rates.lookup_per_ip = a.rate_lookup;
    cfg.rates.coordinate_per_ip = a.rate_coordinate;
    cfg.rates.udp_per_ip = a.rate_udp;
    cfg.limits.relay_rate = if cfg.relay { a.relay_rate } else { 0 };
    cfg.limits.relay_per_tag = a.relay_per_tag;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let bound = http::bind(cfg).await?;
        log::info!(
            "varsto-rendezvous {} on {} (udp {:?})",
            env!("CARGO_PKG_VERSION"),
            bound.http_addr,
            bound.udp_addr
        );
        bound
            .run(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await;
        anyhow::Ok(())
    })
}
