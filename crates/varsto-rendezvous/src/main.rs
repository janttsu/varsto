// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! `varsto-rendezvous`: the rendezvous server (docs/rendezvous.md).

use clap::Parser;
use std::net::SocketAddr;
use std::time::Duration;
use varsto_rendezvous::{http, limits::RateConfig, proto, Config};

/// The Varsto rendezvous service: devices of a vault find each other
/// across networks, punch through NATs and, as the last route, relay their
/// end-to-end encrypted sessions. Everything is kept in memory.
///
/// Every option can also be set in the environment as VARSTO_RV_<NAME>
/// (for example VARSTO_RV_LISTEN), which suits systemd EnvironmentFile=.
#[derive(Parser, Debug)]
#[command(name = "varsto-rendezvous", version)]
struct Args {
    /// HTTP and WebSocket listener (put Caddy or another TLS proxy in front).
    #[arg(long, env = "VARSTO_RV_LISTEN", default_value = "127.0.0.1:8790")]
    listen: SocketAddr,
    /// UDP socket for observe requests, or "off".
    #[arg(long, env = "VARSTO_RV_UDP", default_value = "0.0.0.0:17893")]
    udp: String,
    /// The UDP endpoint clients are told to use (`host:port`), when the
    /// bound address is not what the internet sees (a firewall port, NAT).
    /// May be given more than once (VARSTO_RV_PUBLIC_UDP_ADDR: comma-separated).
    #[arg(
        long = "public-udp-addr",
        env = "VARSTO_RV_PUBLIC_UDP_ADDR",
        value_delimiter = ','
    )]
    public_udp: Vec<String>,
    /// Puts per minute per client address.
    #[arg(long, env = "VARSTO_RV_RATE_PUT", default_value_t = RateConfig::default().put_per_ip)]
    rate_put: u32,
    /// Lookups per minute per client address.
    #[arg(long, env = "VARSTO_RV_RATE_LOOKUP", default_value_t = RateConfig::default().lookup_per_ip)]
    rate_lookup: u32,
    /// Punch and relay requests per minute per client address.
    #[arg(long, env = "VARSTO_RV_RATE_COORDINATE", default_value_t = RateConfig::default().coordinate_per_ip)]
    rate_coordinate: u32,
    /// Observe datagrams per minute per client address.
    #[arg(long, env = "VARSTO_RV_RATE_UDP", default_value_t = RateConfig::default().udp_per_ip)]
    rate_udp: u32,
    /// Control connections opened per minute per client address.
    #[arg(long, env = "VARSTO_RV_RATE_CONTROL", default_value_t = RateConfig::default().control_per_ip)]
    rate_control: u32,
    /// Writes per minute per vault tag.
    #[arg(long, env = "VARSTO_RV_RATE_TAG_PUT", default_value_t = RateConfig::default().put_per_tag)]
    rate_tag_put: u32,
    /// Lookups per minute per vault tag.
    #[arg(long, env = "VARSTO_RV_RATE_TAG_LOOKUP", default_value_t = RateConfig::default().lookup_per_tag)]
    rate_tag_lookup: u32,
    /// Relay bytes per second per session and direction; 0 turns the relay off.
    #[arg(long, env = "VARSTO_RV_RELAY_RATE", default_value_t = proto::Limits::default().relay_rate)]
    relay_rate: u64,
    /// Relay bytes per second over all sessions together; 0 for no cap.
    #[arg(long, env = "VARSTO_RV_RELAY_TOTAL_RATE", default_value_t = Config::default().relay_total_rate)]
    relay_total_rate: u64,
    /// Relay bytes one vault tag may move per hour; 0 for no cap.
    #[arg(long, env = "VARSTO_RV_RELAY_TAG_BYTES", default_value_t = Config::default().relay_tag_bytes)]
    relay_tag_bytes: u64,
    /// Seconds without a byte either way before a relay session ends.
    #[arg(long, env = "VARSTO_RV_RELAY_IDLE", default_value_t = proto::Limits::default().relay_idle)]
    relay_idle: u64,
    /// Relay sessions at once per vault tag.
    #[arg(long, env = "VARSTO_RV_RELAY_PER_TAG", default_value_t = proto::Limits::default().relay_per_tag)]
    relay_per_tag: usize,
    /// Relay sessions at once in all.
    #[arg(long, env = "VARSTO_RV_MAX_RELAYS", default_value_t = 1000)]
    max_relays: usize,
    /// Control connections at once in all.
    #[arg(long, env = "VARSTO_RV_MAX_CONTROLS", default_value_t = Config::default().max_controls)]
    max_controls: usize,
    /// Control connections at once per client address.
    #[arg(long, env = "VARSTO_RV_MAX_CONTROLS_PER_IP", default_value_t = Config::default().max_controls_per_ip)]
    max_controls_per_ip: usize,
    /// Most slots held in all (memory bound).
    #[arg(long, env = "VARSTO_RV_MAX_SLOTS", default_value_t = Config::default().max_slots)]
    max_slots: usize,
    /// Most blob bytes held in all (memory bound).
    #[arg(long, env = "VARSTO_RV_MAX_BYTES", default_value_t = Config::default().max_bytes)]
    max_bytes: usize,
    /// Do not offer the relay.
    #[arg(long, env = "VARSTO_RV_NO_RELAY")]
    no_relay: bool,
    /// Ignore X-Forwarded-For even from a proxy on loopback.
    #[arg(long, env = "VARSTO_RV_NO_TRUST_PROXY")]
    no_trust_proxy: bool,
    /// Seconds open connections get to finish on SIGTERM or Ctrl-C.
    #[arg(long, env = "VARSTO_RV_GRACE", default_value_t = 5)]
    grace: u64,
    /// Log level: error, warn, info or debug. Info lines carry totals only;
    /// debug may carry a salted hash of a client address, never a tag.
    #[arg(long, env = "VARSTO_RV_LOG", default_value = "info")]
    log: String,
    /// Seconds between the totals line at info level; 0 for never.
    #[arg(long, env = "VARSTO_RV_STATS_EVERY", default_value_t = 600)]
    stats_every: u64,
    /// Start a server of its own on loopback, exercise register, lookup,
    /// observe, the control channel and a relay session against it, print
    /// the result and exit (0: all passed).
    #[arg(long)]
    self_test: bool,
}

struct Stderr(log::LevelFilter);

impl log::Log for Stderr {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        m.level() <= self.0
    }
    fn log(&self, r: &log::Record<'_>) {
        if self.enabled(r.metadata()) {
            // No timestamp: journald and most supervisors add their own.
            eprintln!("{} {}", r.level(), r.args());
        }
    }
    fn flush(&self) {}
}

/// Resolves on SIGTERM (systemd stop), SIGINT or Ctrl-C.
async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = term.recv() => log::info!("SIGTERM received"),
                    _ = tokio::signal::ctrl_c() => log::info!("interrupt received"),
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                log::info!("interrupt received");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        log::info!("interrupt received");
    }
}

fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    let level: log::LevelFilter = a.log.parse().unwrap_or(log::LevelFilter::Info);
    let _ = log::set_boxed_logger(Box::new(Stderr(level)));
    log::set_max_level(level);
    if a.self_test {
        match varsto_rendezvous::selftest::run() {
            Ok(steps) => {
                for s in &steps {
                    println!("ok   {s}");
                }
                println!("self-test passed ({} checks)", steps.len());
                return Ok(());
            }
            Err(e) => {
                println!("FAIL {e:#}");
                std::process::exit(1);
            }
        }
    }
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
        max_controls: a.max_controls,
        max_controls_per_ip: a.max_controls_per_ip,
        max_slots: a.max_slots,
        max_bytes: a.max_bytes,
        relay_total_rate: a.relay_total_rate,
        relay_tag_bytes: a.relay_tag_bytes,
        grace: Duration::from_secs(a.grace),
        stats_every: Duration::from_secs(a.stats_every),
        ..Config::default()
    };
    cfg.rates.put_per_ip = a.rate_put;
    cfg.rates.lookup_per_ip = a.rate_lookup;
    cfg.rates.coordinate_per_ip = a.rate_coordinate;
    cfg.rates.udp_per_ip = a.rate_udp;
    cfg.rates.control_per_ip = a.rate_control;
    cfg.rates.put_per_tag = a.rate_tag_put;
    cfg.rates.lookup_per_tag = a.rate_tag_lookup;
    cfg.limits.relay_rate = if cfg.relay { a.relay_rate } else { 0 };
    cfg.limits.relay_idle = a.relay_idle;
    cfg.limits.relay_per_tag = a.relay_per_tag;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let bound = http::bind(cfg).await?;
        log::info!(
            "varsto-rendezvous {} listening on {} (udp {})",
            env!("CARGO_PKG_VERSION"),
            bound.http_addr,
            bound
                .udp_addr
                .map(|a| a.to_string())
                .unwrap_or_else(|| "off".into())
        );
        let shared = bound.shared.clone();
        bound.run(stop_signal()).await;
        log::info!("{}", shared.stats_line());
        log::info!("stopped");
        anyhow::Ok(())
    })
}
