// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Automatic port mapping on the home router, tried before the NAT traversal
//! of `stun` and `quic` (punching, relays): ask the router to forward the
//! peer-to-peer port, TCP and UDP, to this device. Three protocols are tried
//! in order, and the first that maps anything wins:
//!
//! 1. PCP (RFC 6887), a MAP request to the default gateway, UDP port 5351;
//! 2. NAT-PMP (RFC 6886), its predecessor on the same port;
//! 3. UPnP IGD: an SSDP search, the device description, and SOAP calls
//!    (`GetSpecificPortMappingEntry`, `AddPortMapping`,
//!    `AddAnyPortMapping`, `GetExternalIPAddress`, `DeletePortMapping`).
//!
//! Every mapping has a lease (one hour by default) and is renewed at half of
//! what the router granted; mappings are removed when the service stops.
//! Only the peer-to-peer port is ever mapped. A mapping someone else made
//! for the same external port is left alone: one to another computer is
//! never overwritten (another external port is asked for instead), and one
//! to this device made by hand is used as it is, never renewed or removed.
//! A router that answers but has no public address itself (double NAT,
//! carrier-grade NAT) gains nothing, and its mapping is removed again.
//!
//! The three clients are written here rather than taken from crates: PCP
//! and NAT-PMP are two small UDP messages each, and the UPnP crates pull in
//! a URL and XML stack (tens of crates) for the five SOAP calls needed,
//! without the call that tells a user's own mapping apart.
//!
//! Nothing here is logged unless `VARSTO_P2P_DEBUG` is set: a router without
//! any of the protocols is the normal case, and the fallback is silent.

use anyhow::{anyhow, bail, Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

/// The port PCP and NAT-PMP servers listen on.
pub const PMP_PORT: u16 = 5351;
/// The SSDP multicast address and port UPnP devices answer searches on.
pub const SSDP_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(239, 255, 255, 250), 1900));
/// The lease asked for (PCP, NAT-PMP and UPnP alike).
pub const DEFAULT_LEASE: Duration = Duration::from_secs(3600);
/// After every protocol failed, they are tried again this long after
/// (another network, a router whose UPnP was switched on).
pub const RETRY_UNAVAILABLE: Duration = Duration::from_secs(30 * 60);
/// A failed renewal is retried this often until the lease runs out.
const RENEW_RETRY: Duration = Duration::from_secs(60);
/// The description our UPnP mappings carry: how a leftover of an earlier
/// run is told apart from a mapping the user made.
pub const DESCRIPTION: &str = "Varsto P2P";

fn debug(what: &str) {
    if std::env::var_os("VARSTO_P2P_DEBUG").is_some() {
        eprintln!("p2p: port mapping: {what}");
    }
}

/// How a mapping was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Method {
    Pcp,
    NatPmp,
    Upnp,
}

impl Method {
    pub fn label(&self) -> &'static str {
        match self {
            Method::Pcp => "PCP",
            Method::NatPmp => "NAT-PMP",
            Method::Upnp => "UPnP",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    fn upnp(&self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
        }
    }
    fn iana(&self) -> u8 {
        match self {
            Proto::Tcp => 6,
            Proto::Udp => 17,
        }
    }
    fn natpmp_op(&self) -> u8 {
        match self {
            Proto::Udp => 1,
            Proto::Tcp => 2,
        }
    }
}

/// How to reach the router that holds a mapping again (renew, remove).
#[derive(Clone, Debug)]
enum Holder {
    Pcp { server: SocketAddr, nonce: [u8; 12] },
    NatPmp { server: SocketAddr },
    Upnp { control: ControlUrl },
}

/// One port forwarded by the router.
#[derive(Clone, Debug)]
pub struct Mapping {
    pub method: Method,
    pub proto: Proto,
    /// This device's address and port as the router sees them.
    pub internal: SocketAddrV4,
    /// Where the internet reaches it.
    pub external: SocketAddr,
    /// What the router granted; zero for a permanent UPnP mapping (a router
    /// that accepts nothing else).
    pub lease: Duration,
    pub obtained: Instant,
    /// Made by someone else (by hand on the router): used, never renewed or
    /// removed.
    pub foreign: bool,
    /// A renewal failed: the next attempt, before the lease runs out.
    retry_at: Option<Instant>,
    holder: Holder,
}

impl Mapping {
    /// When to renew: at half the lease. `None` for mappings never renewed.
    fn renew_at(&self) -> Option<Instant> {
        if self.foreign || self.lease.is_zero() {
            None
        } else {
            Some(self.retry_at.unwrap_or(self.obtained + self.lease / 2))
        }
    }
    fn expires_at(&self) -> Option<Instant> {
        if self.foreign || self.lease.is_zero() {
            None
        } else {
            Some(self.obtained + self.lease)
        }
    }
}

/// What the status displays show.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapStatus {
    /// `off` (the setting), `trying`, `mapped` or `unavailable`.
    pub state: String,
    pub method: Option<Method>,
    pub tcp: Option<SocketAddr>,
    pub udp: Option<SocketAddr>,
    /// Lease granted, in seconds (0: permanent, or a mapping the user made).
    pub lease_secs: u64,
    /// The mapping was there already, made by hand: it is used, not renewed.
    pub existing: bool,
    /// Our own probe through the mapped UDP address reached us.
    pub verified: bool,
    /// Why nothing was mapped, one reason per protocol.
    pub detail: String,
}

impl PortMapStatus {
    pub fn off() -> Self {
        PortMapStatus {
            state: "off".into(),
            ..Default::default()
        }
    }
    /// "router port opened via UPnP: 203.0.113.5:17893", "not available", ...
    pub fn describe(&self) -> String {
        match self.state.as_str() {
            "mapped" => {
                let mut addrs: Vec<String> = Vec::new();
                match (self.tcp, self.udp) {
                    (Some(t), Some(u)) if t == u => addrs.push(t.to_string()),
                    (t, u) => {
                        if let Some(t) = t {
                            addrs.push(format!("{t} (TCP)"));
                        }
                        if let Some(u) = u {
                            addrs.push(format!("{u} (UDP)"));
                        }
                    }
                }
                format!(
                    "router port {} via {}: {}",
                    if self.existing {
                        "already open"
                    } else {
                        "opened"
                    },
                    self.method.map(|m| m.label()).unwrap_or("?"),
                    addrs.join(", ")
                )
            }
            "off" => "router port mapping: off".into(),
            "trying" => "router port mapping: asking the router".into(),
            _ => "router port mapping: not available".into(),
        }
    }
}

/// Where the requests go. `system()` for the real network; tests point the
/// fields at fake routers on the loopback interface.
#[derive(Clone, Debug)]
pub struct Options {
    /// PCP and NAT-PMP servers: the default gateway, port 5351.
    pub pmp: Vec<SocketAddr>,
    /// Where the SSDP search is sent.
    pub ssdp: SocketAddr,
    /// The lease asked for.
    pub lease: Duration,
    /// First wait for a PCP or NAT-PMP answer; doubled for each retry.
    pub pmp_wait: Duration,
    /// How long SSDP answers are collected.
    pub ssdp_wait: Duration,
}

impl Options {
    pub fn system() -> Options {
        Options {
            pmp: default_gateways()
                .into_iter()
                .map(|g| SocketAddr::new(IpAddr::V4(g), PMP_PORT))
                .collect(),
            ssdp: SSDP_ADDR,
            lease: DEFAULT_LEASE,
            pmp_wait: Duration::from_millis(250),
            ssdp_wait: Duration::from_millis(1500),
        }
    }
}

/// An address the internet can reach: not private, loopback, link-local,
/// carrier-grade NAT (100.64/10) or unspecified.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(v6) => !v6.is_unspecified() && !super::is_lan(IpAddr::V6(v6)),
    }
}

/// Keeps the peer-to-peer port mapped on the router: maps, renews, and
/// removes on `remove_all` (the service calls it when it stops).
pub struct PortMapper {
    opts: Options,
    port: u16,
    mappings: Vec<Mapping>,
    status: PortMapStatus,
    /// When to run the protocols again while nothing is mapped.
    next_try: Option<Instant>,
}

impl PortMapper {
    pub fn new(port: u16, opts: Options) -> PortMapper {
        PortMapper {
            opts,
            port,
            mappings: Vec::new(),
            status: PortMapStatus {
                state: "trying".into(),
                ..Default::default()
            },
            next_try: None,
        }
    }

    pub fn status(&self) -> PortMapStatus {
        self.status.clone()
    }
    /// Where the next attempt sends its requests (the gateway may have
    /// changed since the last one).
    pub fn set_options(&mut self, opts: Options) {
        self.opts = opts;
    }
    pub fn mappings(&self) -> &[Mapping] {
        &self.mappings
    }
    /// The mapped external address for TCP and for UDP.
    pub fn external(&self, proto: Proto) -> Option<SocketAddr> {
        self.mappings
            .iter()
            .find(|m| m.proto == proto)
            .map(|m| m.external)
    }
    pub fn set_verified(&mut self, ok: bool) {
        self.status.verified = ok;
    }

    /// When `tick` has something to do next.
    pub fn next_due(&self) -> Option<Instant> {
        let renew = self.mappings.iter().filter_map(|m| m.renew_at()).min();
        match (renew, self.next_try) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Map, renew or map again as due at `now`. Returns whether the external
    /// addresses changed (the rendezvous record should go out again).
    pub fn tick(&mut self, now: Instant) -> bool {
        let before = (self.external(Proto::Tcp), self.external(Proto::Udp));
        if self.mappings.is_empty() {
            if self.next_try.is_none_or(|t| now >= t) {
                self.map_now(now);
            }
        } else {
            self.renew_due(now);
            if self.mappings.is_empty() {
                // Every lease ran out without a renewal: start over.
                self.map_now(now);
            }
        }
        before != (self.external(Proto::Tcp), self.external(Proto::Udp))
    }

    /// Run the protocols in order (PCP, NAT-PMP, UPnP) until one maps the
    /// port, TCP and UDP.
    fn map_now(&mut self, now: Instant) {
        let mut why: Vec<String> = Vec::new();
        for method in [Method::Pcp, Method::NatPmp, Method::Upnp] {
            let got = match method {
                Method::Pcp => self.try_pmp(true),
                Method::NatPmp => self.try_pmp(false),
                Method::Upnp => self.try_upnp(),
            };
            match got {
                Ok(maps) if !maps.is_empty() => {
                    // A router without a public address of its own (double
                    // NAT): the mapping leads nowhere useful.
                    if let Some(m) = maps.iter().find(|m| !is_public(m.external.ip())) {
                        let ip = m.external.ip();
                        debug(&format!(
                            "{}: the router's own address {ip} is not public; not used",
                            method.label()
                        ));
                        for m in &maps {
                            let _ = remove(m);
                        }
                        why.push(format!(
                            "{}: the router has no public address ({ip})",
                            method.label()
                        ));
                        continue;
                    }
                    for m in &maps {
                        debug(&format!(
                            "{} {} {} -> {} (lease {} s{})",
                            method.label(),
                            m.proto.upnp(),
                            m.internal,
                            m.external,
                            m.lease.as_secs(),
                            if m.foreign { ", made by hand" } else { "" }
                        ));
                    }
                    self.mappings = maps;
                    for m in &mut self.mappings {
                        m.obtained = now;
                    }
                    self.next_try = None;
                    self.update_status(now);
                    return;
                }
                Ok(_) => why.push(format!("{}: nothing mapped", method.label())),
                Err(e) => {
                    debug(&format!("{}: {e:#}", method.label()));
                    why.push(format!("{}: {e:#}", method.label()));
                }
            }
        }
        self.mappings.clear();
        self.next_try = Some(now + RETRY_UNAVAILABLE);
        self.status = PortMapStatus {
            state: "unavailable".into(),
            detail: why.join("; "),
            ..Default::default()
        };
    }

    fn update_status(&mut self, _now: Instant) {
        let verified = self.status.verified;
        self.status = PortMapStatus {
            state: "mapped".into(),
            method: self.mappings.first().map(|m| m.method),
            tcp: self.external(Proto::Tcp),
            udp: self.external(Proto::Udp),
            lease_secs: self
                .mappings
                .iter()
                .map(|m| m.lease.as_secs())
                .min()
                .unwrap_or(0),
            existing: self.mappings.iter().all(|m| m.foreign),
            verified,
            detail: String::new(),
        };
    }

    fn renew_due(&mut self, now: Instant) {
        let mut changed = false;
        let mut keep: Vec<Mapping> = Vec::new();
        for m in std::mem::take(&mut self.mappings) {
            let Some(at) = m.renew_at() else {
                keep.push(m);
                continue;
            };
            if now < at {
                keep.push(m);
                continue;
            }
            match renew(&m, self.opts.lease, self.opts.pmp_wait) {
                Ok(fresh) => {
                    if fresh.external != m.external {
                        debug(&format!(
                            "{} {} now {} (was {})",
                            m.method.label(),
                            m.proto.upnp(),
                            fresh.external,
                            m.external
                        ));
                    }
                    let mut fresh = fresh;
                    fresh.obtained = now;
                    fresh.retry_at = None;
                    keep.push(fresh);
                    changed = true;
                }
                Err(e) => {
                    debug(&format!(
                        "renewing {} {} failed: {e:#}",
                        m.method.label(),
                        m.proto.upnp()
                    ));
                    if m.expires_at().is_some_and(|x| now >= x) {
                        // Gone; the next tick maps again from the start.
                        changed = true;
                        continue;
                    }
                    // Try again in a minute, before the lease runs out.
                    let mut m = m;
                    m.retry_at = Some((now + RENEW_RETRY).min(m.expires_at().unwrap_or(now)));
                    keep.push(m);
                }
            }
        }
        self.mappings = keep;
        if changed {
            if self.mappings.is_empty() {
                self.status = PortMapStatus {
                    state: "trying".into(),
                    ..Default::default()
                };
            } else {
                self.update_status(now);
            }
        }
    }

    /// Remove every mapping this device made (not those made by hand).
    pub fn remove_all(&mut self) {
        for m in std::mem::take(&mut self.mappings) {
            if m.foreign {
                continue;
            }
            match remove(&m) {
                Ok(()) => debug(&format!(
                    "removed {} {} {}",
                    m.method.label(),
                    m.proto.upnp(),
                    m.external
                )),
                Err(e) => debug(&format!(
                    "removing {} {} {} failed: {e:#}",
                    m.method.label(),
                    m.proto.upnp(),
                    m.external
                )),
            }
        }
        self.status = PortMapStatus::off();
        self.next_try = None;
    }

    /// PCP (`pcp`) or NAT-PMP, TCP and UDP, through the first gateway that
    /// answers.
    fn try_pmp(&self, pcp: bool) -> Result<Vec<Mapping>> {
        if self.opts.pmp.is_empty() {
            bail!("no default gateway known");
        }
        let mut last = anyhow!("no answer");
        for server in &self.opts.pmp {
            let mut out = Vec::new();
            for proto in [Proto::Tcp, Proto::Udp] {
                let r = if pcp {
                    pcp_map(
                        *server,
                        proto,
                        self.port,
                        self.port,
                        None,
                        self.opts.lease,
                        self.opts.pmp_wait,
                    )
                } else {
                    natpmp_map(
                        *server,
                        proto,
                        self.port,
                        self.port,
                        self.opts.lease,
                        self.opts.pmp_wait,
                    )
                };
                match r {
                    Ok(m) => out.push(m),
                    Err(e) => last = e,
                }
            }
            if !out.is_empty() {
                return Ok(out);
            }
        }
        Err(last)
    }

    fn try_upnp(&self) -> Result<Vec<Mapping>> {
        let locations = ssdp_search(self.opts.ssdp, self.opts.ssdp_wait)?;
        if locations.is_empty() {
            bail!("no UPnP gateway answered");
        }
        let mut last = anyhow!("no usable gateway");
        for loc in locations {
            let control = match describe(&loc) {
                Ok(c) => c,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            let mut out = Vec::new();
            for proto in [Proto::Tcp, Proto::Udp] {
                match upnp_map(&control, proto, self.port, self.opts.lease) {
                    Ok(m) => out.push(m),
                    Err(e) => last = e,
                }
            }
            if !out.is_empty() {
                return Ok(out);
            }
        }
        Err(last)
    }
}

/// Renew `m` with the same parameters; the result carries the new lease
/// and, should the router have moved it, the new external address.
fn renew(m: &Mapping, lease: Duration, wait: Duration) -> Result<Mapping> {
    match &m.holder {
        Holder::Pcp { server, nonce } => pcp_map(
            *server,
            m.proto,
            m.internal.port(),
            m.external.port(),
            Some(*nonce),
            lease,
            wait,
        ),
        Holder::NatPmp { server } => natpmp_map(
            *server,
            m.proto,
            m.internal.port(),
            m.external.port(),
            lease,
            wait,
        ),
        Holder::Upnp { control } => {
            let lease = if m.lease.is_zero() {
                Duration::ZERO
            } else {
                lease
            };
            soap_add(control, m.proto, m.external.port(), m.internal, lease)?;
            let mut fresh = m.clone();
            fresh.lease = lease;
            if let Ok(ip) = soap_external_ip(control) {
                fresh.external = SocketAddr::new(ip, m.external.port());
            }
            Ok(fresh)
        }
    }
}

fn remove(m: &Mapping) -> Result<()> {
    match &m.holder {
        Holder::Pcp { server, nonce } => pcp_request(
            *server,
            m.proto,
            m.internal.port(),
            0,
            *nonce,
            Duration::ZERO,
            Duration::from_millis(250),
        )
        .map(|_| ()),
        Holder::NatPmp { server } => natpmp_request(
            *server,
            m.proto,
            m.internal.port(),
            0,
            Duration::ZERO,
            Duration::from_millis(250),
        )
        .map(|_| ()),
        Holder::Upnp { control } => soap_delete(control, m.proto, m.external.port()),
    }
}

// ----- default gateway ---------------------------------------------------------

/// IPv4 default gateways of this host: from the routing table where it can
/// be read, else the `.1` of each private /24 this host has an address in
/// (the usual home router; a request to a host that is not one is ignored).
pub fn default_gateways() -> Vec<Ipv4Addr> {
    let mut out = os_gateways();
    if out.is_empty() {
        for ip in super::local_ipv4_addrs() {
            if let IpAddr::V4(v4) = ip {
                if v4.is_private() {
                    let o = v4.octets();
                    let g = Ipv4Addr::new(o[0], o[1], o[2], 1);
                    if g != v4 && !out.contains(&g) {
                        out.push(g);
                    }
                }
            }
        }
    }
    out
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn os_gateways() -> Vec<Ipv4Addr> {
    std::fs::read_to_string("/proc/net/route")
        .map(|t| parse_proc_route(&t))
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn os_gateways() -> Vec<Ipv4Addr> {
    std::process::Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .ok()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| l.trim().strip_prefix("gateway:"))
                .filter_map(|g| g.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(windows)]
fn os_gateways() -> Vec<Ipv4Addr> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    std::process::Command::new("route")
        .args(["print", "-4", "0.0.0.0"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()
        .map(|o| parse_route_print(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default()
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    windows
)))]
fn os_gateways() -> Vec<Ipv4Addr> {
    Vec::new()
}

/// `/proc/net/route`: the default routes (destination 0, gateway flag set);
/// addresses are little-endian hex.
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
fn parse_proc_route(text: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 4 || f[1] != "00000000" {
            continue;
        }
        let (Ok(gw), Ok(flags)) = (u32::from_str_radix(f[2], 16), u16::from_str_radix(f[3], 16))
        else {
            continue;
        };
        if flags & 0x2 == 0 || gw == 0 {
            continue;
        }
        let ip = Ipv4Addr::from(gw.to_le_bytes());
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// `route print -4 0.0.0.0` on Windows: rows `0.0.0.0 0.0.0.0 <gateway> ...`.
#[cfg_attr(not(windows), allow(dead_code))]
fn parse_route_print(text: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" {
            if let Ok(ip) = f[2].parse::<Ipv4Addr>() {
                if !ip.is_unspecified() && !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    out
}

/// The address of ours the host would use toward `peer` (nothing is sent).
fn local_ip_toward(peer: SocketAddr) -> Result<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.connect(peer)?;
    match s.local_addr()?.ip() {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => bail!("no IPv4 address toward {peer}"),
    }
}

// ----- PCP (RFC 6887) ----------------------------------------------------------

const PCP_VERSION: u8 = 2;
const PCP_OP_MAP: u8 = 1;
const PCP_MAP_LEN: usize = 60;

fn mapped_v6(ip: Ipv4Addr) -> [u8; 16] {
    ip.to_ipv6_mapped().octets()
}

/// A PCP MAP request (60 bytes).
pub fn pcp_encode_map(
    client: Ipv4Addr,
    nonce: &[u8; 12],
    proto: Proto,
    internal: u16,
    suggested: u16,
    lifetime: u32,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(PCP_MAP_LEN);
    b.push(PCP_VERSION);
    b.push(PCP_OP_MAP);
    b.extend_from_slice(&[0, 0]);
    b.extend_from_slice(&lifetime.to_be_bytes());
    b.extend_from_slice(&mapped_v6(client));
    b.extend_from_slice(nonce);
    b.push(proto.iana());
    b.extend_from_slice(&[0, 0, 0]);
    b.extend_from_slice(&internal.to_be_bytes());
    b.extend_from_slice(&suggested.to_be_bytes());
    // Any external IPv4 address: ::ffff:0.0.0.0.
    b.extend_from_slice(&mapped_v6(Ipv4Addr::UNSPECIFIED));
    b
}

/// A PCP MAP response: (result code, lifetime, external address).
#[derive(Debug, PartialEq, Eq)]
pub struct PcpAnswer {
    pub result: u8,
    pub lifetime: u32,
    pub nonce: [u8; 12],
    pub proto: u8,
    pub internal: u16,
    pub external: SocketAddr,
}

/// Parse a MAP response. An answer with version 0 comes from a NAT-PMP-only
/// server: `Err` with "unsupported version".
pub fn pcp_decode_map(buf: &[u8]) -> Result<PcpAnswer> {
    if buf.len() < 4 {
        bail!("short PCP answer");
    }
    if buf[0] != PCP_VERSION {
        bail!("unsupported version {} (a NAT-PMP server?)", buf[0]);
    }
    if buf[1] != 0x80 | PCP_OP_MAP {
        bail!("not a MAP answer");
    }
    let result = buf[3];
    if result != 0 {
        // Error answers may be short; the result code is what matters.
        return Ok(PcpAnswer {
            result,
            lifetime: 0,
            nonce: [0; 12],
            proto: 0,
            internal: 0,
            external: SocketAddr::from(([0, 0, 0, 0], 0)),
        });
    }
    if buf.len() < PCP_MAP_LEN {
        bail!("short PCP MAP answer");
    }
    let lifetime = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&buf[24..36]);
    let proto = buf[36];
    let internal = u16::from_be_bytes([buf[40], buf[41]]);
    let port = u16::from_be_bytes([buf[42], buf[43]]);
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&buf[44..60]);
    let v6 = Ipv6Addr::from(ip);
    let ip = match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    };
    Ok(PcpAnswer {
        result,
        lifetime,
        nonce,
        proto,
        internal,
        external: SocketAddr::new(ip, port),
    })
}

fn pcp_result_text(code: u8) -> &'static str {
    match code {
        1 => "unsupported version",
        2 => "not authorized",
        3 => "malformed request",
        4 => "unsupported opcode",
        5 => "unsupported option",
        6 => "malformed option",
        7 => "network failure",
        8 => "no resources",
        9 => "unsupported protocol",
        10 => "user exceeded quota",
        11 => "cannot provide the external address",
        12 => "address mismatch",
        13 => "excessive remote peers",
        _ => "error",
    }
}

/// Send `req` to `server` and wait for an answer, retrying with doubling
/// waits (three tries).
fn udp_exchange(server: SocketAddr, req: &[u8], wait: Duration) -> Result<(Vec<u8>, Ipv4Addr)> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(server)
        .with_context(|| format!("no route to {server}"))?;
    let local = match sock.local_addr()?.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => bail!("IPv4 only"),
    };
    let mut buf = [0u8; 1100];
    let mut w = wait.max(Duration::from_millis(10));
    for _ in 0..3 {
        sock.send(req)?;
        sock.set_read_timeout(Some(w))?;
        match sock.recv(&mut buf) {
            Ok(n) => return Ok((buf[..n].to_vec(), local)),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            // ICMP port unreachable: nobody listens there.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                bail!("{server} refused (no server)")
            }
            Err(e) => return Err(e.into()),
        }
        w *= 2;
    }
    bail!("no answer from {server}")
}

/// One PCP MAP exchange; the client address is the one the socket uses.
fn pcp_request(
    server: SocketAddr,
    proto: Proto,
    internal: u16,
    suggested: u16,
    nonce: [u8; 12],
    lease: Duration,
    wait: Duration,
) -> Result<PcpAnswer> {
    let client = local_ip_toward(server)?;
    let req = pcp_encode_map(
        client,
        &nonce,
        proto,
        internal,
        suggested,
        lease.as_secs().min(u32::MAX as u64) as u32,
    );
    let (resp, _) = udp_exchange(server, &req, wait)?;
    let a = pcp_decode_map(&resp)?;
    if a.result != 0 {
        bail!("PCP error {}: {}", a.result, pcp_result_text(a.result));
    }
    if a.nonce != nonce || a.proto != proto.iana() || a.internal != internal {
        bail!("PCP answer for another request");
    }
    Ok(a)
}

fn pcp_map(
    server: SocketAddr,
    proto: Proto,
    internal: u16,
    suggested: u16,
    nonce: Option<[u8; 12]>,
    lease: Duration,
    wait: Duration,
) -> Result<Mapping> {
    let nonce = nonce.unwrap_or_else(|| {
        let mut n = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut n);
        n
    });
    let a = pcp_request(server, proto, internal, suggested, nonce, lease, wait)?;
    if a.lifetime == 0 {
        bail!("PCP granted no lifetime");
    }
    Ok(Mapping {
        method: Method::Pcp,
        proto,
        internal: SocketAddrV4::new(local_ip_toward(server)?, internal),
        external: a.external,
        lease: Duration::from_secs(a.lifetime as u64),
        obtained: Instant::now(),
        foreign: false,
        retry_at: None,
        holder: Holder::Pcp { server, nonce },
    })
}

// ----- NAT-PMP (RFC 6886) -------------------------------------------------------

pub fn natpmp_encode_map(proto: Proto, internal: u16, suggested: u16, lifetime: u32) -> Vec<u8> {
    let mut b = vec![0, proto.natpmp_op(), 0, 0];
    b.extend_from_slice(&internal.to_be_bytes());
    b.extend_from_slice(&suggested.to_be_bytes());
    b.extend_from_slice(&lifetime.to_be_bytes());
    b
}

fn natpmp_result_text(code: u16) -> &'static str {
    match code {
        1 => "unsupported version",
        2 => "not authorized (mapping switched off on the router)",
        3 => "network failure",
        4 => "out of resources",
        5 => "unsupported opcode",
        _ => "error",
    }
}

/// The router's public address (opcode 0).
fn natpmp_external(server: SocketAddr, wait: Duration) -> Result<Ipv4Addr> {
    let (resp, _) = udp_exchange(server, &[0, 0], wait)?;
    if resp.len() < 12 || resp[0] != 0 || resp[1] != 128 {
        bail!("bad NAT-PMP address answer");
    }
    let result = u16::from_be_bytes([resp[2], resp[3]]);
    if result != 0 {
        bail!("NAT-PMP error {result}: {}", natpmp_result_text(result));
    }
    Ok(Ipv4Addr::new(resp[8], resp[9], resp[10], resp[11]))
}

/// One map request: (mapped external port, lifetime).
fn natpmp_request(
    server: SocketAddr,
    proto: Proto,
    internal: u16,
    suggested: u16,
    lease: Duration,
    wait: Duration,
) -> Result<(u16, u32)> {
    let req = natpmp_encode_map(
        proto,
        internal,
        suggested,
        lease.as_secs().min(u32::MAX as u64) as u32,
    );
    let (resp, _) = udp_exchange(server, &req, wait)?;
    if resp.len() < 16 || resp[0] != 0 || resp[1] != 128 + proto.natpmp_op() {
        bail!("bad NAT-PMP mapping answer");
    }
    let result = u16::from_be_bytes([resp[2], resp[3]]);
    if result != 0 {
        bail!("NAT-PMP error {result}: {}", natpmp_result_text(result));
    }
    if u16::from_be_bytes([resp[8], resp[9]]) != internal {
        bail!("NAT-PMP answer for another port");
    }
    Ok((
        u16::from_be_bytes([resp[10], resp[11]]),
        u32::from_be_bytes(resp[12..16].try_into().unwrap()),
    ))
}

fn natpmp_map(
    server: SocketAddr,
    proto: Proto,
    internal: u16,
    suggested: u16,
    lease: Duration,
    wait: Duration,
) -> Result<Mapping> {
    let ip = natpmp_external(server, wait)?;
    let (port, lifetime) = natpmp_request(server, proto, internal, suggested, lease, wait)?;
    if lifetime == 0 || port == 0 {
        bail!("NAT-PMP granted no mapping");
    }
    Ok(Mapping {
        method: Method::NatPmp,
        proto,
        internal: SocketAddrV4::new(local_ip_toward(server)?, internal),
        external: SocketAddr::new(IpAddr::V4(ip), port),
        lease: Duration::from_secs(lifetime as u64),
        obtained: Instant::now(),
        foreign: false,
        retry_at: None,
        holder: Holder::NatPmp { server },
    })
}

// ----- UPnP IGD -----------------------------------------------------------------

/// A WAN connection service of an Internet Gateway Device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlUrl {
    /// The router's HTTP address (an IP literal).
    pub addr: SocketAddr,
    pub path: String,
    /// e.g. `urn:schemas-upnp-org:service:WANIPConnection:2`.
    pub service: String,
}

impl ControlUrl {
    fn igd2(&self) -> bool {
        self.service.ends_with("WANIPConnection:2")
    }
}

const IGD_SEARCH: [&str; 2] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
];

/// Send SSDP searches for gateways and collect the description URLs of
/// those that answered. Only answers whose description lives on the
/// answering host's own address are taken (no fetching from elsewhere).
pub fn ssdp_search(to: SocketAddr, wait: Duration) -> Result<Vec<(SocketAddr, String)>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let _ = sock.set_multicast_ttl_v4(2);
    for st in IGD_SEARCH {
        let msg = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {st}\r\n\r\n"
        );
        sock.send_to(msg.as_bytes(), to)
            .with_context(|| format!("SSDP search to {to}"))?;
    }
    let until = Instant::now() + wait;
    let mut out: Vec<(SocketAddr, String)> = Vec::new();
    let mut buf = [0u8; 2048];
    loop {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        sock.set_read_timeout(Some(left))?;
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => continue,
            Err(e) => return Err(e.into()),
        };
        let text = String::from_utf8_lossy(&buf[..n]);
        let Some(loc) = header_value(&text, "location") else {
            continue;
        };
        let Ok((addr, path)) = split_http_url(&loc) else {
            continue;
        };
        if addr.ip() != from.ip() || !super::is_lan(addr.ip()) {
            debug(&format!(
                "SSDP answer from {from} points elsewhere ({loc}); ignored"
            ));
            continue;
        }
        if !out.iter().any(|(a, p)| *a == addr && *p == path) {
            out.push((addr, path));
        }
    }
    Ok(out)
}

fn header_value(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

/// `http://192.168.1.1:5000/desc.xml` -> (192.168.1.1:5000, "/desc.xml").
/// Host names are refused: a router's URLs carry its address.
fn split_http_url(url: &str) -> Result<(SocketAddr, String)> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("HTTP://"))
        .ok_or_else(|| anyhow!("not an http URL: {url}"))?;
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let addr: SocketAddr = match host.parse() {
        Ok(a) => a,
        Err(_) => SocketAddr::new(
            host.parse::<IpAddr>()
                .map_err(|_| anyhow!("not an address: {host}"))?,
            80,
        ),
    };
    Ok((addr, path))
}

/// A small HTTP/1.1 exchange over a fresh connection. Answers over 256 KiB
/// are cut off (a description is a few kilobytes).
fn http(addr: SocketAddr, req: &str) -> Result<(u16, String)> {
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(req.as_bytes())?;
    let mut raw = Vec::new();
    s.take(256 * 1024).read_to_end(&mut raw)?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("bad HTTP answer from {addr}"))?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut body = raw[split + 4..].to_vec();
    if header_value(&head, "transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        body = super::decode_chunked(&body)?;
    }
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Ok((status, String::from_utf8_lossy(&body).to_string()))
}

/// The text of the first element named `name` (any namespace prefix).
fn xml_text(xml: &str, name: &str) -> Option<String> {
    let mut rest = xml;
    while let Some(i) = rest.find('<') {
        rest = &rest[i + 1..];
        let end = rest.find('>')?;
        let tag = &rest[..end];
        if tag.starts_with('/') || tag.starts_with('?') || tag.starts_with('!') {
            continue;
        }
        let tag_name = tag
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_end_matches('/');
        let local = tag_name.rsplit(':').next().unwrap_or(tag_name);
        if local == name {
            if tag.ends_with('/') {
                return Some(String::new());
            }
            let body = &rest[end + 1..];
            let stop = body.find('<').unwrap_or(body.len());
            return Some(xml_unescape(body[..stop].trim()));
        }
    }
    None
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Find the WAN connection service in a device description: WANIPConnection
/// version 2, else version 1, else WANPPPConnection.
pub fn parse_description(xml: &str, location: SocketAddr) -> Result<ControlUrl> {
    let base = xml_text(xml, "URLBase")
        .filter(|b| !b.is_empty())
        .and_then(|b| split_http_url(&b).ok())
        .map(|(a, _)| a)
        .unwrap_or(location);
    let mut found: Vec<(usize, ControlUrl)> = Vec::new();
    for seg in xml.split("<service>").skip(1) {
        let seg = seg.split("</service>").next().unwrap_or(seg);
        let (Some(st), Some(ctl)) = (xml_text(seg, "serviceType"), xml_text(seg, "controlURL"))
        else {
            continue;
        };
        let rank = if st.ends_with(":WANIPConnection:2") {
            0
        } else if st.ends_with(":WANIPConnection:1") {
            1
        } else if st.ends_with(":WANPPPConnection:1") {
            2
        } else {
            continue;
        };
        let (addr, path) = if ctl.starts_with("http://") {
            split_http_url(&ctl)?
        } else if ctl.starts_with('/') {
            (base, ctl.clone())
        } else {
            (base, format!("/{ctl}"))
        };
        // The control point is the router itself, not some other host.
        if addr.ip() != location.ip() {
            continue;
        }
        found.push((
            rank,
            ControlUrl {
                addr,
                path,
                service: st,
            },
        ));
    }
    found.sort_by_key(|(r, _)| *r);
    found
        .into_iter()
        .next()
        .map(|(_, c)| c)
        .ok_or_else(|| anyhow!("the gateway offers no WAN connection service"))
}

fn describe(loc: &(SocketAddr, String)) -> Result<ControlUrl> {
    let (addr, path) = loc;
    let (status, body) = http(
        *addr,
        &format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    )?;
    if status != 200 {
        bail!("description at {addr}{path}: HTTP {status}");
    }
    parse_description(&body, *addr)
}

/// A SOAP fault's UPnP error code, or the HTTP status.
#[derive(Debug)]
pub struct SoapError {
    pub code: u32,
    pub text: String,
}

impl std::fmt::Display for SoapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UPnP error {}: {}", self.code, self.text)
    }
}

impl std::error::Error for SoapError {}

fn soap(control: &ControlUrl, action: &str, args: &[(&str, String)]) -> Result<String> {
    let mut inner = String::new();
    for (k, v) in args {
        inner.push_str(&format!("<{k}>{v}</{k}>"));
    }
    let body = format!(
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{svc}\">{inner}</u:{action}></s:Body></s:Envelope>\r\n",
        svc = control.service
    );
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{svc}#{action}\"\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        path = control.path,
        addr = control.addr,
        svc = control.service,
        len = body.len()
    );
    let (status, text) = http(control.addr, &req)?;
    if status == 200 {
        return Ok(text);
    }
    let code = xml_text(&text, "errorCode")
        .and_then(|c| c.parse().ok())
        .unwrap_or(status as u32);
    let desc = xml_text(&text, "errorDescription").unwrap_or_else(|| format!("HTTP {status}"));
    Err(SoapError { code, text: desc }.into())
}

fn soap_code(e: &anyhow::Error) -> Option<u32> {
    e.downcast_ref::<SoapError>().map(|s| s.code)
}

fn soap_external_ip(control: &ControlUrl) -> Result<IpAddr> {
    let r = soap(control, "GetExternalIPAddress", &[])?;
    xml_text(&r, "NewExternalIPAddress")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("the gateway reported no external address"))
}

/// An existing entry for `ext`: (internal client, internal port, description).
fn soap_entry(
    control: &ControlUrl,
    proto: Proto,
    ext: u16,
) -> Result<Option<(String, u16, String)>> {
    match soap(
        control,
        "GetSpecificPortMappingEntry",
        &[
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", ext.to_string()),
            ("NewProtocol", proto.upnp().to_string()),
        ],
    ) {
        Ok(r) => Ok(Some((
            xml_text(&r, "NewInternalClient").unwrap_or_default(),
            xml_text(&r, "NewInternalPort")
                .and_then(|p| p.parse().ok())
                .unwrap_or(0),
            xml_text(&r, "NewPortMappingDescription").unwrap_or_default(),
        ))),
        // 714 NoSuchEntryInArray: free.
        Err(e) if soap_code(&e) == Some(714) => Ok(None),
        Err(e) => Err(e),
    }
}

fn add_args(
    proto: Proto,
    ext: u16,
    internal: SocketAddrV4,
    lease: Duration,
) -> Vec<(&'static str, String)> {
    vec![
        ("NewRemoteHost", String::new()),
        ("NewExternalPort", ext.to_string()),
        ("NewProtocol", proto.upnp().to_string()),
        ("NewInternalPort", internal.port().to_string()),
        ("NewInternalClient", internal.ip().to_string()),
        ("NewEnabled", "1".to_string()),
        ("NewPortMappingDescription", DESCRIPTION.to_string()),
        ("NewLeaseDuration", lease.as_secs().to_string()),
    ]
}

fn soap_add(
    control: &ControlUrl,
    proto: Proto,
    ext: u16,
    internal: SocketAddrV4,
    lease: Duration,
) -> Result<()> {
    soap(
        control,
        "AddPortMapping",
        &add_args(proto, ext, internal, lease),
    )
    .map(|_| ())
}

/// `AddAnyPortMapping` (IGD version 2): the router picks a free external port.
fn soap_add_any(
    control: &ControlUrl,
    proto: Proto,
    ext: u16,
    internal: SocketAddrV4,
    lease: Duration,
) -> Result<u16> {
    let r = soap(
        control,
        "AddAnyPortMapping",
        &add_args(proto, ext, internal, lease),
    )?;
    xml_text(&r, "NewReservedPort")
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| anyhow!("no reserved port in the answer"))
}

fn soap_delete(control: &ControlUrl, proto: Proto, ext: u16) -> Result<()> {
    soap(
        control,
        "DeletePortMapping",
        &[
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", ext.to_string()),
            ("NewProtocol", proto.upnp().to_string()),
        ],
    )
    .map(|_| ())
}

/// Map `port` for `proto` through a UPnP gateway, respecting entries others
/// made: one for this device and port made by hand is used as it is; one
/// for another computer is left alone and another external port is taken.
fn upnp_map(control: &ControlUrl, proto: Proto, port: u16, lease: Duration) -> Result<Mapping> {
    let me = SocketAddrV4::new(local_ip_toward(control.addr)?, port);
    let ip = soap_external_ip(control)?;
    let mapping = |ext: u16, lease: Duration, foreign: bool| Mapping {
        method: Method::Upnp,
        proto,
        internal: me,
        external: SocketAddr::new(ip, ext),
        lease,
        obtained: Instant::now(),
        foreign,
        retry_at: None,
        holder: Holder::Upnp {
            control: control.clone(),
        },
    };
    // Add `ext`; a router that only takes permanent mappings (725) gets one,
    // removed again when the service stops.
    let add = |ext: u16| -> Result<Duration> {
        match soap_add(control, proto, ext, me, lease) {
            Ok(()) => Ok(lease),
            Err(e) if soap_code(&e) == Some(725) => {
                soap_add(control, proto, ext, me, Duration::ZERO)?;
                Ok(Duration::ZERO)
            }
            Err(e) => Err(e),
        }
    };
    let mut candidates: Vec<u16> = vec![port];
    let mut rng = rand::thread_rng();
    for _ in 0..3 {
        candidates.push(20000 + (rand::Rng::gen_range(&mut rng, 0..40000u16)));
    }
    let mut last = anyhow!("no free external port");
    for (i, ext) in candidates.iter().copied().enumerate() {
        // A gateway without GetSpecificPortMappingEntry: rely on its own
        // conflict check (718) when adding.
        let entry = soap_entry(control, proto, ext).unwrap_or(None);
        if let Some((client, iport, desc)) = &entry {
            let ours = client.parse::<Ipv4Addr>().ok() == Some(*me.ip()) && *iport == port;
            if ours && desc != DESCRIPTION {
                // Made by hand for this very device and port: use it, never touch it.
                return Ok(mapping(ext, Duration::ZERO, true));
            }
            if !ours {
                debug(&format!(
                    "UPnP {} {ext} is mapped to {client}:{iport} already; trying another port",
                    proto.upnp()
                ));
                if i == 0 && control.igd2() {
                    // The router picks a free port; it never replaces another's entry.
                    match soap_add_any(control, proto, port, me, lease) {
                        Ok(got) => return Ok(mapping(got, lease, false)),
                        Err(e) => last = e,
                    }
                }
                continue;
            }
            // Ours from an earlier run: take it over (renewed from now on).
        }
        match add(ext) {
            Ok(granted) => return Ok(mapping(ext, granted, false)),
            // 718 ConflictInMappingEntry: someone else's; try another port.
            Err(e) if soap_code(&e) == Some(718) => last = e,
            Err(e) => return Err(e),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn proc_route_and_route_print_are_parsed() {
        let proc =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                    eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                    eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_proc_route(proc), vec![Ipv4Addr::new(192, 168, 1, 1)]);
        let win = "IPv4 Route Table\n===\nActive Routes:\nNetwork Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0      10.0.0.138       10.0.0.20     25\n";
        assert_eq!(parse_route_print(win), vec![Ipv4Addr::new(10, 0, 0, 138)]);
    }

    #[test]
    fn public_addresses() {
        assert!(is_public("203.0.113.5".parse().unwrap()));
        assert!(!is_public("192.168.1.2".parse().unwrap()));
        assert!(!is_public("100.64.3.4".parse().unwrap()));
        assert!(!is_public("10.1.2.3".parse().unwrap()));
        assert!(!is_public("0.0.0.0".parse().unwrap()));
    }

    #[test]
    fn pcp_map_round_trip() {
        let nonce = [7u8; 12];
        let req = pcp_encode_map(
            Ipv4Addr::new(192, 168, 1, 20),
            &nonce,
            Proto::Udp,
            17893,
            17893,
            3600,
        );
        assert_eq!(req.len(), 60);
        assert_eq!(req[0], 2);
        assert_eq!(req[1], 1);
        assert_eq!(
            &req[8..24],
            &Ipv4Addr::new(192, 168, 1, 20).to_ipv6_mapped().octets()
        );
        assert_eq!(req[36], 17);
        // The fake router's answer to it.
        let resp = FakePmp::pcp_answer(&req, 0, 1800, Ipv4Addr::new(203, 0, 113, 5), 40000);
        let a = pcp_decode_map(&resp).unwrap();
        assert_eq!(a.result, 0);
        assert_eq!(a.lifetime, 1800);
        assert_eq!(a.nonce, nonce);
        assert_eq!(a.external, "203.0.113.5:40000".parse().unwrap());
        // A NAT-PMP server answers a PCP request with version 0.
        assert!(pcp_decode_map(&[0, 129, 0, 1, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn xml_and_descriptions() {
        let xml = r#"<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device><serviceList>
            <service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/l3f</controlURL></service>
            </serviceList><deviceList><device><deviceList><device><serviceList>
            <service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType><controlURL>/ppp</controlURL></service>
            <service><controlURL>ctl/IPConn</controlURL><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType></service>
            </serviceList></device></deviceList></device></deviceList></device></root>"#;
        let loc: SocketAddr = "192.168.1.1:5000".parse().unwrap();
        let c = parse_description(xml, loc).unwrap();
        assert_eq!(c.path, "/ctl/IPConn");
        assert_eq!(c.addr, loc);
        assert!(c.service.ends_with("WANIPConnection:1"));
        // A control URL on another host is not followed.
        let evil = xml
            .replace("ctl/IPConn", "http://10.9.9.9:80/x")
            .replace("/ppp", "http://10.9.9.9/y");
        assert!(parse_description(&evil, loc).is_err());
        assert_eq!(
            xml_text(
                "<s:Body><u:R><NewExternalIPAddress>203.0.113.5</NewExternalIPAddress></u:R>",
                "NewExternalIPAddress"
            )
            .as_deref(),
            Some("203.0.113.5")
        );
        assert_eq!(xml_text("<a><b/></a>", "b").as_deref(), Some(""));
    }

    #[test]
    fn status_text() {
        let mut s = PortMapStatus {
            state: "mapped".into(),
            method: Some(Method::Upnp),
            tcp: Some("203.0.113.5:17893".parse().unwrap()),
            udp: Some("203.0.113.5:17893".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(
            s.describe(),
            "router port opened via UPnP: 203.0.113.5:17893"
        );
        s.udp = Some("203.0.113.5:40000".parse().unwrap());
        assert_eq!(
            s.describe(),
            "router port opened via UPnP: 203.0.113.5:17893 (TCP), 203.0.113.5:40000 (UDP)"
        );
        s.state = "unavailable".into();
        assert_eq!(s.describe(), "router port mapping: not available");
    }

    // ----- fake PCP / NAT-PMP router ------------------------------------------

    /// What the fake router speaks.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Speaks {
        Pcp,
        NatPmp,
    }

    /// A PCP or NAT-PMP server on 127.0.0.1 that grants every request with
    /// `lifetime` and maps to `203.0.113.5` (or `external_ip`).
    struct FakePmp {
        addr: SocketAddr,
        requests: Arc<Mutex<Vec<Vec<u8>>>>,
        stop: Arc<AtomicBool>,
    }

    impl FakePmp {
        fn pcp_answer(req: &[u8], result: u8, lifetime: u32, ip: Ipv4Addr, port: u16) -> Vec<u8> {
            let mut r = vec![2, 0x81, 0, result];
            r.extend_from_slice(&lifetime.to_be_bytes());
            r.extend_from_slice(&1234u32.to_be_bytes());
            r.extend_from_slice(&[0; 12]);
            r.extend_from_slice(&req[24..36]); // nonce
            r.push(req[36]);
            r.extend_from_slice(&[0, 0, 0]);
            r.extend_from_slice(&req[40..42]);
            r.extend_from_slice(&port.to_be_bytes());
            r.extend_from_slice(&ip.to_ipv6_mapped().octets());
            r
        }

        fn start(speaks: Speaks, lifetime: u32, external_ip: Ipv4Addr) -> FakePmp {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let addr = sock.local_addr().unwrap();
            let requests: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
            let stop = Arc::new(AtomicBool::new(false));
            let (rq, st) = (requests.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut buf = [0u8; 1100];
                while !st.load(Ordering::Relaxed) {
                    let Ok((n, from)) = sock.recv_from(&mut buf) else {
                        continue;
                    };
                    let req = buf[..n].to_vec();
                    rq.lock().unwrap().push(req.clone());
                    let resp = match (speaks, req[0]) {
                        (Speaks::Pcp, 2) => {
                            let life = u32::from_be_bytes(req[4..8].try_into().unwrap());
                            let ext = u16::from_be_bytes([req[42], req[43]]);
                            let port = if life == 0 {
                                0
                            } else if ext == 0 {
                                45000
                            } else {
                                ext
                            };
                            FakePmp::pcp_answer(&req, 0, life.min(lifetime), external_ip, port)
                        }
                        // A PCP server answers NAT-PMP with UNSUPP_VERSION (RFC 6887 9).
                        (Speaks::Pcp, _) => vec![2, 0x80 | req[1], 0, 1],
                        // A NAT-PMP server answers version 2 with its own version 0.
                        (Speaks::NatPmp, 2) => vec![0, 0x80 | req[1], 0, 1, 0, 0, 0, 0],
                        (Speaks::NatPmp, _) if req[1] == 0 => {
                            let mut r = vec![0, 128, 0, 0, 0, 0, 0, 1];
                            r.extend_from_slice(&external_ip.octets());
                            r
                        }
                        (Speaks::NatPmp, _) => {
                            let life = u32::from_be_bytes(req[8..12].try_into().unwrap());
                            let mut r = vec![0, 128 + req[1], 0, 0, 0, 0, 0, 1];
                            r.extend_from_slice(&req[4..6]);
                            let ext = u16::from_be_bytes([req[6], req[7]]);
                            r.extend_from_slice(&(if life == 0 { 0 } else { ext }).to_be_bytes());
                            r.extend_from_slice(&life.min(lifetime).to_be_bytes());
                            r
                        }
                    };
                    let _ = sock.send_to(&resp, from);
                }
            });
            FakePmp {
                addr,
                requests,
                stop,
            }
        }
        fn count(&self, pred: impl Fn(&[u8]) -> bool) -> usize {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| pred(r))
                .count()
        }
    }

    impl Drop for FakePmp {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    /// A port nobody answers on (bound and silent).
    fn silent() -> (UdpSocket, SocketAddr) {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let a = s.local_addr().unwrap();
        (s, a)
    }

    fn opts(pmp: Vec<SocketAddr>, ssdp: SocketAddr) -> Options {
        Options {
            pmp,
            ssdp,
            lease: DEFAULT_LEASE,
            pmp_wait: Duration::from_millis(20),
            ssdp_wait: Duration::from_millis(300),
        }
    }

    #[test]
    fn pcp_maps_both_protocols_renews_and_removes() {
        let router = FakePmp::start(Speaks::Pcp, 3600, Ipv4Addr::new(203, 0, 113, 5));
        let (_q, nobody) = silent();
        let mut m = PortMapper::new(17893, opts(vec![router.addr], nobody));
        let t0 = Instant::now();
        assert!(m.tick(t0));
        let s = m.status();
        assert_eq!(s.state, "mapped");
        assert_eq!(s.method, Some(Method::Pcp));
        assert_eq!(s.tcp, Some("203.0.113.5:17893".parse().unwrap()));
        assert_eq!(s.udp, Some("203.0.113.5:17893".parse().unwrap()));
        assert_eq!(s.lease_secs, 3600);
        assert_eq!(
            s.describe(),
            "router port opened via PCP: 203.0.113.5:17893"
        );
        let maps = router.count(|r| r[0] == 2);
        assert_eq!(maps, 2);
        // Nothing to do before half the lease.
        assert!(!m.tick(t0 + Duration::from_secs(1700)));
        assert_eq!(router.count(|r| r[0] == 2), 2);
        // At half the lease both are renewed, with the same nonce.
        assert!(m.next_due().unwrap() <= t0 + Duration::from_secs(1801));
        assert!(!m.tick(t0 + Duration::from_secs(1801)));
        let reqs = router.requests.lock().unwrap().clone();
        assert_eq!(reqs.len(), 4);
        assert_eq!(reqs[0][24..36], reqs[2][24..36]);
        // Removal sends lifetime 0 for each.
        m.remove_all();
        let reqs = router.requests.lock().unwrap().clone();
        assert_eq!(reqs.len(), 6);
        assert!(reqs[4..].iter().all(|r| r[4..8] == [0, 0, 0, 0]));
        assert_eq!(m.status().state, "off");
    }

    #[test]
    fn natpmp_is_tried_when_pcp_is_not_spoken() {
        let router = FakePmp::start(Speaks::NatPmp, 7200, Ipv4Addr::new(203, 0, 113, 9));
        let (_q, nobody) = silent();
        let mut m = PortMapper::new(17893, opts(vec![router.addr], nobody));
        m.tick(Instant::now());
        let s = m.status();
        assert_eq!(s.method, Some(Method::NatPmp), "{s:?}");
        assert_eq!(s.udp, Some("203.0.113.9:17893".parse().unwrap()));
        // PCP first (refused with version 0), then NAT-PMP.
        let reqs = router.requests.lock().unwrap().clone();
        assert_eq!(reqs[0][0], 2);
        assert!(reqs.iter().any(|r| r[0] == 0 && r[1] == 2));
        assert!(reqs.iter().any(|r| r[0] == 0 && r[1] == 1));
        // Lease: as asked (an hour), not the router's longer maximum.
        assert_eq!(s.lease_secs, 3600);
        m.remove_all();
        assert_eq!(
            router.count(|r| r[0] == 0 && r.len() == 12 && r[8..12] == [0, 0, 0, 0]),
            2
        );
    }

    #[test]
    fn a_short_lease_is_renewed_in_time() {
        let router = FakePmp::start(Speaks::Pcp, 4, Ipv4Addr::new(203, 0, 113, 5));
        let (_q, nobody) = silent();
        let mut m = PortMapper::new(17893, opts(vec![router.addr], nobody));
        let t0 = Instant::now();
        m.tick(t0);
        assert_eq!(m.status().lease_secs, 4);
        let due = m.next_due().unwrap();
        assert!(due <= t0 + Duration::from_secs(2) + Duration::from_millis(500));
        m.tick(due);
        assert_eq!(router.count(|r| r[0] == 2), 4);
        assert_eq!(m.status().state, "mapped");
    }

    #[test]
    fn a_failed_renewal_is_retried_and_a_lapsed_mapping_mapped_again() {
        let router = FakePmp::start(Speaks::Pcp, 600, Ipv4Addr::new(203, 0, 113, 5));
        let (_q, nobody) = silent();
        let mut m = PortMapper::new(17893, opts(vec![router.addr], nobody));
        let t0 = Instant::now();
        m.tick(t0);
        assert_eq!(m.status().state, "mapped");
        // The router goes away.
        let addr = router.addr;
        drop(router);
        std::thread::sleep(Duration::from_millis(100));
        let _hold = UdpSocket::bind(addr).ok(); // silent from now on
        m.tick(t0 + Duration::from_secs(301));
        // Still kept (the lease runs until 600 s), retried a minute later.
        assert_eq!(m.status().state, "mapped");
        let due = m.next_due().unwrap();
        assert!(due >= t0 + Duration::from_secs(360) && due <= t0 + Duration::from_secs(362));
        // After the lease: dropped, and every protocol failed.
        m.tick(t0 + Duration::from_secs(700));
        assert_eq!(m.status().state, "unavailable");
        assert!(m.external(Proto::Tcp).is_none());
    }

    #[test]
    fn nothing_answers_falls_back_silently() {
        let (_a, quiet1) = silent();
        let (_b, quiet2) = silent();
        let mut m = PortMapper::new(17893, opts(vec![quiet1], quiet2));
        let t0 = Instant::now();
        assert!(!m.tick(t0));
        let s = m.status();
        assert_eq!(s.state, "unavailable");
        assert!(
            s.detail.contains("PCP") && s.detail.contains("NAT-PMP") && s.detail.contains("UPnP"),
            "{}",
            s.detail
        );
        assert_eq!(s.describe(), "router port mapping: not available");
        // Tried again half an hour later, not before.
        assert_eq!(m.next_due(), Some(t0 + RETRY_UNAVAILABLE));
    }

    #[test]
    fn a_router_without_a_public_address_is_not_used() {
        let router = FakePmp::start(Speaks::Pcp, 3600, Ipv4Addr::new(100, 64, 0, 7));
        let (_q, nobody) = silent();
        let mut m = PortMapper::new(17893, opts(vec![router.addr], nobody));
        m.tick(Instant::now());
        let s = m.status();
        assert_eq!(s.state, "unavailable");
        assert!(s.detail.contains("no public address"), "{}", s.detail);
        // The two mappings were removed again.
        assert_eq!(router.count(|r| r[0] == 2 && r[4..8] == [0, 0, 0, 0]), 2);
    }

    // ----- fake UPnP IGD ------------------------------------------------------

    #[derive(Clone, Debug)]
    struct Entry {
        client: String,
        iport: u16,
        desc: String,
        lease: u64,
    }

    struct FakeIgd {
        ssdp: SocketAddr,
        table: Arc<Mutex<std::collections::BTreeMap<(String, u16), Entry>>>,
        actions: Arc<Mutex<Vec<String>>>,
        stop: Arc<AtomicBool>,
    }

    impl FakeIgd {
        /// `igd2`: WANIPConnection:2 with AddAnyPortMapping; `permanent_only`:
        /// leases other than 0 are refused with 725.
        fn start(igd2: bool, permanent_only: bool) -> FakeIgd {
            let http = tiny_http::Server::http("127.0.0.1:0").unwrap();
            let http_addr = http.server_addr().to_ip().unwrap();
            let ssdp = UdpSocket::bind("127.0.0.1:0").unwrap();
            ssdp.set_read_timeout(Some(Duration::from_millis(50)))
                .unwrap();
            let ssdp_addr = ssdp.local_addr().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let table: Arc<Mutex<std::collections::BTreeMap<(String, u16), Entry>>> =
                Arc::default();
            let actions: Arc<Mutex<Vec<String>>> = Arc::default();
            let st = stop.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 2048];
                while !st.load(Ordering::Relaxed) {
                    let Ok((n, from)) = ssdp.recv_from(&mut buf) else {
                        continue;
                    };
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    if !req.starts_with("M-SEARCH") {
                        continue;
                    }
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: http://{http_addr}/rootDesc.xml\r\n\r\n"
                    );
                    let _ = ssdp.send_to(resp.as_bytes(), from);
                }
            });
            let svc = if igd2 {
                "WANIPConnection:2"
            } else {
                "WANIPConnection:1"
            };
            let (st, tb, ac) = (stop.clone(), table.clone(), actions.clone());
            std::thread::spawn(move || {
                while !st.load(Ordering::Relaxed) {
                    let Ok(Some(mut rq)) = http.recv_timeout(Duration::from_millis(50)) else {
                        continue;
                    };
                    let url = rq.url().to_string();
                    if url == "/rootDesc.xml" {
                        let xml = format!("<?xml version=\"1.0\"?><root><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><deviceList><device><deviceList><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:{svc}</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>/ctl/IPConn</controlURL></service></serviceList></device></deviceList></device></deviceList></device></root>");
                        let _ = rq.respond(tiny_http::Response::from_string(xml));
                        continue;
                    }
                    let action = rq
                        .headers()
                        .iter()
                        .find(|h| h.field.equiv("SOAPAction"))
                        .map(|h| {
                            h.value
                                .as_str()
                                .trim_matches('"')
                                .rsplit('#')
                                .next()
                                .unwrap_or("")
                                .to_string()
                        })
                        .unwrap_or_default();
                    let mut body = String::new();
                    let _ = rq.as_reader().read_to_string(&mut body);
                    ac.lock().unwrap().push(action.clone());
                    let arg = |k: &str| xml_text(&body, k).unwrap_or_default();
                    let ok = |inner: String| {
                        format!("<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action}Response xmlns:u=\"urn:schemas-upnp-org:service:{svc}\">{inner}</u:{action}Response></s:Body></s:Envelope>")
                    };
                    let fault = |code: u32, text: &str| {
                        format!("<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>{code}</errorCode><errorDescription>{text}</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>")
                    };
                    let key = (
                        arg("NewProtocol"),
                        arg("NewExternalPort").parse::<u16>().unwrap_or(0),
                    );
                    let (status, out) = match action.as_str() {
                        "GetExternalIPAddress" => (200, ok("<NewExternalIPAddress>203.0.113.5</NewExternalIPAddress>".into())),
                        "GetSpecificPortMappingEntry" => match tb.lock().unwrap().get(&key) {
                            Some(e) => (200, ok(format!("<NewInternalPort>{}</NewInternalPort><NewInternalClient>{}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{}</NewPortMappingDescription><NewLeaseDuration>{}</NewLeaseDuration>", e.iport, e.client, e.desc, e.lease))),
                            None => (500, fault(714, "NoSuchEntryInArray")),
                        },
                        "AddPortMapping" | "AddAnyPortMapping" => {
                            let lease: u64 = arg("NewLeaseDuration").parse().unwrap_or(0);
                            let e = Entry { client: arg("NewInternalClient"), iport: arg("NewInternalPort").parse().unwrap_or(0), desc: arg("NewPortMappingDescription"), lease };
                            let mut t = tb.lock().unwrap();
                            if permanent_only && lease != 0 {
                                (500, fault(725, "OnlyPermanentLeasesSupported"))
                            } else if action == "AddAnyPortMapping" {
                                let mut p = key.1;
                                while t.contains_key(&(key.0.clone(), p)) { p += 1; }
                                t.insert((key.0.clone(), p), e);
                                (200, ok(format!("<NewReservedPort>{p}</NewReservedPort>")))
                            } else if t.get(&key).is_some_and(|x| x.client != e.client) {
                                (500, fault(718, "ConflictInMappingEntry"))
                            } else {
                                t.insert(key, e);
                                (200, ok(String::new()))
                            }
                        }
                        "DeletePortMapping" => match tb.lock().unwrap().remove(&key) {
                            Some(_) => (200, ok(String::new())),
                            None => (500, fault(714, "NoSuchEntryInArray")),
                        },
                        _ => (500, fault(401, "Invalid Action")),
                    };
                    let _ =
                        rq.respond(tiny_http::Response::from_string(out).with_status_code(status));
                }
            });
            FakeIgd {
                ssdp: ssdp_addr,
                table,
                actions,
                stop,
            }
        }
        fn count(&self, action: &str) -> usize {
            self.actions
                .lock()
                .unwrap()
                .iter()
                .filter(|a| *a == action)
                .count()
        }
    }

    impl Drop for FakeIgd {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    fn me() -> String {
        local_ip_toward("127.0.0.1:9".parse().unwrap())
            .unwrap()
            .to_string()
    }

    #[test]
    fn upnp_maps_after_pcp_and_natpmp_fail_renews_and_removes() {
        let igd = FakeIgd::start(false, false);
        let (_q, nobody) = silent();
        let mut m = PortMapper::new(17893, opts(vec![nobody], igd.ssdp));
        let t0 = Instant::now();
        assert!(m.tick(t0));
        let s = m.status();
        assert_eq!(s.method, Some(Method::Upnp), "{s:?}");
        assert_eq!(
            s.describe(),
            "router port opened via UPnP: 203.0.113.5:17893"
        );
        assert_eq!(s.lease_secs, 3600);
        {
            let t = igd.table.lock().unwrap();
            let e = t.get(&("TCP".to_string(), 17893)).unwrap();
            assert_eq!(e.desc, DESCRIPTION);
            assert_eq!(e.lease, 3600);
            assert_eq!(e.client, me());
            assert!(t.contains_key(&("UDP".to_string(), 17893)));
        }
        assert_eq!(igd.count("AddPortMapping"), 2);
        m.tick(t0 + Duration::from_secs(1800));
        assert_eq!(igd.count("AddPortMapping"), 4);
        m.remove_all();
        assert!(igd.table.lock().unwrap().is_empty());
        assert_eq!(igd.count("DeletePortMapping"), 2);
    }

    #[test]
    fn upnp_leaves_another_computers_mapping_alone() {
        let igd = FakeIgd::start(false, false);
        igd.table.lock().unwrap().insert(
            ("TCP".into(), 17893),
            Entry {
                client: "192.168.1.77".into(),
                iport: 17893,
                desc: "game console".into(),
                lease: 0,
            },
        );
        let (_q, nobody) = silent();
        let mut m = PortMapper::new(17893, opts(vec![nobody], igd.ssdp));
        m.tick(Instant::now());
        let tcp = m.external(Proto::Tcp).unwrap();
        assert_ne!(tcp.port(), 17893);
        assert_eq!(m.external(Proto::Udp).unwrap().port(), 17893);
        let other = igd
            .table
            .lock()
            .unwrap()
            .get(&("TCP".into(), 17893))
            .cloned()
            .unwrap();
        assert_eq!(other.client, "192.168.1.77");
        m.remove_all();
        // Only ours went.
        let t = igd.table.lock().unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(&("TCP".into(), 17893)).unwrap().desc, "game console");
    }

    #[test]
    fn upnp_igd2_uses_add_any_on_conflict() {
        let igd = FakeIgd::start(true, false);
        igd.table.lock().unwrap().insert(
            ("UDP".into(), 17893),
            Entry {
                client: "192.168.1.77".into(),
                iport: 17893,
                desc: "x".into(),
                lease: 0,
            },
        );
        let (_q, nobody) = silent();
        let mut m = PortMapper::new(17893, opts(vec![nobody], igd.ssdp));
        m.tick(Instant::now());
        assert_eq!(m.external(Proto::Udp).unwrap().port(), 17894);
        assert_eq!(igd.count("AddAnyPortMapping"), 1);
    }

    #[test]
    fn upnp_uses_a_hand_made_mapping_without_touching_it() {
        let igd = FakeIgd::start(false, false);
        for p in ["TCP", "UDP"] {
            igd.table.lock().unwrap().insert(
                (p.into(), 17893),
                Entry {
                    client: me(),
                    iport: 17893,
                    desc: "my forward".into(),
                    lease: 0,
                },
            );
        }
        let (_q, nobody) = silent();
        let mut m = PortMapper::new(17893, opts(vec![nobody], igd.ssdp));
        let t0 = Instant::now();
        m.tick(t0);
        let s = m.status();
        assert_eq!(s.state, "mapped");
        assert!(s.existing);
        assert_eq!(
            s.describe(),
            "router port already open via UPnP: 203.0.113.5:17893"
        );
        assert_eq!(igd.count("AddPortMapping"), 0);
        assert_eq!(m.next_due(), None);
        m.tick(t0 + Duration::from_secs(7200));
        m.remove_all();
        assert_eq!(
            igd.count("AddPortMapping") + igd.count("DeletePortMapping"),
            0
        );
        assert_eq!(igd.table.lock().unwrap().len(), 2);
    }

    #[test]
    fn upnp_takes_over_its_own_leftover_and_handles_permanent_only_routers() {
        let igd = FakeIgd::start(false, true);
        igd.table.lock().unwrap().insert(
            ("TCP".into(), 17893),
            Entry {
                client: me(),
                iport: 17893,
                desc: DESCRIPTION.into(),
                lease: 0,
            },
        );
        let (_q, nobody) = silent();
        let mut m = PortMapper::new(17893, opts(vec![nobody], igd.ssdp));
        m.tick(Instant::now());
        let s = m.status();
        assert_eq!(s.state, "mapped");
        assert!(!s.existing);
        assert_eq!(s.lease_secs, 0);
        assert_eq!(m.next_due(), None);
        m.remove_all();
        assert!(igd.table.lock().unwrap().is_empty());
    }

    #[test]
    fn ssdp_answers_pointing_elsewhere_are_ignored() {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let served = Arc::new(AtomicUsize::new(0));
        let s2 = served.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            while let Ok((_, from)) = sock.recv_from(&mut buf) {
                let _ = sock.send_to(
                    b"HTTP/1.1 200 OK\r\nLOCATION: http://198.51.100.7:80/d.xml\r\n\r\n",
                    from,
                );
                s2.fetch_add(1, Ordering::Relaxed);
            }
        });
        let found = ssdp_search(addr, Duration::from_millis(300)).unwrap();
        assert!(found.is_empty());
        assert!(served.load(Ordering::Relaxed) >= 1);
    }
}
