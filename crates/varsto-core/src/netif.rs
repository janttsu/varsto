// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Which local address to show for the pairing offer (spec section 68).
//!
//! The old code asked the OS which address it would use towards a public
//! host. With a VPN that carries the default route (or a tunnel the OS
//! prefers) that is not the Wi-Fi address the new device can reach.
//! [`interfaces`] lists every IPv4 interface address and [`rank`] orders
//! them: private addresses on real, up interfaces first, then public ones,
//! then VPN-like ones; never loopback, link-local or virtual bridges.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

/// One IPv4 address of one network interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Iface {
    pub name: String,
    pub ip: Ipv4Addr,
    /// Prefix length of the subnet mask (0 to 32).
    pub prefix: u8,
    /// Administratively up and running.
    pub up: bool,
    pub loopback: bool,
}

/// How an address ranks as a place to reach this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// Private address on a physical-looking interface (Wi-Fi, Ethernet).
    Lan,
    /// Public address on a physical-looking interface.
    Public,
    /// Carrier-grade NAT range (100.64/10, mobile data) or a tunnel
    /// interface (VPN): reachable only by peers on the same overlay.
    Overlay,
}

/// A usable address with its subnet, best first in [`rank`]'s result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub ip: Ipv4Addr,
    pub prefix: u8,
    pub name: String,
    pub kind: Kind,
}

/// At most this many candidates are offered (and put in a pairing link).
pub const MAX_CANDIDATES: usize = 8;

/// Interfaces a phone or another computer can never reach us on: container
/// and VM bridges, Apple's peer-to-peer and low-latency Wi-Fi links.
fn is_unreachable_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const PREFIXES: &[&str] = &[
        "docker",
        "br-",
        "veth",
        "virbr",
        "vmnet",
        "vboxnet",
        "vmenet",
        "awdl",
        "llw",
        "lo",
        "bridge",
        "anpi",
        "ap",
        "gif",
        "stf",
        "cni",
        "flannel",
        "cali",
        "podman",
        "lxc",
        "lxd",
        "vethernet",
        "vmware",
        "virtualbox",
        "hyper-v",
        "wsl",
    ];
    PREFIXES.iter().any(|p| n.starts_with(p))
}

/// Tunnel interfaces (VPN): usable only for peers on the same overlay.
fn is_tunnel_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    const PREFIXES: &[&str] = &[
        "utun",
        "tun",
        "tap",
        "ppp",
        "wg",
        "tailscale",
        "zt",
        "ipsec",
        "nordlynx",
        "proton",
        "mullvad",
        "wintun",
    ];
    PREFIXES.iter().any(|p| n.starts_with(p))
}

fn is_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (64..128).contains(&o[1])
}

/// Rank the interface addresses: usable ones best first, the same address
/// only once, at most [`MAX_CANDIDATES`]. Skipped: loopback, down
/// interfaces, 0.0.0.0, 169.254/16, multicast, broadcast, and interfaces
/// that a peer cannot reach (container bridges and so on).
pub fn rank(ifaces: &[Iface]) -> Vec<Candidate> {
    let mut out: Vec<(usize, Candidate)> = Vec::new();
    for (i, f) in ifaces.iter().enumerate() {
        let ip = f.ip;
        if f.loopback
            || !f.up
            || ip.is_unspecified()
            || ip.is_loopback()
            || ip.is_link_local()
            || ip.is_multicast()
            || ip.is_broadcast()
            || is_unreachable_name(&f.name)
            || out.iter().any(|(_, c)| c.ip == ip)
        {
            continue;
        }
        let kind = if is_tunnel_name(&f.name) || is_cgnat(ip) {
            Kind::Overlay
        } else if ip.is_private() {
            Kind::Lan
        } else {
            Kind::Public
        };
        out.push((
            i,
            Candidate {
                ip,
                prefix: f.prefix.min(32),
                name: f.name.clone(),
                kind,
            },
        ));
    }
    // Best kind first; within a kind the OS order (usually the primary
    // interface first), which sorting by index keeps.
    out.sort_by_key(|(i, c)| (c.kind, *i));
    out.into_iter()
        .map(|(_, c)| c)
        .take(MAX_CANDIDATES)
        .collect()
}

/// Does `ip` lie in the subnet `net`/`prefix`?
pub fn same_subnet(ip: Ipv4Addr, net: Ipv4Addr, prefix: u8) -> bool {
    let p = u32::from(prefix.min(32));
    if p == 0 {
        return false;
    }
    let mask = u32::MAX << (32 - p);
    u32::from(ip) & mask == u32::from(net) & mask
}

/// Put the addresses that share a subnet with one of our own interfaces
/// first (the other device is then on the same network), keeping the order
/// otherwise. `own` is what [`interfaces`] returned on the joining device.
pub fn sort_by_reach(addrs: &mut [SocketAddr], own: &[Iface]) {
    let reach = |a: &SocketAddr| match a.ip() {
        IpAddr::V4(v4) => own.iter().any(|f| {
            f.up && !f.loopback && !f.ip.is_link_local() && same_subnet(v4, f.ip, f.prefix)
        }),
        IpAddr::V6(_) => false,
    };
    addrs.sort_by_key(|a| !reach(a));
}

/// The directed broadcast address of a candidate's subnet.
pub fn broadcast_of(c: &Candidate) -> Ipv4Addr {
    let p = u32::from(c.prefix.clamp(1, 30));
    let host = u32::MAX >> p;
    Ipv4Addr::from(u32::from(c.ip) | host)
}

/// Every IPv4 interface address of this host. Where the platform call is
/// not available (or lists nothing) the address towards a public host is
/// returned alone, as older versions did.
pub fn interfaces() -> Vec<Iface> {
    #[cfg(unix)]
    let mut v: Vec<Iface> = unix_interfaces();
    #[cfg(not(unix))]
    let mut v: Vec<Iface> = Vec::new();
    if v.is_empty() {
        if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
            if s.connect("192.0.2.1:9").is_ok() {
                if let Ok(SocketAddr::V4(a)) = s.local_addr() {
                    v.push(Iface {
                        name: "default".into(),
                        ip: *a.ip(),
                        prefix: 24,
                        up: true,
                        loopback: a.ip().is_loopback(),
                    });
                }
            }
        }
    }
    v
}

/// The ranked candidates of this host.
pub fn candidates() -> Vec<Candidate> {
    rank(&interfaces())
}

#[cfg(unix)]
fn unix_interfaces() -> Vec<Iface> {
    use std::ffi::CStr;
    let mut out = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list that freeifaddrs releases;
    // the list is only read while it is alive and every pointer is checked.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let a = &*cur;
            cur = a.ifa_next;
            if a.ifa_addr.is_null() || i32::from((*a.ifa_addr).sa_family) != libc::AF_INET {
                continue;
            }
            let sin = &*(a.ifa_addr as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let prefix = if a.ifa_netmask.is_null() {
                24
            } else {
                let m = &*(a.ifa_netmask as *const libc::sockaddr_in);
                u32::from_be(m.sin_addr.s_addr).count_ones() as u8
            };
            let flags = a.ifa_flags as i32;
            let name = if a.ifa_name.is_null() {
                String::new()
            } else {
                CStr::from_ptr(a.ifa_name).to_string_lossy().into_owned()
            };
            out.push(Iface {
                name,
                ip,
                prefix,
                up: flags & libc::IFF_UP != 0 && flags & libc::IFF_RUNNING != 0,
                loopback: flags & libc::IFF_LOOPBACK != 0,
            });
        }
        libc::freeifaddrs(head);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(name: &str, ip: [u8; 4], prefix: u8, up: bool) -> Iface {
        Iface {
            name: name.into(),
            ip: Ipv4Addr::from(ip),
            prefix,
            up,
            loopback: name.starts_with("lo"),
        }
    }

    fn names(c: &[Candidate]) -> Vec<String> {
        c.iter().map(|c| format!("{}={}", c.name, c.ip)).collect()
    }

    #[test]
    fn wifi_wins_over_vpn_docker_and_link_local() {
        // A MacBook on a VPN with a VM bridge and stale link-local addresses.
        let table = [
            f("lo0", [127, 0, 0, 1], 8, true),
            f("utun3", [10, 8, 0, 2], 24, true),
            f("bridge100", [192, 168, 64, 1], 24, true),
            f("awdl0", [169, 254, 7, 7], 16, true),
            f("en1", [169, 254, 1, 2], 16, true),
            f("en0", [192, 168, 1, 23], 24, true),
            f("vmnet8", [172, 16, 5, 1], 24, true),
        ];
        let c = rank(&table);
        assert_eq!(names(&c), ["en0=192.168.1.23", "utun3=10.8.0.2"]);
        assert_eq!(c[0].kind, Kind::Lan);
        assert_eq!(c[1].kind, Kind::Overlay);
    }

    #[test]
    fn linux_table_skips_docker_down_and_duplicates() {
        let table = [
            f("lo", [127, 0, 0, 1], 8, true),
            f("docker0", [172, 17, 0, 1], 16, true),
            f("br-1a2b3c", [172, 18, 0, 1], 16, true),
            f("veth9", [10, 99, 0, 1], 24, true),
            f("tailscale0", [100, 101, 102, 103], 32, true),
            f("wlan0", [192, 168, 0, 7], 24, true),
            f("eth0", [10, 0, 0, 5], 24, false),
            f("wlan0:1", [192, 168, 0, 7], 24, true),
            f("enp3s0", [203, 0, 113, 9], 24, true),
        ];
        assert_eq!(
            names(&rank(&table)),
            [
                "wlan0=192.168.0.7",
                "enp3s0=203.0.113.9",
                "tailscale0=100.101.102.103"
            ]
        );
    }

    #[test]
    fn android_wlan_and_mobile_data() {
        let table = [
            f("lo", [127, 0, 0, 1], 8, true),
            f("rmnet_data1", [100, 72, 3, 4], 28, true),
            f("wlan0", [192, 168, 43, 120], 24, true),
        ];
        // The carrier NAT address ranks after the Wi-Fi one.
        assert_eq!(
            names(&rank(&table)),
            ["wlan0=192.168.43.120", "rmnet_data1=100.72.3.4"]
        );
    }

    #[test]
    fn nothing_usable_gives_nothing_and_the_list_is_capped() {
        assert!(rank(&[f("lo", [127, 0, 0, 1], 8, true)]).is_empty());
        let many: Vec<Iface> = (0..20)
            .map(|i| f(&format!("en{i}"), [10, 0, i, 1], 24, true))
            .collect();
        let c = rank(&many);
        assert_eq!(c.len(), MAX_CANDIDATES);
        assert_eq!(c[0].name, "en0");
    }

    #[test]
    fn subnet_ordering_for_the_joining_side() {
        let own = [
            f("lo0", [127, 0, 0, 1], 8, true),
            f("en0", [192, 168, 1, 40], 24, true),
        ];
        let mut a: Vec<SocketAddr> = ["10.8.0.2:5000", "192.168.1.23:5000", "192.168.9.9:5000"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        sort_by_reach(&mut a, &own);
        assert_eq!(a[0].to_string(), "192.168.1.23:5000");
        assert_eq!(a[1].to_string(), "10.8.0.2:5000", "others keep their order");
        assert!(same_subnet(
            Ipv4Addr::new(192, 168, 1, 200),
            Ipv4Addr::new(192, 168, 1, 40),
            24
        ));
        assert!(!same_subnet(
            Ipv4Addr::new(192, 168, 2, 1),
            Ipv4Addr::new(192, 168, 1, 40),
            24
        ));
    }

    #[test]
    fn directed_broadcast_uses_the_real_mask() {
        let c = |ip: [u8; 4], prefix| Candidate {
            ip: Ipv4Addr::from(ip),
            prefix,
            name: "en0".into(),
            kind: Kind::Lan,
        };
        assert_eq!(
            broadcast_of(&c([192, 168, 1, 23], 24)),
            Ipv4Addr::new(192, 168, 1, 255)
        );
        assert_eq!(
            broadcast_of(&c([10, 1, 2, 3], 16)),
            Ipv4Addr::new(10, 1, 255, 255)
        );
        assert_eq!(
            broadcast_of(&c([172, 16, 5, 9], 20)),
            Ipv4Addr::new(172, 16, 15, 255)
        );
    }

    #[test]
    fn this_host_lists_only_usable_addresses() {
        for c in candidates() {
            assert!(!c.ip.is_loopback() && !c.ip.is_link_local());
        }
    }
}
