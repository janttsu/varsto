// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Rate limits (spec 83.8): token buckets per client address (IPv6 by
//! /64) and per tag, per class of request. The [`RateLimit`] trait is the
//! hook; [`Buckets`] the default. Each class has its own map, so a flood
//! of one class cannot fill the map that admits clients of another. Nothing
//! here is logged or kept longer than a bucket needs to refill.

use crate::proto::Tag;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// What is being limited.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    Put,
    Lookup,
    /// Opening a control connection.
    Control,
    /// `punch` and `relay` requests.
    Coordinate,
    /// Opening a relay stream.
    Relay,
    /// UDP observe datagrams.
    Udp,
    /// `info` and `health`.
    Meta,
}

/// Requests per minute per address and per tag, by class (0: no limit).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateConfig {
    pub put_per_ip: u32,
    pub lookup_per_ip: u32,
    pub control_per_ip: u32,
    pub coordinate_per_ip: u32,
    pub relay_per_ip: u32,
    pub udp_per_ip: u32,
    pub meta_per_ip: u32,
    pub put_per_tag: u32,
    pub lookup_per_tag: u32,
    pub coordinate_per_tag: u32,
}

impl Default for RateConfig {
    fn default() -> RateConfig {
        RateConfig {
            put_per_ip: 60,
            lookup_per_ip: 120,
            control_per_ip: 20,
            coordinate_per_ip: 60,
            relay_per_ip: 60,
            udp_per_ip: 600,
            meta_per_ip: 120,
            put_per_tag: 120,
            lookup_per_tag: 240,
            coordinate_per_tag: 60,
        }
    }
}

impl RateConfig {
    fn per_ip(&self, c: Class) -> u32 {
        match c {
            Class::Put => self.put_per_ip,
            Class::Lookup => self.lookup_per_ip,
            Class::Control => self.control_per_ip,
            Class::Coordinate => self.coordinate_per_ip,
            Class::Relay => self.relay_per_ip,
            Class::Udp => self.udp_per_ip,
            Class::Meta => self.meta_per_ip,
        }
    }
    fn per_tag(&self, c: Class) -> u32 {
        match c {
            Class::Put => self.put_per_tag,
            Class::Lookup => self.lookup_per_tag,
            Class::Coordinate => self.coordinate_per_tag,
            _ => 0,
        }
    }
    /// No limits at all (tests).
    pub fn unlimited() -> RateConfig {
        RateConfig {
            put_per_ip: 0,
            lookup_per_ip: 0,
            control_per_ip: 0,
            coordinate_per_ip: 0,
            relay_per_ip: 0,
            udp_per_ip: 0,
            meta_per_ip: 0,
            put_per_tag: 0,
            lookup_per_tag: 0,
            coordinate_per_tag: 0,
        }
    }
}

/// The rate-limit hook. `allow_ip` and `allow_tag` take one token each.
pub trait RateLimit: Send + Sync {
    fn allow_ip(&self, class: Class, ip: IpAddr, now: Instant) -> bool;
    fn allow_tag(&self, class: Class, tag: &Tag, now: Instant) -> bool;
    /// Forget buckets that are full again (called once a minute).
    fn prune(&self, _now: Instant) {}
}

/// The key of an address: IPv4 as it is, IPv6 by its /64 (one household
/// or one host usually holds a whole /64).
pub fn ip_key(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.to_ipv6_mapped().octets();
            }
            let mut o = v6.octets();
            o[8..].fill(0);
            o
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SubKey {
    Ip([u8; 16]),
    Tag(Tag),
}

/// Token buckets: capacity one minute's worth, refilled continuously.
/// One map per [`Class`]. The cap is per map.
pub struct Buckets {
    cfg: RateConfig,
    max_buckets: usize,
    maps: [Mutex<HashMap<SubKey, Bucket>>; CLASS_COUNT],
}

/// Most buckets one class keeps. Past this, new keys of that class are
/// refused until a prune. A flood of fresh addresses must not grow memory
/// without end, and must not spend a budget that belongs to another class.
/// The UDP observe port answers any source, so its map is the one a spoofed
/// flood can fill; puts, lookups and control connections have their own.
const MAX_BUCKETS: usize = 200_000;

const CLASS_COUNT: usize = 7;

impl Class {
    fn index(self) -> usize {
        match self {
            Class::Put => 0,
            Class::Lookup => 1,
            Class::Control => 2,
            Class::Coordinate => 3,
            Class::Relay => 4,
            Class::Udp => 5,
            Class::Meta => 6,
        }
    }
}

impl Buckets {
    pub fn new(cfg: RateConfig) -> Buckets {
        Self::with_max(cfg, MAX_BUCKETS)
    }

    fn with_max(cfg: RateConfig, max_buckets: usize) -> Buckets {
        Buckets {
            cfg,
            max_buckets,
            maps: std::array::from_fn(|_| Mutex::new(HashMap::new())),
        }
    }

    fn map(&self, class: Class) -> &Mutex<HashMap<SubKey, Bucket>> {
        &self.maps[class.index()]
    }

    fn take(&self, class: Class, key: SubKey, per_min: u32, now: Instant) -> bool {
        if per_min == 0 {
            return true;
        }
        let cap = per_min as f64;
        let mut map = self.map(class).lock().unwrap_or_else(|e| e.into_inner());
        if !map.contains_key(&key) && map.len() >= self.max_buckets {
            return false;
        }
        let b = map.entry(key).or_insert(Bucket {
            tokens: cap,
            at: now,
        });
        let dt = now.saturating_duration_since(b.at).as_secs_f64();
        b.tokens = (b.tokens + dt * cap / 60.0).min(cap);
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub fn len(&self) -> usize {
        self.maps
            .iter()
            .map(|m| m.lock().unwrap_or_else(|e| e.into_inner()).len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl RateLimit for Buckets {
    fn allow_ip(&self, class: Class, ip: IpAddr, now: Instant) -> bool {
        self.take(class, SubKey::Ip(ip_key(ip)), self.cfg.per_ip(class), now)
    }
    fn allow_tag(&self, class: Class, tag: &Tag, now: Instant) -> bool {
        self.take(class, SubKey::Tag(*tag), self.cfg.per_tag(class), now)
    }
    fn prune(&self, now: Instant) {
        for map in &self.maps {
            let mut map = map.lock().unwrap_or_else(|e| e.into_inner());
            map.retain(|_, b| now.saturating_duration_since(b.at) < Duration::from_secs(60));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn a_bucket_allows_a_minute_s_worth_and_refills() {
        let b = Buckets::new(RateConfig {
            put_per_ip: 3,
            ..RateConfig::default()
        });
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let t0 = Instant::now();
        assert!(b.allow_ip(Class::Put, ip, t0));
        assert!(b.allow_ip(Class::Put, ip, t0));
        assert!(b.allow_ip(Class::Put, ip, t0));
        assert!(!b.allow_ip(Class::Put, ip, t0));
        // Another address and another class have their own buckets.
        assert!(b.allow_ip(Class::Put, "192.0.2.2".parse().unwrap(), t0));
        assert!(b.allow_ip(Class::Lookup, ip, t0));
        // 20 s give back one token of three a minute.
        assert!(b.allow_ip(Class::Put, ip, t0 + Duration::from_secs(20)));
        assert!(!b.allow_ip(Class::Put, ip, t0 + Duration::from_secs(20)));
        b.prune(t0 + Duration::from_secs(200));
        assert!(b.is_empty());
    }

    #[test]
    fn ipv6_counts_by_its_64_and_mapped_v4_as_v4() {
        let a: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        let c: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(ip_key(a), ip_key(b));
        assert_ne!(ip_key(a), ip_key(c));
        let v4: IpAddr = "192.0.2.1".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        assert_eq!(ip_key(v4), ip_key(mapped));
    }

    #[test]
    fn tags_are_limited_on_their_own() {
        let b = Buckets::new(RateConfig {
            put_per_tag: 1,
            ..RateConfig::default()
        });
        let t0 = Instant::now();
        assert!(b.allow_tag(Class::Put, &[1; 16], t0));
        assert!(!b.allow_tag(Class::Put, &[1; 16], t0));
        assert!(b.allow_tag(Class::Put, &[2; 16], t0));
        // Classes without a per-tag limit always pass.
        assert!(b.allow_tag(Class::Relay, &[1; 16], t0));
        let u = Buckets::new(RateConfig::unlimited());
        for _ in 0..1000 {
            assert!(u.allow_ip(Class::Udp, "192.0.2.1".parse().unwrap(), t0));
        }
    }

    #[test]
    fn a_full_udp_map_does_not_block_other_classes() {
        // The cap is per class. Filling the observe map (the one a spoofed
        // source can fill, because UDP does not check the sender) must
        // still leave room for a new TCP client.
        let b = Buckets::with_max(
            RateConfig {
                udp_per_ip: 1,
                put_per_ip: 1,
                lookup_per_ip: 1,
                control_per_ip: 1,
                coordinate_per_ip: 1,
                relay_per_ip: 1,
                meta_per_ip: 1,
                ..RateConfig::default()
            },
            3,
        );
        let t0 = Instant::now();
        for i in 1..=3u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(i));
            assert!(b.allow_ip(Class::Udp, ip, t0), "{ip}");
        }
        let fresh = IpAddr::V4(Ipv4Addr::from(99));
        assert!(
            !b.allow_ip(Class::Udp, fresh, t0),
            "a new observe address is refused once that map is full"
        );
        // An address that already has a bucket is not a new key: it is
        // limited by its own tokens, and those refill while the map is full.
        let known = IpAddr::V4(Ipv4Addr::from(1));
        assert!(!b.allow_ip(Class::Udp, known, t0));
        assert!(b.allow_ip(Class::Udp, known, t0 + Duration::from_secs(60)));
        assert!(!b.allow_ip(Class::Udp, fresh, t0 + Duration::from_secs(60)));
        for class in [
            Class::Put,
            Class::Lookup,
            Class::Control,
            Class::Coordinate,
            Class::Relay,
            Class::Meta,
        ] {
            assert!(
                b.allow_ip(class, fresh, t0),
                "{class:?} must still admit a new address"
            );
        }
        assert!(b.allow_tag(Class::Put, &[7; 16], t0));
        // The other way round: a full put map does not lock out observe.
        // Observe is already full, so use a second limiter for this direction.
        let puts = Buckets::with_max(
            RateConfig {
                put_per_ip: 1,
                udp_per_ip: 1,
                ..RateConfig::default()
            },
            2,
        );
        assert!(puts.allow_ip(Class::Put, IpAddr::V4(Ipv4Addr::from(1)), t0));
        assert!(puts.allow_ip(Class::Put, IpAddr::V4(Ipv4Addr::from(2)), t0));
        assert!(!puts.allow_ip(Class::Put, fresh, t0));
        assert!(puts.allow_ip(Class::Udp, fresh, t0));
        b.prune(t0 + Duration::from_secs(121));
        assert!(b.allow_ip(Class::Udp, fresh, t0 + Duration::from_secs(121)));
    }
}
