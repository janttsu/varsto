// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Durability policies (F-032): "at least two cloud copies and one at home,
//! verified within 30 days". A policy belongs to a folder, travels with the
//! folder record, and is evaluated on every device from the ledger alone, so
//! every device reaches the same verdict without talking to the others.
//!
//! States: `ok`, `at_risk` (still true, but about to stop being true: a
//! verification is ageing out, or the margin is zero and a copy sits on
//! media that cannot be read right now), `violated`, `unknown` (a storage
//! could not be checked).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Policy {
    /// Minimum number of storages (any place, carriers excluded) holding every chunk.
    #[serde(default)]
    pub min_copies: u32,
    /// Minimum copies per place, e.g. {"cloud": 2, "home": 1}.
    #[serde(default)]
    pub min_per_place: BTreeMap<String, u32>,
    /// Every chunk must have been verified by a device other than its writer
    /// within this many days.
    #[serde(default)]
    pub verified_within_days: Option<u32>,
}

/// How a place reads in sentences: the two default places by what they
/// are (a directory or disk pool is "home", S3 and rclone are "cloud"),
/// other labels as given.
pub fn place_phrase(place: &str) -> String {
    match place {
        "home" => "on your own devices and disks".to_string(),
        "cloud" => "in external storage (S3 and the like)".to_string(),
        other => format!("in place '{other}'"),
    }
}

impl Policy {
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.min_copies > 0 {
            parts.push(format!(
                "at least {} cop{}",
                self.min_copies,
                if self.min_copies == 1 { "y" } else { "ies" }
            ));
        }
        for (place, n) in &self.min_per_place {
            parts.push(format!("{n} {}", place_phrase(place)));
        }
        if let Some(d) = self.verified_within_days {
            parts.push(format!("verified within {d} days"));
        }
        if parts.is_empty() {
            "no requirements".to_string()
        } else {
            parts.join(", ")
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum PolicyState {
    Ok,
    AtRisk,
    Violated,
    Unknown,
}

impl PolicyState {
    pub fn exit_code(self) -> i32 {
        match self {
            PolicyState::Ok => 0,
            PolicyState::AtRisk => 1,
            PolicyState::Violated => 2,
            PolicyState::Unknown => 3,
        }
    }
}

/// One chunk's standing against the policy.
pub struct ChunkFacts {
    /// Storage name -> (place, verified by someone other than the writer, newest verification time).
    pub copies: Vec<(String, String, bool, i64)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyReport {
    pub folder: String,
    pub policy: Policy,
    pub state: PolicyState,
    pub chunks: u64,
    pub chunks_short_of_copies: u64,
    pub chunks_short_per_place: BTreeMap<String, u64>,
    pub chunks_unverified_in_window: u64,
    /// Days since the oldest verification that still satisfies the window.
    pub oldest_verification_days: Option<i64>,
    pub reasons: Vec<String>,
    /// What will break the policy if nothing is done.
    pub warnings: Vec<String>,
}

pub fn evaluate(
    folder: &str,
    policy: &Policy,
    chunks: &[ChunkFacts],
    unreadable_places: &BTreeMap<String, Vec<String>>, // place -> storages that cannot be read now (cold, carrier away)
    storages_unknown: &[String],
    now_utc: i64,
) -> PolicyReport {
    let mut short_copies = 0u64;
    let mut short_place: BTreeMap<String, u64> = BTreeMap::new();
    let mut unverified = 0u64;
    let mut oldest_ok: Option<i64> = None;
    let mut zero_margin_on_unreadable = 0u64;
    let mut ageing = 0u64;
    let window = policy.verified_within_days.map(|d| d as i64 * 86_400);
    for c in chunks {
        let copies = c.copies.len() as u64;
        if copies < policy.min_copies as u64 {
            short_copies += 1;
        } else if copies == policy.min_copies as u64
            && policy.min_copies > 0
            && c.copies.iter().any(|(name, place, _, _)| {
                unreadable_places
                    .get(place)
                    .is_some_and(|v| v.contains(name))
            })
        {
            zero_margin_on_unreadable += 1;
        }
        for (place, n) in &policy.min_per_place {
            let have = c.copies.iter().filter(|(_, p, _, _)| p == place).count() as u32;
            if have < *n {
                *short_place.entry(place.clone()).or_default() += 1;
            }
        }
        if let Some(w) = window {
            let newest = c
                .copies
                .iter()
                .filter(|(_, _, verified, _)| *verified)
                .map(|(_, _, _, t)| *t)
                .max();
            match newest {
                Some(t) if now_utc - t <= w => {
                    oldest_ok = Some(oldest_ok.map_or(t, |o: i64| o.min(t)));
                    if now_utc - t > w * 3 / 4 {
                        ageing += 1;
                    }
                }
                _ => unverified += 1,
            }
        }
    }
    let mut reasons = Vec::new();
    let mut warnings = Vec::new();
    if short_copies > 0 {
        reasons.push(format!(
            "{short_copies} chunks have fewer than {} copies",
            policy.min_copies
        ));
    }
    for (place, n) in &short_place {
        reasons.push(format!(
            "{n} chunks have fewer than {} copies {}",
            policy.min_per_place[place],
            place_phrase(place)
        ));
    }
    if unverified > 0 {
        reasons.push(format!(
            "{unverified} chunks were not verified by another device within {} days",
            policy.verified_within_days.unwrap_or(0)
        ));
    }
    if ageing > 0 {
        warnings.push(format!(
            "{ageing} chunks have a verification older than three quarters of the {}-day window: another device renews them with its automatic verification (`varsto verify`) or with `varsto fsck --verify`",
            policy.verified_within_days.unwrap_or(0)
        ));
    }
    if zero_margin_on_unreadable > 0 {
        warnings.push(format!(
            "{zero_margin_on_unreadable} chunks meet the copy count exactly, and one copy is on media that cannot be read right now (cold storage or a transferrer that is away)"
        ));
    }
    if !storages_unknown.is_empty() {
        warnings.push(format!(
            "storages that could not be checked: {}",
            storages_unknown.join(", ")
        ));
    }
    let state = if !reasons.is_empty() {
        PolicyState::Violated
    } else if !storages_unknown.is_empty() {
        PolicyState::Unknown
    } else if !warnings.is_empty() {
        PolicyState::AtRisk
    } else {
        PolicyState::Ok
    };
    PolicyReport {
        folder: folder.to_string(),
        policy: policy.clone(),
        state,
        chunks: chunks.len() as u64,
        chunks_short_of_copies: short_copies,
        chunks_short_per_place: short_place,
        chunks_unverified_in_window: unverified,
        oldest_verification_days: oldest_ok.map(|t| (now_utc - t) / 86_400),
        reasons,
        warnings,
    }
}

/// Parse `cloud=2` style specs.
pub fn parse_place_spec(s: &str) -> Option<(String, u32)> {
    let (p, n) = s.split_once('=')?;
    Some((p.trim().to_string(), n.trim().parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(copies: &[(&str, &str, bool, i64)]) -> ChunkFacts {
        ChunkFacts {
            copies: copies
                .iter()
                .map(|(n, p, v, t)| (n.to_string(), p.to_string(), *v, *t))
                .collect(),
        }
    }

    #[test]
    fn states_follow_the_rules() {
        let now = 2_000_000_000;
        let day = 86_400;
        let policy = Policy {
            min_copies: 2,
            min_per_place: [("cloud".to_string(), 1)].into_iter().collect(),
            verified_within_days: Some(30),
        };
        let none = BTreeMap::new();
        // Two copies, one cloud, verified recently: ok.
        let r = evaluate(
            "f",
            &policy,
            &[chunk(&[
                ("box", "home", true, now - day),
                ("s3", "cloud", true, now - 2 * day),
            ])],
            &none,
            &[],
            now,
        );
        assert_eq!(r.state, PolicyState::Ok);
        // Verification ageing (25 of 30 days): at risk, with a warning.
        let r = evaluate(
            "f",
            &policy,
            &[chunk(&[
                ("box", "home", false, 0),
                ("s3", "cloud", true, now - 25 * day),
            ])],
            &none,
            &[],
            now,
        );
        assert_eq!(r.state, PolicyState::AtRisk);
        assert!(r.warnings[0].contains("fsck --verify"));
        // Only one copy: violated.
        let r = evaluate(
            "f",
            &policy,
            &[chunk(&[("s3", "cloud", true, now - day)])],
            &none,
            &[],
            now,
        );
        assert_eq!(r.state, PolicyState::Violated);
        assert_eq!(r.chunks_short_of_copies, 1);
        // Two copies but none in the cloud: violated for the place rule.
        let r = evaluate(
            "f",
            &policy,
            &[chunk(&[
                ("box", "home", true, now - day),
                ("nas", "home", true, now - day),
            ])],
            &none,
            &[],
            now,
        );
        assert_eq!(r.state, PolicyState::Violated);
        assert_eq!(r.chunks_short_per_place["cloud"], 1);
        // Exactly the minimum with one copy on a cold storage: at risk.
        let mut unreadable = BTreeMap::new();
        unreadable.insert("cloud".to_string(), vec!["glacier".to_string()]);
        let r = evaluate(
            "f",
            &policy,
            &[chunk(&[
                ("box", "home", true, now - day),
                ("glacier", "cloud", true, now - day),
            ])],
            &unreadable,
            &[],
            now,
        );
        assert_eq!(r.state, PolicyState::AtRisk);
        // A storage that could not be checked: unknown.
        let r = evaluate(
            "f",
            &policy,
            &[chunk(&[
                ("box", "home", true, now - day),
                ("s3", "cloud", true, now - day),
            ])],
            &none,
            &["s3".to_string()],
            now,
        );
        assert_eq!(r.state, PolicyState::Unknown);
        assert_eq!(parse_place_spec("cloud=2"), Some(("cloud".to_string(), 2)));
    }
}
