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
    /// The policy of every folder that never had one set: one copy on any
    /// storage, one in external storage (S3 and the like), one on your own
    /// devices and disks, and every block checked by another device within
    /// 30 days. Clearing a folder's policy stores an empty one instead.
    pub fn folder_default() -> Policy {
        Policy {
            min_copies: 1,
            min_per_place: [("cloud".to_string(), 1), ("home".to_string(), 1)]
                .into_iter()
                .collect(),
            verified_within_days: Some(30),
        }
    }

    /// No requirement at all (a policy cleared by hand).
    pub fn is_empty(&self) -> bool {
        self.min_copies == 0
            && self.min_per_place.values().all(|n| *n == 0)
            && self.verified_within_days.is_none()
    }

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

/// Grace for new data (spec section 14.7): a block is not counted against a
/// verification condition until it has been stored for longer than the
/// larger of this and the policy's verification window. Until then it is
/// "stored, verification pending", which is neutral. The default is 24 hours;
/// this is the one place to change it.
pub const NEW_DATA_GRACE_SECS: i64 = 24 * 3600;

/// One chunk's standing against the policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkFacts {
    /// Storage name -> (place, verified by someone other than the writer, newest verification time).
    pub copies: Vec<(String, String, bool, i64)>,
    /// When the block was first stored on any storage (UTC seconds); 0 when
    /// unknown, which counts as old data (no grace).
    pub stored_utc: i64,
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
    /// Blocks not yet verified that are still inside the grace for new data:
    /// neutral, not a violation.
    #[serde(default)]
    pub chunks_verification_pending: u64,
    /// Days since the oldest verification that still satisfies the window.
    pub oldest_verification_days: Option<i64>,
    pub reasons: Vec<String>,
    /// What will break the policy if nothing is done.
    pub warnings: Vec<String>,
    /// Blocks short of the rules that a mailbox holds staged for their
    /// target (section 78): *in transit*. They still count as short: a
    /// staged copy is not a copy.
    #[serde(default)]
    pub chunks_in_transit: u64,
    #[serde(default)]
    pub bytes_in_transit: u64,
}

impl PolicyReport {
    /// Met with nothing pending: what actions that give up another copy of
    /// the data (an import removing its source files) wait for. The grace for
    /// new data keeps the state `ok`, but is no proof of a verification.
    pub fn fully_met(&self) -> bool {
        self.state == PolicyState::Ok && self.chunks_verification_pending == 0
    }

    /// Why the policy is not fully met, in a sentence.
    pub fn why_not_met(&self) -> String {
        if !self.reasons.is_empty() {
            self.reasons.join("; ")
        } else if !self.warnings.is_empty() {
            self.warnings.join("; ")
        } else {
            format!(
                "{} blocks are stored but no other device has verified them yet",
                self.chunks_verification_pending
            )
        }
    }
}

pub fn evaluate(
    folder: &str,
    policy: &Policy,
    chunks: &[ChunkFacts],
    unreadable_places: &BTreeMap<String, Vec<String>>, // place -> storages that cannot be read now (cold, carrier away)
    storages_unknown: &[String],
    now_utc: i64,
) -> PolicyReport {
    evaluate_with_grace(
        folder,
        policy,
        chunks,
        unreadable_places,
        storages_unknown,
        now_utc,
        NEW_DATA_GRACE_SECS,
    )
}

/// `evaluate` with an explicit grace for new data (seconds).
pub fn evaluate_with_grace(
    folder: &str,
    policy: &Policy,
    chunks: &[ChunkFacts],
    unreadable_places: &BTreeMap<String, Vec<String>>,
    storages_unknown: &[String],
    now_utc: i64,
    grace_secs: i64,
) -> PolicyReport {
    let mut pending = 0u64;
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
                _ => {
                    // New data: it cannot have been verified yet.
                    let fresh = c.stored_utc > 0 && now_utc - c.stored_utc < w.max(grace_secs);
                    if fresh {
                        pending += 1;
                    } else {
                        unverified += 1;
                    }
                }
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
        chunks_verification_pending: pending,
        oldest_verification_days: oldest_ok.map(|t| (now_utc - t) / 86_400),
        reasons,
        warnings,
        chunks_in_transit: 0,
        bytes_in_transit: 0,
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
            stored_utc: 0,
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

    #[test]
    fn new_data_has_a_grace_before_verification_counts() {
        let now = 2_000_000_000;
        let day = 86_400;
        let policy = Policy {
            min_copies: 1,
            min_per_place: BTreeMap::new(),
            verified_within_days: Some(7),
        };
        let none = BTreeMap::new();
        let stored_at = |t: i64| ChunkFacts {
            stored_utc: t,
            ..chunk(&[("box", "home", false, 0)])
        };
        let run = |c: ChunkFacts, grace: i64| {
            evaluate_with_grace("f", &policy, &[c], &none, &[], now, grace)
        };
        // Just stored: pending, neutral.
        let r = run(stored_at(now - 60), NEW_DATA_GRACE_SECS);
        assert_eq!(r.state, PolicyState::Ok);
        assert_eq!(r.chunks_verification_pending, 1);
        assert_eq!(r.chunks_unverified_in_window, 0);
        // Still inside the 7-day window: pending.
        assert_eq!(run(stored_at(now - 6 * day), 3600).state, PolicyState::Ok);
        // Older than the window with no verification: violated.
        let r = run(stored_at(now - 8 * day), NEW_DATA_GRACE_SECS);
        assert_eq!(r.state, PolicyState::Violated);
        assert_eq!(r.chunks_unverified_in_window, 1);
        assert_eq!(r.chunks_verification_pending, 0);
        // Old data of unknown age is not given a grace.
        assert_eq!(
            run(chunk(&[("box", "home", false, 0)]), NEW_DATA_GRACE_SECS).state,
            PolicyState::Violated
        );
        // A policy with a short window: the default grace is the larger.
        let short = Policy {
            verified_within_days: Some(0),
            ..policy.clone()
        };
        let r = evaluate_with_grace(
            "f",
            &short,
            &[stored_at(now - 3600)],
            &none,
            &[],
            now,
            24 * 3600,
        );
        assert_eq!(r.state, PolicyState::Ok);
        let r = evaluate_with_grace(
            "f",
            &short,
            &[stored_at(now - 30 * 3600)],
            &none,
            &[],
            now,
            24 * 3600,
        );
        assert_eq!(r.state, PolicyState::Violated);
        // A condition that cannot be met still warns at once: two copies
        // wanted, one storage.
        let two = Policy {
            min_copies: 2,
            ..policy.clone()
        };
        let r = evaluate("f", &two, &[stored_at(now - 60)], &none, &[], now);
        assert_eq!(r.state, PolicyState::Violated);
        assert_eq!(r.chunks_short_of_copies, 1);
        assert_eq!(r.chunks_verification_pending, 1);
    }
}
