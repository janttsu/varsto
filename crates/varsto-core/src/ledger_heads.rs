// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Ledger heads between peers (`docs/spec/alpha-0-format.md` section 74).
//!
//! A device tells another, over peer-to-peer, how far it holds every
//! device's ledger: `(device, head seq, head hash, newest checkpoint seq)`
//! for each device it knows, as a statement signed with its device key. A
//! receiver keeps the newest statement of each sender in
//! `ledger/heads-seen.json` and compares it with its own heads after the
//! next pull: a trusted full device that provably holds batches this device
//! lacks, and that no storage hands over, is the sign of a storage that
//! withholds or rolls back the ledger. A statement only raises that
//! question; it never moves a head, ingests anything or makes a device
//! refuse a batch.

use crate::crypto::{self, SigningKey, VerifyingKey};
use crate::ids::{DeviceId, VaultId};
use crate::util;
use anyhow::{bail, Result};
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Most devices one statement lists (a vault has a few hundred at most).
pub const MAX_ENTRIES: usize = 512;
/// Largest statement taken from the wire.
pub const MAX_BYTES: usize = 256 * 1024;
/// A statement older than this (by its own time) is no longer compared.
pub const MAX_AGE_SECS: i64 = 14 * 86_400;
/// A statement whose request path would be longer than this is not carried
/// on `/p2p/changed`; the receiver asks for it (`/p2p/heads`) instead.
pub const PIGGYBACK_MAX_PATH: usize = 24 * 1024;
/// The path of `/p2p/changed` with a statement.
pub const CHANGED_PREFIX: &str = "/p2p/changed/";

const FILE: &str = "ledger/heads-seen.json";

/// What one device holds of one device's ledger.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeadEntry {
    pub device: DeviceId,
    pub seq: u64,
    #[serde(default)]
    pub hash: String,
    /// The newest checkpoint of that device held (0: none).
    #[serde(default)]
    pub checkpoint: u64,
}

impl HeadEntry {
    /// How far the sender holds this device's ledger.
    pub fn reach(&self) -> u64 {
        self.seq.max(self.checkpoint)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeadStatement {
    pub version: u32,
    pub vault: VaultId,
    pub sender: DeviceId,
    /// The sender's Lamport clock and wall clock when it signed: the order
    /// of statements of one sender.
    pub lamport: u64,
    pub utc: i64,
    pub heads: Vec<HeadEntry>,
    pub sig_alg: String,
    pub sig_b64: String,
}

impl HeadStatement {
    pub const VERSION: u32 = 1;

    fn message(
        vault: &VaultId,
        sender: &DeviceId,
        lamport: u64,
        utc: i64,
        heads: &[HeadEntry],
    ) -> Vec<u8> {
        let body = serde_json::to_vec(heads).unwrap_or_default();
        crypto::aad(
            "ledger-heads-statement",
            &[
                vault.as_str().as_bytes(),
                sender.as_str().as_bytes(),
                &lamport.to_le_bytes(),
                &utc.to_le_bytes(),
                &crypto::hash(&body),
            ],
        )
    }

    pub fn sign(
        vault: &VaultId,
        sender: &DeviceId,
        lamport: u64,
        utc: i64,
        mut heads: Vec<HeadEntry>,
        signer: &SigningKey,
    ) -> HeadStatement {
        heads.sort_by(|a, b| a.device.cmp(&b.device));
        heads.truncate(MAX_ENTRIES);
        let sig = signer.sign(&Self::message(vault, sender, lamport, utc, &heads));
        HeadStatement {
            version: Self::VERSION,
            vault: vault.clone(),
            sender: sender.clone(),
            lamport,
            utc,
            heads,
            sig_alg: signer.alg().to_string(),
            sig_b64: B64.encode(sig),
        }
    }

    /// Check the signature of the sender's key, the vault and the size.
    pub fn verify(&self, vault: &VaultId, key: &VerifyingKey) -> Result<()> {
        if self.version != Self::VERSION {
            bail!("unknown head statement version {}", self.version);
        }
        if &self.vault != vault {
            bail!("head statement of another vault");
        }
        if self.heads.len() > MAX_ENTRIES {
            bail!("head statement lists too many devices");
        }
        let sig = B64.decode(&self.sig_b64)?;
        key.verify(
            &self.sig_alg,
            &Self::message(
                &self.vault,
                &self.sender,
                self.lamport,
                self.utc,
                &self.heads,
            ),
            &sig,
        )
    }

    pub fn encode(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn decode(bytes: &[u8]) -> Result<HeadStatement> {
        if bytes.len() > MAX_BYTES {
            bail!("head statement too large");
        }
        Ok(serde_json::from_slice(bytes)?)
    }

    /// The request path that carries this statement on `/p2p/changed`, or
    /// `None` when it would be too long.
    pub fn changed_path(&self) -> Option<String> {
        let p = format!("{CHANGED_PREFIX}{}", B64URL.encode(self.encode()));
        (p.len() <= PIGGYBACK_MAX_PATH).then_some(p)
    }

    /// The statement a `/p2p/changed/<token>` path carries.
    pub fn from_changed_path(path: &str) -> Option<HeadStatement> {
        let token = path.strip_prefix(CHANGED_PREFIX)?;
        Self::decode(&B64URL.decode(token).ok()?).ok()
    }

    /// Whether `self` is newer than `other` of the same sender.
    pub fn newer_than(&self, other: &HeadStatement) -> bool {
        let total = |s: &HeadStatement| s.heads.iter().map(|e| e.reach()).sum::<u64>();
        (self.lamport, self.utc, total(self)) > (other.lamport, other.utc, total(other))
    }

    pub fn entry(&self, device: &DeviceId) -> Option<&HeadEntry> {
        self.heads.iter().find(|e| &e.device == device)
    }
}

/// The newest statement of every sender (`ledger/heads-seen.json`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HeadsSeen {
    #[serde(default)]
    pub statements: BTreeMap<DeviceId, HeadStatement>,
}

impl HeadsSeen {
    pub fn load(home: &Path) -> HeadsSeen {
        util::read_json(&home.join(FILE)).unwrap_or_default()
    }

    pub fn save(&self, home: &Path) {
        // Never recreate a ledger directory that was removed.
        if home.join("ledger").is_dir() {
            let _ = util::write_json(&home.join(FILE), self);
        }
    }

    /// Keep `st` (already verified) when it is newer than the one held of
    /// its sender; true when it was kept.
    pub fn keep(&mut self, st: HeadStatement) -> bool {
        match self.statements.get(&st.sender) {
            Some(old) if !st.newer_than(old) => false,
            _ => {
                self.statements.insert(st.sender.clone(), st);
                true
            }
        }
    }

    /// Drop what a sender that does not count any more said.
    pub fn forget(&mut self, sender: &DeviceId) -> bool {
        self.statements.remove(sender).is_some()
    }
}

/// Statements heard on `/p2p/changed` (the server has no engine): taken by
/// the engine at its next ledger pull, verified there.
static HEARD: std::sync::Mutex<Vec<HeadStatement>> = std::sync::Mutex::new(Vec::new());
const HEARD_MAX: usize = 64;

pub fn hear(st: HeadStatement) {
    let mut h = HEARD.lock().unwrap_or_else(|e| e.into_inner());
    if h.iter().any(|o| o.sender == st.sender && !st.newer_than(o)) {
        return;
    }
    h.retain(|o| o.sender != st.sender);
    if h.len() >= HEARD_MAX {
        h.remove(0);
    }
    h.push(st);
}

/// The statements heard for `vault` (one process normally serves one vault;
/// tests run several side by side).
/// Statements signed by `me` are left (they belong to a device of the same
/// process, which only tests have).
pub fn take_heard(vault: &VaultId, me: &DeviceId) -> Vec<HeadStatement> {
    let mut h = HEARD.lock().unwrap_or_else(|e| e.into_inner());
    let (mine, rest): (Vec<_>, Vec<_>) = std::mem::take(&mut *h)
        .into_iter()
        .partition(|s| &s.vault == vault && &s.sender != me);
    *h = rest;
    mine
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(d: &DeviceId, seq: u64) -> HeadEntry {
        HeadEntry {
            device: d.clone(),
            seq,
            hash: "ab".repeat(32),
            checkpoint: 0,
        }
    }

    fn setup() -> (VaultId, DeviceId, SigningKey, DeviceId) {
        (
            VaultId::random(),
            DeviceId::random(),
            SigningKey::generate(),
            DeviceId::random(),
        )
    }

    #[test]
    fn a_statement_round_trips_and_verifies() {
        let (vault, me, key, other) = setup();
        let st = HeadStatement::sign(&vault, &me, 7, 1000, vec![entry(&other, 9)], &key);
        let back = HeadStatement::decode(&st.encode()).unwrap();
        assert_eq!(back, st);
        back.verify(&vault, &key.public()).unwrap();
        assert_eq!(back.entry(&other).unwrap().reach(), 9);
    }

    #[test]
    fn a_changed_forged_or_foreign_statement_is_refused() {
        let (vault, me, key, other) = setup();
        let st = HeadStatement::sign(&vault, &me, 7, 1000, vec![entry(&other, 9)], &key);
        let mut raised = st.clone();
        raised.heads[0].seq = 90;
        assert!(raised.verify(&vault, &key.public()).is_err());
        let mut later = st.clone();
        later.lamport += 1;
        assert!(later.verify(&vault, &key.public()).is_err());
        let mut renamed = st.clone();
        renamed.sender = other.clone();
        assert!(renamed.verify(&vault, &key.public()).is_err());
        let stranger = SigningKey::generate();
        assert!(st.verify(&vault, &stranger.public()).is_err());
        assert!(st.verify(&VaultId::random(), &key.public()).is_err());
        st.verify(&vault, &key.public()).unwrap();
    }

    #[test]
    fn only_a_newer_statement_replaces_the_kept_one() {
        let (vault, me, key, other) = setup();
        let mut seen = HeadsSeen::default();
        let s5 = HeadStatement::sign(&vault, &me, 5, 100, vec![entry(&other, 5)], &key);
        let s9 = HeadStatement::sign(&vault, &me, 9, 100, vec![entry(&other, 9)], &key);
        assert!(seen.keep(s5.clone()));
        assert!(seen.keep(s9.clone()));
        assert!(!seen.keep(s5), "older");
        assert!(!seen.keep(s9.clone()), "equal");
        assert_eq!(seen.statements[&me], s9);
        assert!(seen.forget(&me) && !seen.forget(&me));
    }

    #[test]
    fn a_statement_rides_a_changed_path_when_it_fits() {
        let (vault, me, key, other) = setup();
        let st = HeadStatement::sign(&vault, &me, 3, 50, vec![entry(&other, 4)], &key);
        let path = st.changed_path().unwrap();
        assert!(path.starts_with(CHANGED_PREFIX) && path.len() < 12 * 1024);
        assert_eq!(HeadStatement::from_changed_path(&path), Some(st));
        assert!(HeadStatement::from_changed_path("/p2p/changed").is_none());
        assert!(HeadStatement::from_changed_path("/p2p/changed/@@").is_none());
        let many: Vec<HeadEntry> = (0..400).map(|i| entry(&DeviceId::random(), i)).collect();
        let big = HeadStatement::sign(&vault, &me, 3, 50, many, &key);
        assert!(big.changed_path().is_none(), "left to /p2p/heads");
        big.verify(&vault, &key.public()).unwrap();
    }

    #[test]
    fn heard_statements_are_kept_per_vault_and_newest() {
        let (vault, me, key, other) = setup();
        let old = HeadStatement::sign(&vault, &me, 1, 10, vec![entry(&other, 1)], &key);
        let new = HeadStatement::sign(&vault, &me, 2, 10, vec![entry(&other, 2)], &key);
        hear(new.clone());
        hear(old);
        assert!(take_heard(&VaultId::random(), &other).is_empty());
        assert!(take_heard(&vault, &me).is_empty(), "own statements stay");
        assert_eq!(take_heard(&vault, &other), vec![new]);
        assert!(take_heard(&vault, &other).is_empty());
    }

    #[test]
    fn a_huge_statement_is_not_read() {
        assert!(HeadStatement::decode(&vec![b' '; MAX_BYTES + 1]).is_err());
    }
}
