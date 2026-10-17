// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Ledger heads between peers (`docs/spec/alpha-0-format.md` section 74):
//! signing this device's statement, taking in the ones peers send, and the
//! numbers that `watch_freshness` compares after a pull.

use super::*;
use crate::ledger_heads::{HeadEntry, HeadStatement};

/// Peers are asked for their statement at most this often.
const ASK_EVERY: std::time::Duration = std::time::Duration::from_secs(10);
/// A peer that does not answer within this long is left to answer in the
/// background; its statement is taken at the next pull.
const ASK_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

impl Engine {
    /// The statement of what this device holds of every device's ledger,
    /// signed with the device key. `None` for a device that signs no ledger
    /// batches of the vault (a removed one, a member of shared folders).
    pub fn head_statement(&self) -> Option<HeadStatement> {
        self.signed_heads(false)
    }

    /// Only this device's own head, for its rendezvous record.
    pub(super) fn own_head_statement(&self) -> Option<HeadStatement> {
        self.signed_heads(true)
    }

    fn signed_heads(&self, own_only: bool) -> Option<HeadStatement> {
        if self.removal.is_some() || self.vault.member {
            return None;
        }
        let me = &self.vault.device_id;
        let mut entries = Vec::new();
        for dev in self.ledger.devices() {
            let own = &dev == me;
            if own_only && !own {
                continue;
            }
            let head = self.ledger.head(&dev);
            let mut checkpoint = head.base.as_ref().map(|b| b.seq).unwrap_or(0);
            let (seq, hash) = if own {
                // Only what a storage is known to hold: a batch not pushed
                // yet is not one a storage withheld.
                let pushed = head.seq.min(self.ledger.pushed_max());
                checkpoint = checkpoint.min(pushed);
                let hash = match self.ledger.get(me, pushed) {
                    Ok(Some(b)) => b.hash,
                    _ => String::new(),
                };
                (pushed, hash)
            } else {
                (head.seq, head.hash.clone().unwrap_or_default())
            };
            if seq == 0 && checkpoint == 0 {
                continue;
            }
            entries.push(HeadEntry {
                device: dev,
                seq,
                hash,
                checkpoint,
            });
        }
        Some(HeadStatement::sign(
            &self.vault.vault_id,
            me,
            self.clock.lamport,
            util::now_utc(),
            entries,
            &self.keys.signer,
        ))
    }

    /// Take in a statement a peer sent: it must be of this vault, by a
    /// trusted full device other than this one, signed with that device's
    /// key, not from the future and newer than the one kept. It changes
    /// nothing but `ledger/heads-seen.json`. True when it was kept.
    pub fn accept_head_statement(&mut self, st: HeadStatement) -> bool {
        let me = self.vault.device_id.clone();
        if st.sender == me || !self.trusted(&st.sender) {
            return false;
        }
        let Some(pk) = self.device_key(&st.sender) else {
            return false;
        };
        if st.verify(&self.vault.vault_id, &pk).is_err() {
            return false;
        }
        if st.lamport > self.clock.lamport.saturating_add(Self::CLOCK_LEAP)
            || st.utc > util::now_utc() + 86_400
        {
            return false;
        }
        let kept = self.ledger_alarm.heads.keep(st);
        if kept {
            self.ledger_alarm.heads.save(&self.home);
        }
        kept
    }

    /// Before a pull: ask the peers for their statements (at most every few
    /// seconds, never for long) and take in the ones heard since, on
    /// `/p2p/changed`, `/p2p/heads` and in rendezvous records.
    pub(super) fn exchange_heads(&mut self) {
        if let Some(peers) = self.peers.clone() {
            let due = self
                .ledger_alarm
                .heads_asked
                .is_none_or(|t| t.elapsed() >= ASK_EVERY);
            if due {
                self.ledger_alarm.heads_asked = Some(std::time::Instant::now());
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    peers.exchange_heads();
                    let _ = tx.send(());
                });
                let _ = rx.recv_timeout(ASK_WAIT);
            }
        }
        for st in crate::ledger_heads::take_heard(&self.vault.vault_id, &self.vault.device_id) {
            self.accept_head_statement(st);
        }
        // What a sender that does not count any more said is forgotten.
        let gone: Vec<DeviceId> = self
            .ledger_alarm
            .heads
            .statements
            .keys()
            .filter(|d| !self.trusted(d))
            .cloned()
            .collect();
        if !gone.is_empty() {
            for d in gone {
                self.ledger_alarm.heads.forget(&d);
            }
            self.ledger_alarm.heads.save(&self.home);
        }
    }

    /// Per device: how far a trusted full device says it holds that
    /// device's ledger. Beyond a removed device's cut-off nothing counts;
    /// statements older than two weeks or of senders that no longer count
    /// are left out.
    pub(super) fn peer_reach(&self, dir: &KeyDirectory) -> BTreeMap<DeviceId, u64> {
        let me = &self.vault.device_id;
        let now = util::now_utc();
        let mut out: BTreeMap<DeviceId, u64> = BTreeMap::new();
        for (sender, st) in &self.ledger_alarm.heads.statements {
            if sender == me
                || !self.trusted(sender)
                || now - st.utc > crate::ledger_heads::MAX_AGE_SECS
            {
                continue;
            }
            for e in &st.heads {
                if &e.device == me || !dir.contains_key(&e.device) {
                    continue;
                }
                let reach = match self.devices.revoked.get(&e.device) {
                    Some(r) => e.reach().min(r.cutoff_seq),
                    None => e.reach(),
                };
                let slot = out.entry(e.device.clone()).or_insert(0);
                *slot = (*slot).max(reach);
            }
        }
        out
    }
}
