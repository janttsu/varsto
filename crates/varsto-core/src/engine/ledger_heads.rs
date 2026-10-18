// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Ledger heads between peers in storage format 3 (`format-3-design.md`
//! section 8, `alpha-0-format.md` sections 75 and 77.8): this device's head
//! list, the catch-up that asks the peers what they can **prove** (batch
//! envelopes signed by their writers, and the writers' own peer records)
//! and fetches the batches this device lacks from them, and the rollback
//! judge that compares what each storage shows with what was proved.
//!
//! The pull calls [`Engine::p2p_catch_up`] before it reads the storages and
//! [`Engine::p2p_judge_rollback`] after; both are safe to call without
//! peers. Proofs are kept in `ledger/proofs.json` (`p2p::v3::heads::Watch`).

use super::*;
use crate::ledger3::events::Batch as Batch3;
use crate::p2p::v3::heads::{
    self, BatchSink, CatchUp, Expectation, Proof, Proved, RollbackWarning, StorageView, Watch,
};
use crate::record::{Acceptor, Id16, SignedRecord};

/// A fetched batch is opened like any record (acceptance steps 1 to 4);
/// the ledger store checks its body and chain when it takes it in.
impl crate::record::RecordBody for Batch3 {}

/// Batches fetched from peers, held until the catch-up ends; the heads
/// are this device's before it started.
struct Fetched {
    heads: BTreeMap<Id16, u64>,
    got: Vec<(String, Vec<u8>)>,
}

impl BatchSink for Fetched {
    fn head(&self, device: &Id16) -> u64 {
        let have = self.heads.get(device).copied().unwrap_or(0);
        // Batches fetched this round count too (fetches run in order).
        let fetched = self
            .got
            .iter()
            .filter_map(|(_, b)| SignedRecord::decode(b).ok())
            .filter(|r| r.device == *device)
            .map(|r| r.seq)
            .max()
            .unwrap_or(0);
        have.max(fetched)
    }
    fn ingest(&mut self, name: &str, record: &[u8]) -> Result<()> {
        self.got.push((name.to_string(), record.to_vec()));
        Ok(())
    }
}

impl Engine {
    /// Head exchange with every peer (design section 8): the peers answer
    /// this device's head list with proofs of newer batches; the proofs and
    /// the writers' own heads in their peer records are kept in
    /// `ledger/proofs.json`, and the batches this device lacks up to a proof
    /// are fetched from the peer that proved it (or from the writer whose
    /// record proved it), checked as from a storage and taken into the
    /// ledger. They are not pushed: only their writers push them.
    pub fn p2p_catch_up(&mut self) -> Result<CatchUp> {
        if self.vault.member || self.removal.is_some() {
            return Ok(CatchUp::default());
        }
        let now = util::now_utc();
        let vault = members3::bin(&self.vault.vault_id)?;
        let key_map = self.full_device_keys();
        let mut watch = Watch::load(&self.home);
        let dir = self.peer_directory().unwrap_or_default();
        let mut by_record: Vec<(DeviceId, Proof)> = Vec::new();
        for b in dir.bodies() {
            if !key_map.contains_key(&b.device) {
                continue;
            }
            watch.note_peer_record(b, now);
            if let Some(h) = b.heads.iter().find(|h| h.device == b.device) {
                by_record.push((
                    DeviceId::from_bytes(&b.device),
                    Proof {
                        device: h.device,
                        seq: h.seq,
                        hash: h.hash,
                    },
                ));
            }
        }
        let mut sink = Fetched {
            heads: key_map
                .keys()
                .map(|d| (*d, self.f3.ledger.head(d).seq))
                .collect(),
            got: Vec::new(),
        };
        let mut out = CatchUp::default();
        if let Some(peers) = self.peers.clone() {
            let mine = self.head_list();
            let vault_keys = self.vault_keys3();
            let keys = self.keys3(&vault_keys);
            let trust = self.f3.members.trust();
            let acceptor = Acceptor {
                vault,
                keys: &keys,
                trust: &trust,
            };
            let key_of = |d: &Id16| key_map.get(d).cloned();
            out = heads::catch_up::<Batch3>(
                &peers, &mine, &vault, &acceptor, &key_of, &mut watch, &mut sink, now,
            );
            // A writer's own record proves its head: it hands its batches
            // over itself.
            for (writer, p) in &by_record {
                heads::fetch_proved::<Batch3>(&peers, writer, p, &acceptor, &mut sink, &mut out);
            }
        }
        let limit = self.clock.lamport.saturating_add(Self::CLOCK_LEAP);
        for (name, bytes) in std::mem::take(&mut sink.got) {
            let Ok(rec) = SignedRecord::decode(&bytes) else {
                continue;
            };
            let Some(pk) = key_map.get(&rec.device) else {
                continue;
            };
            let key = self.key_for3(&rec.key_id);
            if let Err(e) = self
                .f3
                .ledger
                .ingest_named(&name, rec, pk, key.as_ref(), limit)
            {
                log::warn!("ledger batch from a peer skipped: {e:#}");
                out.refused += 1;
            }
        }
        // What senders that do not count any more proved is forgotten.
        let me = self.me3();
        watch.proved.retain(|k, _| {
            crate::record::kinds::parse_id16(k).is_some_and(|d| d != me && key_map.contains_key(&d))
        });
        watch.save(&self.home);
        if out.fetched > 0 {
            let view = self.view3()?;
            self.observe_clock(view.max_lamport)?;
        }
        Ok(out)
    }

    /// What each hot metadata storage shows of every full device's ledger
    /// (the newest batch or checkpoint listed), for the rollback judge when
    /// the pull does not hand its own listing over.
    pub fn storage_views(&self) -> Vec<StorageView> {
        let mut devices: Vec<Id16> = self.full_device_keys().keys().copied().collect();
        devices.push(self.me3());
        let mut out = Vec::new();
        let Ok(storages) = self.record_storages3() else {
            return out;
        };
        for (spec, backend) in storages {
            let Some(storage) = verify::storage_identity(backend.as_ref())
                .ok()
                .and_then(|id| crate::record::kinds::parse_id16(&id))
            else {
                continue;
            };
            let mut view = StorageView {
                storage,
                name: spec.name().to_string(),
                reachable: true,
                shown: BTreeMap::new(),
            };
            for d in &devices {
                let prefix = format!("ledger/{}/", hex::encode(d));
                match backend.list(&prefix) {
                    Ok(names) => {
                        let top = names
                            .iter()
                            .filter_map(|n| n.strip_prefix(&prefix))
                            .filter_map(crate::ledger3::LedgerObject::parse)
                            .map(|o| match o {
                                crate::ledger3::LedgerObject::Batch(s) => s,
                                crate::ledger3::LedgerObject::Checkpoint(s, _) => s,
                            })
                            .max()
                            .unwrap_or(0);
                        view.shown.insert(*d, top);
                    }
                    Err(_) => {
                        view.reachable = false;
                        break;
                    }
                }
            }
            out.push(view);
        }
        out
    }

    /// The rollback warning (design section 8): after a pull that started
    /// at `pull_utc`, a storage that the writing device confirmed in its
    /// peer record (`pushed`), or that this device pushed its own batches
    /// to, and that shows less than a proof older than the pull, is
    /// suspect; two such pulls in a row give the warning. `views` is what
    /// the pull's listing showed (read here when `None`).
    pub fn p2p_judge_rollback(
        &mut self,
        pull_utc: i64,
        views: Option<Vec<StorageView>>,
    ) -> Result<Vec<RollbackWarning>> {
        if self.vault.member || self.removal.is_some() {
            return Ok(Vec::new());
        }
        let views = views.unwrap_or_else(|| self.storage_views());
        let key_map = self.full_device_keys();
        let me = self.me3();
        let mut expected = Vec::new();
        for b in self.peer_directory().unwrap_or_default().bodies() {
            if !key_map.contains_key(&b.device) {
                continue;
            }
            for p in &b.pushed {
                expected.push(Expectation {
                    storage: p.storage,
                    device: b.device,
                    seq: p.seq,
                });
            }
        }
        let mut watch = Watch::load(&self.home);
        let mut proofs = watch.proved.clone();
        // This device's own batches: what it pushed to each storage it
        // knows itself.
        let mut own_top = 0;
        for (spec, backend) in self.record_storages3()? {
            let seq = self.f3.ledger.pushed(spec.name());
            let Some(storage) = verify::storage_identity(backend.as_ref())
                .ok()
                .and_then(|id| crate::record::kinds::parse_id16(&id))
            else {
                continue;
            };
            if seq > 0 {
                own_top = own_top.max(seq);
                expected.push(Expectation {
                    storage,
                    device: me,
                    seq,
                });
            }
        }
        if own_top > 0 {
            proofs.insert(
                hex::encode(me),
                Proved {
                    seq: own_top,
                    hash: String::new(),
                    peer: hex::encode(me),
                    source: "this device".into(),
                    utc: 0,
                },
            );
        }
        let names = |d: &Id16| -> String {
            self.f3
                .members
                .devices
                .get(d)
                .map(|r| r.name.clone())
                .unwrap_or_else(|| hex::encode(&d[..4]))
        };
        let warnings = watch.rollback.after_pull(
            pull_utc,
            &views,
            &expected,
            &proofs,
            &names,
            util::now_utc(),
        );
        watch.save(&self.home);
        for w in &warnings {
            log::warn!("{}", w.text);
        }
        Ok(warnings)
    }

    /// The suspect (storage, device) pairs the rollback judge keeps.
    pub fn rollback_suspects(&self) -> BTreeMap<String, heads::Suspect> {
        Watch::load(&self.home).rollback.suspects
    }

    /// Format 2's pull asks the peers here before it lists the storages;
    /// in format 3 that is the catch-up.
    pub(super) fn exchange_heads(&mut self) {
        if let Err(e) = self.p2p_catch_up() {
            log::debug!("head exchange with peers failed: {e:#}");
        }
    }

    /// Per device: how far a peer proved that device's ledger (a signed
    /// batch envelope or the writer's own peer record). Beyond a removed
    /// device's cut-off nothing counts.
    pub(super) fn peer_reach(&self, dir: &KeyDirectory) -> BTreeMap<DeviceId, u64> {
        let me = &self.vault.device_id;
        let mut out: BTreeMap<DeviceId, u64> = BTreeMap::new();
        for (dev, p) in Watch::load(&self.home).proved {
            let Ok(dev) = DeviceId::from_hex(&dev) else {
                continue;
            };
            if &dev == me || !dir.contains_key(&dev) {
                continue;
            }
            let reach = match self.devices.revoked.get(&dev) {
                Some(r) => p.seq.min(r.cutoff_seq),
                None => p.seq,
            };
            out.insert(dev, reach);
        }
        out
    }
}
