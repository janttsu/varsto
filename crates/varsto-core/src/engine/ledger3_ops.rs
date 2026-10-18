// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The pack-level ledger of storage format 3 in the engine
//! (`docs/spec/format-3-design.md` section 4): this device's batches are
//! signed records under the ledger key of the newest vault epoch, pushed to
//! every hot metadata storage at `ledger/<device>/<seq 16>-0000.rec`; a
//! pull lists each known device's batches after the head held here and
//! hands them to `ledger3::LedgerStore`; the view is replayed from the
//! batches under the keys, cut-offs, scopes and folder roles of the
//! membership (`Members3`), and kept between calls.
//!
//! Events of the rest of the engine that are recorded in the format-2 form
//! (`Engine::pending`) are carried over into the batch where format 3 has
//! them (enrolment, folders, retirements, snapshots); the per-block events
//! of format 2 are not part of format 3 and are left out (format 3 claims
//! packs: `Engine::pending3`).

use super::*;
use crate::ledger3::events::{
    BackupStopped, DeviceEnrolled, Event as Event3, FolderAdded, SnapshotExpired, SnapshotTaken,
    StorageRetired,
};
use crate::ledger3::{self, EventScope, LedgerView as View3, ViewCache};
use crate::record::{Id16, KeyId};

/// The format-3 part of an engine.
pub(crate) struct Core3 {
    pub ledger: ledger3::LedgerStore,
    pub members: members3::Members3,
    /// The raw view and the context it was built under.
    pub view: std::sync::Mutex<Option<ViewCache>>,
    /// The folder block map tables opened in this process.
    pub tables: std::sync::Mutex<BTreeMap<Id16, std::sync::Arc<std::sync::RwLock<MapTable3>>>>,
    /// The recovery key of this session (`set_recovery_key`).
    pub recovery: Option<crate::membership3::RecoveryKey>,
    /// Events of the next batch.
    pub pending: Vec<Event3>,
}

pub(crate) type MapTable3 = crate::blockmap::MapTable;

impl Core3 {
    pub fn open(home: &Path, vault: &VaultId) -> Result<Core3> {
        Ok(Core3 {
            ledger: ledger3::LedgerStore::open(&home.join("ledger"), members3::bin(vault)?)?,
            members: Default::default(),
            view: Default::default(),
            tables: Default::default(),
            recovery: None,
            pending: Vec::new(),
        })
    }
}

/// The format-3 form of a format-2 event, where format 3 has one.
fn convert(ev: &Event) -> Option<Event3> {
    let b = |id: &crate::ids::Id| members3::bin(id).ok();
    Some(match ev {
        Event::DeviceEnrolled { name } => {
            Event3::DeviceEnrolled(DeviceEnrolled { name: name.clone() })
        }
        Event::FolderAdded { folder } => Event3::FolderAdded(FolderAdded { folder: b(folder)? }),
        Event::StorageRetired { storage } => Event3::StorageRetired(StorageRetired {
            storage: storage.clone(),
        }),
        Event::SnapshotTaken {
            backup,
            seq,
            taken_utc,
            expires_utc,
            files,
            bytes,
            ..
        } => Event3::SnapshotTaken(SnapshotTaken {
            backup: b(backup)?,
            seq: *seq,
            taken_utc: *taken_utc,
            expires_utc: *expires_utc,
            files: *files,
            bytes: *bytes,
        }),
        Event::SnapshotExpired {
            backup,
            device,
            seq,
        } => Event3::SnapshotExpired(SnapshotExpired {
            backup: b(backup)?,
            device: b(device)?,
            seq: *seq,
        }),
        Event::BackupStopped { backup } => {
            Event3::BackupStopped(BackupStopped { backup: b(backup)? })
        }
        // Per-block events of format 2: format 3 claims packs instead.
        Event::ChunkStored { .. }
        | Event::ChunkVerified { .. }
        | Event::ChunkOnDevice { .. }
        | Event::ManifestPublished { .. }
        | Event::ChunkDropped { .. }
        | Event::Unknown => return None,
    })
}

impl Engine {
    /// The ledger key id and key of this device's batches: the newest vault
    /// epoch held.
    fn ledger_key3(&self) -> Result<(String, SecretKey)> {
        let keys = self.vault_keys3();
        let e = keys.newest_epoch();
        let k = keys
            .ledger(e)
            .ok_or_else(|| anyhow!("no vault key of epoch {e} is held here"))?;
        Ok((ledger3::scope::ledger_key_id(e), k))
    }

    /// The key that opens a batch or checkpoint with `key_id`, if held.
    pub(crate) fn key_for3(&self, key_id: &str) -> Option<SecretKey> {
        match KeyId::parse(key_id)? {
            KeyId::Ledger(e) => Some(crate::membership3::derive3(
                self.epochs.keys.get(&e)?,
                "ledger",
                &[],
            )),
            KeyId::ShareLedger { folder, epoch } => {
                self.f3.members.granted.get(&folder)?.share_ledger(epoch)
            }
            // Replicas' batches: part B (f3-switch).
            _ => None,
        }
    }

    /// Whether batch `seq` of `device` counts: a removed device's only up
    /// to its cut-off.
    fn keep3(&self, device: &Id16, seq: u64) -> bool {
        self.f3
            .members
            .revocations
            .get(device)
            .is_none_or(|r| seq <= r.cutoff_seq)
    }

    /// The role a batch of `device` under `key_id` is read with: full
    /// devices of the registry under the vault ledger key, member devices
    /// of shared folders under their folder's key, with the role the folder
    /// records give them.
    fn scope3(&self, device: &Id16, key_id: &str) -> Option<EventScope> {
        let m = &self.f3.members;
        match EventScope::of_key_id(key_id)? {
            EventScope::Full => m.devices.get(device).map(|_| EventScope::Full),
            EventScope::Member(f) => {
                m.members.get(&f, device)?;
                match m.role(device, &f) {
                    Some(crate::membership3::Role::Viewer) => Some(EventScope::Viewer(f)),
                    Some(_) => Some(EventScope::Member(f)),
                    None => None,
                }
            }
            // Replicas: part B (f3-switch).
            _ => None,
        }
    }

    /// What decides which batches count, as text: the keys held, the
    /// cut-offs, every device's scope and the folder roles.
    fn view_context3(&self) -> String {
        let m = &self.f3.members;
        let mut parts: Vec<Vec<u8>> = Vec::new();
        for (e, k) in &self.epochs.keys {
            parts.push(e.to_le_bytes().to_vec());
            parts.push(crypto::hash(&k.0).to_vec());
        }
        for (f, k) in &m.granted.folders {
            parts.push(f.to_vec());
            for (e, k9) in &k.epochs {
                parts.push(e.to_le_bytes().to_vec());
                parts.push(crypto::hash(&k9.0).to_vec());
            }
        }
        for (d, r) in &m.revocations {
            parts.push(d.to_vec());
            parts.push(r.cutoff_seq.to_le_bytes().to_vec());
        }
        for d in m.devices.devices.keys() {
            parts.push(d.to_vec());
        }
        for (f, d) in m.members.members.keys() {
            parts.push(f.to_vec());
            parts.push(d.to_vec());
        }
        for (f, st) in &m.registry.folders {
            parts.push(f.to_vec());
            for (d, h) in &st.history {
                parts.push(d.to_vec());
                for (s, r) in h {
                    parts.push(s.lamport.to_le_bytes().to_vec());
                    parts.push(s.device.to_vec());
                    parts.push(vec![r.map_or(0, |r| r as u8 + 1)]);
                }
            }
        }
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        hex::encode(crypto::hash(&crypto::aad("ledger3-view-context", &refs)))
    }

    /// The pack-level view: the batches held here applied under the
    /// membership's keys, cut-offs, scopes and folder roles (kept between
    /// calls and brought up to date with new batches).
    pub(crate) fn view3(&self) -> Result<View3> {
        let context = self.view_context3();
        let mut slot = self.f3.view.lock().unwrap_or_else(|e| e.into_inner());
        let fits = slot.as_ref().is_some_and(|c| {
            c.format == ViewCache::FORMAT && c.context == context && self.f3.ledger.cache_fits(c)
        });
        if !fits {
            *slot = Some(ViewCache::new(context));
        }
        let cache = slot.as_mut().expect("set above");
        self.f3.ledger.update_view_with_roles(
            cache,
            |id| self.key_for3(id),
            |d, seq| self.keep3(d, seq),
            |d, id| self.scope3(d, id),
            &self.f3.members.registry,
        )?;
        Ok(self.f3.ledger.finish(&cache.raw))
    }

    /// Forget the view kept in memory (keys or roles changed).
    pub(crate) fn reset_view3(&self) {
        *self.f3.view.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Seal the events recorded since the last batch (format-3 events and
    /// the format-2 ones format 3 carries) into one batch and push it.
    pub(crate) fn commit3(&mut self) -> Result<Option<u64>> {
        if self.removal.is_some() {
            self.pending.clear();
            self.f3.pending.clear();
            self.clear_deferred();
            return self.ensure_active().map(|_| None);
        }
        if self.cycle.is_some() {
            // One batch at the end of the action (`one_batch`).
            self.defer_events()?;
            return Ok(None);
        }
        let mut events: Vec<Event3> = self.pending.iter().filter_map(convert).collect();
        events.append(&mut self.f3.pending);
        self.pending.clear();
        self.clear_deferred();
        if events.is_empty() {
            return Ok(None);
        }
        if self.vault.member {
            // Folder-scoped batches of members: part B (f3-switch).
            bail!("a member device writes folder-scoped batches, which this build does not seal yet (f3-switch: part B)");
        }
        if self.forked_self {
            bail!("this device's ledger is forked; it must be re-enrolled as a new device");
        }
        let me = self.me3();
        let (key_id, key) = self.ledger_key3()?;
        let seen = self.f3.ledger.vault_seen(&me);
        let raw: Vec<_> = events.iter().map(Event3::to_raw).collect();
        let n = raw.len();
        let mut last = None;
        // One batch per action, more only past the size limits.
        for group in ledger3::events::split_events(raw) {
            let lamport = self.tick()?;
            let rec = self.f3.ledger.append_own(
                &me,
                group,
                seen.clone(),
                lamport,
                &key,
                &key_id,
                ledger3::NO_FOLDER,
                &self.keys.signer,
            )?;
            last = Some(rec.seq);
        }
        log::debug!(events = n, seq = last.unwrap_or(0); "ledger batch sealed");
        self.push_own_batches3()?;
        Ok(last)
    }

    /// Push every own batch a hot metadata storage does not have yet. A
    /// storage that holds another batch under one of this device's numbers
    /// (a copy of this identity restored from an old backup) stops it.
    pub(crate) fn push_own_batches3(&mut self) -> Result<()> {
        let me = self.me3();
        let head = self.f3.ledger.head(&me);
        for (spec, backend) in self.metadata_storages(false)? {
            if spec.is_carrier() {
                continue;
            }
            let done = self.f3.ledger.pushed(spec.name()).min(head.seq);
            for seq in done.max(head.dropped) + 1..=head.seq {
                let Some(rec) = self.f3.ledger.get(&me, seq)? else {
                    continue;
                };
                let key = ledger3::checkpoint::batch_key(&me, seq);
                let bytes = rec.encode();
                if !backend.put_if_absent(&key, &bytes)? {
                    let same = backend
                        .get_bounded(&key, crate::record::MAX_PART_READ)?
                        .is_some_and(|b| b == bytes);
                    if !same {
                        let theirs = backend
                            .get_bounded(&key, crate::record::MAX_PART_READ)?
                            .and_then(|b| crate::record::SignedRecord::decode(&b).ok());
                        if theirs.is_some_and(|r| r.verify(&self.keys.signer.public()).is_ok()) {
                            self.forked_self = true;
                            bail!("ledger fork: storage {} already holds a different batch {} of this device (restored from an old copy?)", backend.name(), seq);
                        }
                        log::warn!(storage = backend.name(), seq = seq; "ledger: junk under this device's batch name");
                    }
                }
            }
            self.f3.ledger.set_pushed(spec.name(), head.seq)?;
        }
        Ok(())
    }

    /// Pull the membership and every known device's new batches from every
    /// hot metadata storage. Returns the devices found forked.
    pub(crate) fn pull_ledger3(&mut self) -> Result<Vec<DeviceId>> {
        self.refresh_members3()?;
        let me = self.me3();
        let mut keys: BTreeMap<Id16, crypto::VerifyingKey> = BTreeMap::new();
        for (d, (rec, _)) in &self.f3.members.devices.devices {
            if let Some(k) = rec.signing_key() {
                keys.insert(*d, k);
            }
        }
        for m in self.f3.members.members.members.values() {
            if let Some(k) = m.signing_key() {
                keys.entry(m.device).or_insert(k);
            }
        }
        let mut forks = BTreeSet::new();
        let limit = self.clock.lamport.saturating_add(Self::CLOCK_LEAP);
        for (spec, backend) in self.metadata_storages(false)? {
            if spec.is_carrier() {
                continue;
            }
            for (dev, pk) in &keys {
                let head = self.f3.ledger.head(dev);
                if !self.keep3(dev, head.seq + 1) {
                    continue;
                }
                let prefix = format!("ledger/{}/", hex::encode(dev));
                let after = if head.forked || head.seq == 0 {
                    String::new()
                } else {
                    ledger3::checkpoint::batch_key(dev, head.seq)
                };
                let names = backend.list_after(&prefix, &after)?;
                // The newest checkpoint first: it stands in for batches a
                // pruning device deleted (other devices' only; one of this
                // device's own is its own).
                let newest_cp = names
                    .iter()
                    .filter_map(|n| n.strip_prefix(&prefix))
                    .filter_map(ledger3::LedgerObject::parse)
                    .filter_map(|o| match o {
                        ledger3::LedgerObject::Checkpoint(s, 0) => Some(s),
                        _ => None,
                    })
                    .filter(|s| self.keep3(dev, *s))
                    .max();
                if let (Some(s), false) = (newest_cp, *dev == me) {
                    self.pull_checkpoint3(backend.as_ref(), dev, pk, s)?;
                }
                for name in names {
                    let Some(file) = name.strip_prefix(&prefix) else {
                        continue;
                    };
                    let Some(ledger3::LedgerObject::Batch(seq)) =
                        ledger3::LedgerObject::parse(file)
                    else {
                        continue;
                    };
                    let head = self.f3.ledger.head(dev);
                    if !self.keep3(dev, seq)
                        || self.f3.ledger.get(dev, seq)?.is_some()
                        || (head.base.as_ref().is_some_and(|b| seq <= b.seq) && !head.forked)
                    {
                        continue;
                    }
                    let Some(bytes) = backend.get_bounded(&name, crate::record::MAX_PART_READ)?
                    else {
                        continue;
                    };
                    let Ok(rec) = crate::record::SignedRecord::decode(&bytes) else {
                        log::warn!(storage = backend.name(); "ledger: {name} is not a record");
                        continue;
                    };
                    if *dev == me && seq > head.seq {
                        if rec.verify(pk).is_ok() {
                            // Another copy of this identity published ahead of us.
                            forks.insert(DeviceId::from_bytes(dev));
                            self.forked_self = true;
                        }
                        continue;
                    }
                    let key = self.key_for3(&rec.key_id);
                    match self
                        .f3
                        .ledger
                        .ingest_named(&name, rec, pk, key.as_ref(), limit)
                    {
                        Ok(Ingest::Fork) => {
                            forks.insert(DeviceId::from_bytes(dev));
                        }
                        Ok(Ingest::Refused) => {
                            log::warn!(storage = backend.name(), seq = seq; "ledger batch refused");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            log::warn!(storage = backend.name(), seq = seq, error:% = e; "ledger batch skipped");
                        }
                    }
                }
            }
        }
        let view = self.view3()?;
        self.observe_clock(view.max_lamport)?;
        Ok(forks.into_iter().collect())
    }

    /// Take the newest checkpoint of another device listed in `objects`
    /// when it is newer than the one held here: it stands in for the
    /// batches it covers, which may be gone from the storages.
    fn pull_checkpoint3(
        &mut self,
        backend: &dyn Storage,
        dev: &Id16,
        pk: &crypto::VerifyingKey,
        seq: u64,
    ) -> Result<()> {
        let head = self.f3.ledger.head(dev);
        if head.base.as_ref().is_some_and(|b| b.seq >= seq) {
            return Ok(());
        }
        let name0 = ledger3::checkpoint::checkpoint_key(dev, seq, 0);
        let Some(b0) = backend.get_bounded(&name0, crate::record::MAX_PART_READ)? else {
            return Ok(());
        };
        let Ok(first) = crate::record::SignedRecord::decode(&b0) else {
            return Ok(());
        };
        let mut read = vec![(name0, b0)];
        for part in 1..first.parts.min(crate::record::MAX_PARTS) {
            let name = ledger3::checkpoint::checkpoint_key(dev, seq, part);
            match backend.get_bounded(&name, crate::record::MAX_PART_READ)? {
                Some(b) => read.push((name, b)),
                None => return Ok(()),
            }
        }
        if self.scope3(dev, &first.key_id) != Some(EventScope::Full) {
            return Ok(());
        }
        let Some(key) = self.key_for3(&first.key_id) else {
            return Ok(());
        };
        let vault = members3::bin(&self.vault.vault_id)?;
        let Ok((envs, cp)) = ledger3::Checkpoint::accept(&read, &vault, pk, &key) else {
            log::warn!(storage = backend.name(), seq = seq; "ledger checkpoint refused");
            return Ok(());
        };
        let floor = head.seq.max(head.base.as_ref().map_or(0, |b| b.seq));
        let anchor = if seq > floor.saturating_add(ledger3::MAX_AHEAD) {
            backend
                .get_bounded(
                    &ledger3::checkpoint::batch_key(dev, seq),
                    crate::record::MAX_PART_READ,
                )?
                .and_then(|b| crate::record::SignedRecord::decode(&b).ok())
                .filter(|b| b.verify(pk).is_ok())
        } else {
            None
        };
        self.f3
            .ledger
            .ingest_checkpoint(&envs, &cp, anchor.as_ref())?;
        Ok(())
    }

    /// The full devices whose acknowledgements let a checkpoint's batches
    /// go: every device of the registry that is not removed.
    fn ledger_readers3(&self) -> Vec<Id16> {
        self.f3
            .members
            .devices
            .devices
            .keys()
            .filter(|d| !self.f3.members.revoked.contains(*d))
            .copied()
            .collect()
    }

    /// Keep the ledger small after a sync (design section 4, "Checkpoints",
    /// "Acknowledgements", "Pruning"): acknowledge the other devices'
    /// checkpoints, write a checkpoint of this device's own batches when
    /// enough have accumulated, and once every reader acknowledged a
    /// checkpoint delete the batches it covers (on the hot storages for
    /// this device's own, locally for everyone's). Cold storages are left
    /// as they are.
    pub(crate) fn ledger_upkeep3(&mut self) -> Result<()> {
        if self.vault.member
            || self.forked_self
            || self.removal.is_some()
            || self.ledger_alarm.needs_rebuild()
        {
            return Ok(());
        }
        let me = self.me3();
        let view = self.view3()?;
        // 1. Acknowledge other devices' checkpoints in a batch of our own.
        let ack_due = self.f3.ledger.devices().iter().any(|d| {
            *d != me
                && self
                    .f3
                    .ledger
                    .head(d)
                    .base
                    .is_some_and(|b| view.acked(&me, d, None) < b.seq)
        });
        if ack_due && self.cycle.is_none() {
            let (key_id, key) = self.ledger_key3()?;
            let lamport = self.tick()?;
            let seen = self.f3.ledger.vault_seen(&me);
            self.f3.ledger.append_own(
                &me,
                Vec::new(),
                seen,
                lamport,
                &key,
                &key_id,
                ledger3::NO_FOLDER,
                &self.keys.signer,
            )?;
            self.push_own_batches3()?;
        }
        // 2. A checkpoint of our own batches.
        let head = self.f3.ledger.head(&me);
        let base = head.base.as_ref().map_or(0, |b| b.seq);
        if head.seq >= base + self.ledger_policy.checkpoint_every.max(1) {
            let (key_id, key) = self.ledger_key3()?;
            let own = self
                .f3
                .ledger
                .contribution(&me, head.seq, |id| self.key_for3(id))?;
            let parts = self.f3.ledger.seal_checkpoint(
                &me,
                head.seq,
                own,
                &key,
                &key_id,
                &self.keys.signer,
            )?;
            for (spec, backend) in self.metadata_storages(false)? {
                if spec.is_carrier() {
                    continue;
                }
                for p in &parts {
                    backend.put_if_absent(
                        &ledger3::checkpoint::checkpoint_key(&me, p.seq, p.part),
                        &p.encode(),
                    )?;
                }
            }
        }
        // 3. What checkpoints cover goes once every reader has seen past it.
        let view = self.view3()?;
        let readers = self.ledger_readers3();
        let keep = self.ledger_policy.keep_before;
        if let Some(b) = self.f3.ledger.head(&me).base {
            if view.vault_acked_by_all(readers.iter(), &me, b.seq) {
                let upto = b.seq.saturating_sub(keep);
                let prefix = format!("ledger/{}/", hex::encode(me));
                for (spec, backend) in self.metadata_storages(false)? {
                    if spec.is_carrier()
                        || self.f3.ledger.pruned(spec.name()) >= upto
                        || !backend.exists(&ledger3::checkpoint::checkpoint_key(&me, b.seq, 0))?
                    {
                        continue;
                    }
                    for seq in self.f3.ledger.pruned(spec.name()) + 1..=upto {
                        backend.delete(&ledger3::checkpoint::batch_key(&me, seq))?;
                    }
                    for name in backend.list(&prefix)? {
                        if let Some(ledger3::LedgerObject::Checkpoint(s, _)) = name
                            .strip_prefix(&prefix)
                            .and_then(ledger3::LedgerObject::parse)
                        {
                            if s < b.seq {
                                backend.delete(&name)?;
                            }
                        }
                    }
                    self.f3.ledger.set_pruned(spec.name(), upto)?;
                }
                self.f3.ledger.drop_through(&me, upto)?;
            }
        }
        for d in self.f3.ledger.devices() {
            if d == me {
                continue;
            }
            if let Some(b) = self.f3.ledger.head(&d).base {
                if self.keep3(&d, b.seq) && view.vault_acked_by_all(readers.iter(), &d, b.seq) {
                    self.f3.ledger.drop_through(&d, b.seq)?;
                }
            }
        }
        Ok(())
    }
}
