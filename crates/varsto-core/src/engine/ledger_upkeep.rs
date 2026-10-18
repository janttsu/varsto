// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Keeping the ledger cheap as it grows. The mailbox reads only what is new:
//! a pull lists each known device's batches after the head this device
//! already holds, and a push lists its own batches from the newest one a
//! storage is known to hold (`pushed.json`), so neither lists the whole
//! `ledger/` prefix on every sync.
//!
//! The location view is not replayed from every batch on every call: it is
//! kept in memory and in `ledger/view.enc` (encrypted under a key derived
//! from this device's root key) together with the batches it was built
//! from, and new batches are applied to it as they arrive. Applying is
//! order-independent, so the result equals a full replay. A change of keys
//! (a key epoch, a shared folder) or of revocation cut-offs (which can drop
//! batches already applied) rebuilds it; retirements, replica claims and
//! forks are applied on top at every call, as a full replay does.
//!
//! One user action seals at most one batch (`one_batch`), and small events
//! that nobody waits for wait for the next one (`ledger/pending.json`).
//! After a sync, `ledger_upkeep` writes checkpoints of this device's own
//! batches, acknowledges other devices' checkpoints, and deletes batches a
//! checkpoint covers once every reader has acknowledged it
//! (`docs/spec/alpha-0-format.md` section 22).

use super::*;
use crate::ledger::{LedgerObject, SignedCheckpoint};

/// Listing start for the objects of `device` after batch `seq` (0: all).
/// Checkpoint names sort after every batch name, so they are always listed.
fn start_after(device: &DeviceId, seq: u64) -> String {
    if seq == 0 {
        String::new()
    } else {
        SignedBatch::storage_key(device, seq)
    }
}

/// The batches and checkpoints of `device` on a storage after batch `seq`.
fn remote_objects(
    backend: &dyn Storage,
    device: &DeviceId,
    seq: u64,
) -> Result<BTreeSet<LedgerObject>> {
    let prefix = format!("ledger/{device}/");
    Ok(backend
        .list_after(&prefix, &start_after(device, seq))?
        .iter()
        .filter_map(|k| k.strip_prefix(&prefix).and_then(LedgerObject::parse))
        .collect())
}

fn batches_of(objects: &BTreeSet<LedgerObject>) -> BTreeSet<u64> {
    objects
        .iter()
        .filter_map(|o| match o {
            LedgerObject::Batch(s) => Some(*s),
            LedgerObject::Checkpoint(_) => None,
        })
        .collect()
}

fn checkpoints_of(objects: &BTreeSet<LedgerObject>) -> BTreeSet<u64> {
    objects
        .iter()
        .filter_map(|o| match o {
            LedgerObject::Checkpoint(s) => Some(*s),
            LedgerObject::Batch(_) => None,
        })
        .collect()
}

/// When a device writes a checkpoint of its own batches and how many
/// batches it keeps on the storages before its newest checkpoint.
#[derive(Clone, Copy, Debug)]
pub struct LedgerPolicy {
    /// At least this many own batches since the last checkpoint; more when
    /// the last checkpoint was large, so checkpoints cost at most about as
    /// much as the batches they replace.
    pub checkpoint_every: u64,
    /// Batches kept before the newest checkpoint (fork detection).
    pub keep_before: u64,
}

impl Default for LedgerPolicy {
    fn default() -> Self {
        LedgerPolicy {
            checkpoint_every: 256,
            keep_before: 8,
        }
    }
}

/// Typical size of a stored batch (mostly its hybrid signature).
const TYPICAL_BATCH_BYTES: u64 = 8 * 1024;

/// Events recorded but not yet sealed into a batch, kept across restarts.
const DEFERRED_FILE: &str = "ledger/pending.json";

/// The events waiting for the next batch, and whether the file holding
/// them could not be read (it is then moved aside and its events are lost:
/// `docs/spec/alpha-0-format.md` section 38 says which come back).
pub(super) fn load_deferred(home: &Path) -> (Vec<Event>, bool) {
    let path = home.join(DEFERRED_FILE);
    if !path.exists() {
        return (Vec::new(), false);
    }
    match util::read_json(&path) {
        Ok(events) => (events, false),
        Err(_) => {
            let _ = ledger::set_aside(&path);
            (Vec::new(), true)
        }
    }
}

/// One action whose ledger events go into a single batch.
#[derive(Default)]
pub(super) struct Cycle {
    /// Forks found by the ledger pull of this action, which runs once.
    forks: Option<Vec<DeviceId>>,
}

/// Save the cached view after this many newly applied batches; a view that
/// is not saved is brought up to date from the batches on the next run.
const VIEW_SAVE_EVERY: u64 = 32;

/// The cached location view of one engine.
#[derive(Default)]
pub(super) struct ViewSlot {
    cache: Option<ledger::ViewCache>,
    loaded: bool,
    unsaved: u64,
}

impl Engine {
    /// Run `f` with every ledger event it records sealed into one batch when
    /// it returns, also when it fails (what was done stays recorded). Nested
    /// calls join the outer one.
    pub fn one_batch<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.one_batch_seq(f).map(|(out, _)| out)
    }

    /// Like `one_batch`, with the sequence number of the batch (if any).
    pub(super) fn one_batch_seq<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<(T, Option<u64>)> {
        if self.cycle.is_some() {
            return f(self).map(|out| (out, None));
        }
        self.cycle = Some(Cycle::default());
        let out = f(self);
        self.cycle = None;
        let committed = self.commit_batch();
        let out = out?;
        Ok((out, committed?))
    }

    /// Fetch, check and keep checkpoint `seq` of another device. One that
    /// does not verify or open is skipped (the batches still count), and so
    /// is one that is not a trusted full device's: replicas and members
    /// write none, and a checkpoint speaks for its signer only anyway
    /// (`LedgerView::restricted_to`). One far beyond the batches held is
    /// kept only beside the signed batch it ends at.
    fn pull_checkpoint(
        &mut self,
        backend: &dyn Storage,
        dev: &DeviceId,
        seq: u64,
        pk: &crypto::VerifyingKey,
    ) -> Result<Ingest> {
        let Some(blob) = backend.get(&SignedCheckpoint::storage_key(dev, seq))? else {
            return Ok(Ingest::Known);
        };
        let Ok(cp) = serde_json::from_slice::<SignedCheckpoint>(&blob) else {
            return Ok(Ingest::Known);
        };
        if &cp.device != dev || cp.seq != seq || cp.verify(pk).is_err() {
            return Ok(Ingest::Known);
        }
        if self.event_scope(dev, &cp.key_id) != Some(ledger::EventScope::Full) {
            return Ok(Ingest::Known);
        }
        let head = self.ledger.head(dev);
        let floor = head.seq.max(head.base.as_ref().map(|b| b.seq).unwrap_or(0));
        let anchor = if seq > floor.saturating_add(ledger::MAX_AHEAD) {
            backend
                .get(&SignedBatch::storage_key(dev, seq))?
                .and_then(|b| serde_json::from_slice::<SignedBatch>(&b).ok())
                .filter(|b| b.verify(pk).is_ok())
        } else {
            None
        };
        match self.key_for_id(&cp.key_id) {
            Some(key) if cp.open(&key).is_ok() => {
                self.ledger.ingest_checkpoint_anchored(cp, anchor.as_ref())
            }
            _ => Ok(Ingest::Known),
        }
    }

    /// The newest batch of every other device held here, for the `seen`
    /// field of this device's next batch.
    pub(super) fn seen_heads(&self) -> BTreeMap<DeviceId, u64> {
        self.ledger
            .devices()
            .into_iter()
            .filter(|d| d != &self.vault.device_id)
            .map(|d| {
                let seq = self.ledger.head(&d).seq;
                (d, seq)
            })
            .filter(|(_, seq)| *seq > 0)
            .collect()
    }

    /// The devices whose acknowledgement a checkpoint needs before the
    /// batches it covers may go: full devices of the vault that are trusted
    /// and not revoked. Members of shared folders and replicas do not read
    /// the vault ledger.
    pub(super) fn ledger_readers(&self) -> Vec<DeviceId> {
        self.devices
            .devices
            .keys()
            .filter(|d| *d != &self.vault.device_id && self.trusted(d))
            .cloned()
            .collect()
    }

    /// Whether every reader other than `device` itself has said it holds
    /// `device`'s batches up to `seq`.
    fn all_acked(&self, view: &LedgerView, device: &DeviceId, seq: u64) -> bool {
        self.ledger_readers()
            .iter()
            .filter(|r| *r != device)
            .all(|r| {
                view.acks
                    .get(r)
                    .and_then(|a| a.get(device))
                    .is_some_and(|s| *s >= seq)
            })
    }

    /// Keep the ledger small, after a sync: acknowledge other devices'
    /// checkpoints, write a checkpoint of this device's own batches when
    /// enough have accumulated, and once every reader has acknowledged a
    /// checkpoint delete the batches it covers (on the hot storages for
    /// this device's own, locally for everyone's). Cold storages are left
    /// as they are.
    pub fn ledger_upkeep(&mut self) -> Result<()> {
        crate::logged_op_plain!("ledger upkeep", "", { self.ledger_upkeep3() })
    }

    /// Format 2 (f3-switch: part B deletes it).
    fn ledger_upkeep_inner2(&mut self) -> Result<()> {
        if self.vault.member
            || self.forked_self
            || self.removal.is_some()
            || self.ledger_alarm.needs_rebuild()
        {
            return Ok(());
        }
        let me = self.vault.device_id.clone();
        let view = self.view()?;

        // 1. Acknowledge checkpoints of others in a batch of our own.
        let acked = view.acks.get(&me).cloned().unwrap_or_default();
        let ack_due = self.ledger.devices().iter().any(|d| {
            d != &me
                && self
                    .ledger
                    .head(d)
                    .base
                    .is_some_and(|b| acked.get(d).copied().unwrap_or(0) < b.seq)
        });
        if ack_due {
            if self.pending.is_empty() {
                let lamport = self.tick()?;
                let (key_id, key) = self.ledger_key_now();
                self.ledger.append_own_seen(
                    &me,
                    Vec::new(),
                    self.seen_heads(),
                    lamport,
                    &key,
                    &key_id,
                    &self.keys.signer,
                )?;
                self.push_own_batches()?;
            } else {
                self.commit_batch()?;
            }
        }

        // 2. A checkpoint of our own batches.
        let head = self.ledger.head(&me);
        let base = head.base.as_ref().map(|b| b.seq).unwrap_or(0);
        let last_size = match head.base.as_ref() {
            Some(_) => self
                .ledger
                .checkpoint(&me)?
                .map(|c| c.body_hex.len() as u64 / 2)
                .unwrap_or(0),
            None => 0,
        };
        let every = self
            .ledger_policy
            .checkpoint_every
            .max(last_size / TYPICAL_BATCH_BYTES);
        if head.seq >= base + every {
            let (key_id, key) = self.ledger_key_now();
            let own = self
                .ledger
                .contribution(&me, head.seq, |id| self.key_for_id(id))?;
            self.ledger
                .seal_checkpoint(&me, head.seq, own, &key, &key_id, &self.keys.signer)?;
            self.push_own_batches()?;
        }

        // 3. Drop what checkpoints cover once every reader has seen past them.
        let view = self.view()?;
        let keep = self.ledger_policy.keep_before;
        if let Some(b) = self.ledger.head(&me).base {
            if self.all_acked(&view, &me, b.seq) {
                let upto = b.seq.saturating_sub(keep);
                for (spec, backend) in self.metadata_storages(false)? {
                    if self.ledger.pruned(spec.name()) >= upto
                        || !backend.exists(&SignedCheckpoint::storage_key(&me, b.seq))?
                    {
                        continue;
                    }
                    for seq in self.ledger.pruned(spec.name()) + 1..=upto {
                        backend.delete(&SignedBatch::storage_key(&me, seq))?;
                    }
                    for old in checkpoints_of(&remote_objects(backend.as_ref(), &me, upto)?) {
                        if old < b.seq {
                            backend.delete(&SignedCheckpoint::storage_key(&me, old))?;
                        }
                    }
                    self.ledger.set_pruned(spec.name(), upto)?;
                }
                self.ledger.drop_through(&me, upto)?;
            }
        }
        for d in self.ledger.devices() {
            if d == me {
                continue;
            }
            if let Some(b) = self.ledger.head(&d).base {
                if self.batch_accepted(&d, b.seq) && self.all_acked(&view, &d, b.seq) {
                    self.ledger.drop_through(&d, b.seq)?;
                }
            }
        }
        Ok(())
    }

    /// Write a checkpoint after `checkpoint_every` own batches and keep
    /// `keep_before` batches before it (tests and measurements; the
    /// defaults are `LedgerPolicy::default()`).
    #[doc(hidden)]
    pub fn set_ledger_policy(&mut self, checkpoint_every: u64, keep_before: u64) {
        self.ledger_policy = LedgerPolicy {
            checkpoint_every,
            keep_before,
        };
    }

    /// Tests: what a modified client could sign, a batch of exactly
    /// `events` under the key with id `key_id` (`None`: this device's own,
    /// a member's for its first shared folder) at Lamport time `lamport`
    /// (`None`: the next tick), pushed to every storage. Other devices must
    /// take from it only what this device's role allows.
    #[doc(hidden)]
    pub fn seal_batch_unchecked(
        &mut self,
        key_id: Option<&str>,
        events: Vec<Event>,
        lamport: Option<u64>,
    ) -> Result<u64> {
        let (key_id, key) = match key_id {
            Some(id) => (
                id.to_string(),
                self.key_for_id(id)
                    .ok_or_else(|| anyhow!("no key for {id} on this device"))?,
            ),
            None if self.vault.member => {
                bail!("a member device writes format-3 folder-scoped batches only")
            }
            None => self.ledger_key_now(),
        };
        let lamport = match lamport {
            Some(l) => l,
            None => self.tick()?,
        };
        let seen = if self.vault.member {
            BTreeMap::new()
        } else {
            self.seen_heads()
        };
        let signed = self.ledger.append_own_seen(
            &self.vault.device_id.clone(),
            events,
            seen,
            lamport,
            &key,
            &key_id,
            &self.keys.signer,
        )?;
        self.push_own_batches()?;
        Ok(signed.seq)
    }

    /// Pull the ledger, once per `one_batch` action.
    pub(super) fn pull_ledger_once(&mut self) -> Result<Vec<DeviceId>> {
        if let Some(forks) = self.cycle.as_ref().and_then(|c| c.forks.clone()) {
            return Ok(forks);
        }
        let forks = self.pull_ledger()?;
        if let Some(c) = self.cycle.as_mut() {
            c.forks = Some(forks.clone());
        }
        Ok(forks)
    }

    /// Keep the recorded events for the next batch, on disk so a restart
    /// does not lose them. They count in this device's view meanwhile.
    pub(super) fn defer_events(&mut self) -> Result<()> {
        self.locate_pending();
        if self.pending.is_empty() {
            self.clear_deferred();
            return Ok(());
        }
        util::write_json(&self.home.join(DEFERRED_FILE), &self.pending)
    }

    pub(super) fn clear_deferred(&self) {
        let _ = fs::remove_file(self.home.join(DEFERRED_FILE));
    }

    /// The location view: the cached one, updated with the batches that
    /// arrived since, or rebuilt when keys or cut-offs changed.
    pub fn view(&self) -> Result<LedgerView> {
        let context = self.view_context();
        let mut slot = self.view_cache.lock().unwrap_or_else(|e| e.into_inner());
        let ViewSlot {
            cache,
            loaded,
            unsaved,
        } = &mut *slot;
        if !*loaded {
            *loaded = true;
            *cache = self.load_view_cache();
        }
        let fits = cache.as_ref().is_some_and(|c| {
            c.format == ledger::ViewCache::FORMAT
                && c.context == context
                && self.ledger.cache_fits(c)
        });
        if !fits {
            *cache = Some(ledger::ViewCache::new(context));
            *unsaved = VIEW_SAVE_EVERY;
        }
        let c = cache.as_mut().expect("set above");
        *unsaved += self.ledger.update_view_scoped(
            c,
            |id| self.key_for_id(id),
            |d, seq| self.batch_accepted(d, seq),
            |d, id| self.event_scope(d, id),
        )?;
        if *unsaved >= VIEW_SAVE_EVERY && self.save_view_cache(c).is_ok() {
            *unsaved = 0;
        }
        let generation = Self::pack_generation(&c.raw, &c.context);
        if self.pending.is_empty() {
            let view = self.ledger.finish(&c.raw);
            self.feed_pack_locator(&view, generation);
            return Ok(view);
        }
        // Events recorded and not sealed yet count as this device's next batch.
        let mut raw = c.raw.clone();
        raw.apply(&ledger::Batch {
            device: self.vault.device_id.clone(),
            seq: self.ledger.head(&self.vault.device_id).seq + 1,
            prev: None,
            lamport: self.clock.lamport + 1,
            created_utc: util::now_utc(),
            events: self.pending.clone(),
            seen: BTreeMap::new(),
        });
        raw.batches -= 1;
        let view = self.ledger.finish_owned(raw);
        self.feed_pack_locator(&view, generation);
        Ok(view)
    }

    /// The view replayed from every local batch, without the cache (and
    /// without events not sealed into a batch yet).
    pub fn view_replayed(&self) -> Result<LedgerView> {
        self.ledger.view_scoped(
            |id| self.key_for_id(id),
            |d, seq| self.batch_accepted(d, seq),
            |d, id| self.event_scope(d, id),
        )
    }

    /// Fingerprint of what decides which batches count: every key id this
    /// device can open (with a hash of the key), every revocation cut-off
    /// and the role of every device.
    fn view_context(&self) -> String {
        let mut ids = vec![KEY_LEDGER.to_string(), KEY_REPLICA.to_string()];
        ids.extend(
            self.epochs
                .keys
                .keys()
                .filter(|e| **e > 0)
                .map(|e| format!("{}{e}", ledger::KEY_LEDGER_EPOCH_PREFIX)),
        );
        let mut parts: Vec<Vec<u8>> = Vec::new();
        for id in ids {
            if let Some(k) = self.key_for_id(&id) {
                parts.push(id.into_bytes());
                parts.push(crypto::hash(&k.0).to_vec());
            }
        }
        for (d, r) in &self.devices.revoked {
            parts.push(d.as_str().as_bytes().to_vec());
            parts.push(r.cutoff_seq.to_le_bytes().to_vec());
        }
        for (d, cutoff) in &self.devices.share_viewers {
            parts.push(b"viewer".to_vec());
            parts.push(d.as_str().as_bytes().to_vec());
            parts.push(cutoff.to_le_bytes().to_vec());
        }
        // Which role each device's batches are read with (`event_scope`).
        parts.push(b"scopes".to_vec());
        parts.push(self.scope_context());
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        hex::encode(crypto::hash(&crypto::aad("ledger-view-context", &refs)))
    }

    /// Forget the cached view (memory and `ledger/view.enc`): the next
    /// call rebuilds it from the batches.
    pub(super) fn reset_view_cache(&self) {
        let mut slot = self.view_cache.lock().unwrap_or_else(|e| e.into_inner());
        *slot = ViewSlot {
            cache: None,
            loaded: true,
            unsaved: 0,
        };
        let _ = fs::remove_file(self.view_cache_path());
    }

    fn view_cache_path(&self) -> PathBuf {
        self.home.join("ledger").join("view.enc")
    }

    fn view_cache_key(&self) -> (SecretKey, Vec<u8>) {
        (
            self.keys.master.derive("ledger-view-cache", &[]),
            crypto::aad(
                "ledger-view-cache",
                &[
                    self.vault.vault_id.as_str().as_bytes(),
                    self.vault.device_id.as_str().as_bytes(),
                ],
            ),
        )
    }

    /// The saved view, if there is one that opens and parses.
    fn load_view_cache(&self) -> Option<ledger::ViewCache> {
        let blob = fs::read(self.view_cache_path()).ok()?;
        let (key, aad) = self.view_cache_key();
        let packed = crypto::decrypt(&key, &aad, &blob).ok()?;
        let json = zstd::bulk::decompress(&packed, 1 << 30).ok()?;
        serde_json::from_slice(&json).ok()
    }

    fn save_view_cache(&self, cache: &ledger::ViewCache) -> Result<()> {
        let path = self.view_cache_path();
        // Never recreate a ledger directory that was removed (reset, wipe).
        if !path.parent().is_some_and(|p| p.is_dir()) {
            return Ok(());
        }
        let json = serde_json::to_vec(cache)?;
        let packed = zstd::bulk::compress(&json, 3)?;
        let (key, aad) = self.view_cache_key();
        util::write_atomic(&path, &crypto::encrypt(&key, &aad, &packed)?)
    }

    /// Push every own batch that a hot metadata storage does not have yet
    /// (format 3, `ledger3_ops`).
    pub(super) fn push_own_batches(&mut self) -> Result<()> {
        self.push_own_batches3()
    }

    /// Pull the membership and everyone's new batches (format 3,
    /// `ledger3_ops`).
    pub(super) fn pull_ledger(&mut self) -> Result<Vec<DeviceId>> {
        self.pull_ledger3()
    }

    /// Push every own batch (and the newest own checkpoint) that a storage
    /// does not have yet; detect forks. Format 2 (f3-switch: part B
    /// deletes it).
    pub(super) fn push_own_batches2(&mut self) -> Result<()> {
        let me = self.vault.device_id.clone();
        let head = self.ledger.head(&me);
        let checkpoint = self.ledger.checkpoint(&me)?;
        for (spec, backend) in self.metadata_storages(true)? {
            // List from the newest batch this storage is known to hold, so
            // that batch is seen again: a storage that lost it (or another
            // storage under a known name) is filled from the start.
            let mut done = self.ledger.pushed(spec.name()).min(head.seq);
            let mut objects = remote_objects(backend.as_ref(), &me, done.saturating_sub(1))?;
            let mut present = batches_of(&objects);
            if done > 0 && !present.contains(&done) && done > head.dropped {
                done = 0;
                objects = remote_objects(backend.as_ref(), &me, 0)?;
                present = batches_of(&objects);
            }
            // Only objects this device's key signed are its history; junk
            // under its name is noted and never taken for a fork.
            for newest in present.iter().rev().take_while(|n| **n > head.seq) {
                if self.own_object_genuine(
                    spec.name(),
                    backend.as_ref(),
                    &LedgerObject::Batch(*newest),
                )? {
                    bail!("ledger fork: storage {} holds batch {} of this device, newer than its own last batch {} (restored from an old copy?)", backend.name(), newest, head.seq);
                }
            }
            for newest in checkpoints_of(&objects)
                .iter()
                .rev()
                .take_while(|n| **n > head.seq)
            {
                if self.own_object_genuine(
                    spec.name(),
                    backend.as_ref(),
                    &LedgerObject::Checkpoint(*newest),
                )? {
                    bail!("ledger fork: storage {} holds checkpoint {} of this device, newer than its own last batch {} (restored from an old copy?)", backend.name(), newest, head.seq);
                }
            }
            if let Some(cp) = checkpoint.as_ref() {
                if !checkpoints_of(&objects).contains(&cp.seq) {
                    backend.put_if_absent(
                        &SignedCheckpoint::storage_key(&me, cp.seq),
                        &serde_json::to_vec(cp)?,
                    )?;
                }
            }
            for seq in done.max(head.dropped).max(1)..=head.seq {
                let key = SignedBatch::storage_key(&me, seq);
                if present.contains(&seq) {
                    if seq == head.seq {
                        if let (Some(remote), Some(batch)) =
                            (backend.get(&key)?, self.ledger.get(&me, seq)?)
                        {
                            let remote = serde_json::from_slice::<SignedBatch>(&remote)
                                .ok()
                                .filter(|r| r.device == me && r.seq == seq);
                            match remote {
                                Some(r) if r.hash == batch.hash => {}
                                Some(r) if r.verify(&self.keys.signer.public()).is_ok() => {
                                    bail!("ledger fork: storage {} already holds a different batch {} of this device (restored from an old copy?)", backend.name(), seq);
                                }
                                _ => {
                                    // Junk occupies the name: noted; the
                                    // other storages hold the batch.
                                    self.own_object_genuine(
                                        spec.name(),
                                        backend.as_ref(),
                                        &LedgerObject::Batch(seq),
                                    )?;
                                }
                            }
                        }
                    }
                    continue;
                }
                let Some(batch) = self.ledger.get(&me, seq)? else {
                    continue;
                };
                let written = backend.put_if_absent(&key, &serde_json::to_vec(&batch)?)?;
                if !written {
                    let same = backend
                        .get(&key)?
                        .and_then(|b| serde_json::from_slice::<SignedBatch>(&b).ok())
                        .is_some_and(|r| r.hash == batch.hash);
                    if !same
                        && self.own_object_genuine(
                            spec.name(),
                            backend.as_ref(),
                            &LedgerObject::Batch(seq),
                        )?
                    {
                        bail!(
                            "ledger fork: batch {} of this device appeared on {} concurrently",
                            seq,
                            backend.name()
                        );
                    }
                }
            }
            self.ledger.set_pushed(spec.name(), head.seq)?;
        }
        self.ledger_alarm.watch.save(&self.home);
        Ok(())
    }

    /// Pull everyone's new batches from every hot storage: for each device
    /// with a known key, only the batches after the local head, and its
    /// newest checkpoint when that is newer than the one held here. Format
    /// 2 (f3-switch: part B deletes it).
    pub(super) fn pull_ledger2(&mut self) -> Result<Vec<DeviceId>> {
        self.pull_registry()?;
        self.sync_membership()?;
        let dir = self.key_directory()?;
        let me = self.vault.device_id.clone();
        let mut devices: Vec<DeviceId> = dir.keys().cloned().collect();
        devices.sort();
        // What peers say they hold (section 74); the pull below asks the
        // storages for it.
        self.exchange_heads();
        let mut forks = BTreeSet::new();
        let (mut malformed, mut refused) = (0u64, 0u64);
        for (spec, backend) in self.metadata_storages(false)? {
            for dev in &devices {
                let head = self.ledger.head(dev);
                if !self.batch_accepted(dev, head.seq + 1) {
                    // Revoked, and everything up to the cut-off is here.
                    continue;
                }
                // Our own identity is listed after our head too: anything
                // there was written by another copy of this device. A forked
                // device is read in full, as it always was.
                let after = if head.forked { 0 } else { head.seq };
                let objects = remote_objects(backend.as_ref(), dev, after)?;
                if !objects.is_empty() {
                    log::debug!(device:% = dev, storage = backend.name(), after = after, objects = objects.len(); "ledger: new objects of a device");
                }
                let pk = &dir[dev];
                if dev == &me {
                    // Only a checkpoint this device's key signed fences it:
                    // anything else under its name is junk.
                    let own_head = self.ledger.head(&me).seq;
                    for n in checkpoints_of(&objects).into_iter().rev() {
                        if n <= own_head {
                            break;
                        }
                        let o = LedgerObject::Checkpoint(n);
                        if self.own_object_genuine(spec.name(), backend.as_ref(), &o)? {
                            forks.insert(me.clone());
                            self.mark_forked(&me)?;
                            break;
                        }
                    }
                } else if let Some(n) = checkpoints_of(&objects)
                    .into_iter()
                    .rfind(|n| self.batch_accepted(dev, *n))
                {
                    if !self.vault.member && head.base.as_ref().is_none_or(|b| b.seq < n) {
                        if let Ingest::Fork = self.pull_checkpoint(backend.as_ref(), dev, n, pk)? {
                            forks.insert(dev.clone());
                        }
                    }
                }
                for seq in batches_of(&objects) {
                    if !self.batch_accepted(dev, seq) {
                        // Signed by a revoked device after its cut-off.
                        continue;
                    }
                    let head = self.ledger.head(dev);
                    if head.base.as_ref().is_some_and(|b| seq <= b.seq) && !head.forked {
                        // A checkpoint held here covers it.
                        continue;
                    }
                    if (self.ledger.get(dev, seq)?.is_some() || self.ledger.has_pending(dev, seq))
                        && !head.forked
                    {
                        continue;
                    }
                    if dev == &me
                        && self
                            .ledger_alarm
                            .watch
                            .junk
                            .get(spec.name())
                            .is_some_and(|j| j.contains(&SignedBatch::storage_key(dev, seq)))
                    {
                        // Known junk under this device's name.
                        continue;
                    }
                    let Some(blob) = backend.get(&SignedBatch::storage_key(dev, seq))? else {
                        continue;
                    };
                    // One storage holding a damaged or planted object does
                    // not stop the pull: another storage may hold the batch.
                    let parsed = serde_json::from_slice::<SignedBatch>(&blob)
                        .ok()
                        .filter(|b| &b.device == dev && b.seq == seq);
                    let Some(signed) = parsed else {
                        if dev == &me {
                            self.own_object_genuine(
                                spec.name(),
                                backend.as_ref(),
                                &LedgerObject::Batch(seq),
                            )?;
                        } else {
                            malformed += 1;
                        }
                        continue;
                    };
                    // A batch under a key this device lacks is kept unread.
                    let key = self.key_for_id(&signed.key_id);
                    if dev == &me && seq > self.ledger.head(&me).seq {
                        if signed.verify(pk).is_err() {
                            // Not signed by this device: junk, it fences nothing.
                            self.own_object_genuine(
                                spec.name(),
                                backend.as_ref(),
                                &LedgerObject::Batch(seq),
                            )?;
                            continue;
                        }
                        // Another copy of this device identity published ahead of us.
                        forks.insert(me.clone());
                        let _ = self.ledger.ingest_with(signed, pk, key.as_ref());
                        self.mark_forked(&me)?;
                        continue;
                    }
                    let limit = self.clock.lamport.saturating_add(Self::CLOCK_LEAP);
                    match self.ledger.ingest_limited(signed, pk, key.as_ref(), limit) {
                        Ok(Ingest::Fork) => {
                            forks.insert(dev.clone());
                        }
                        Ok(Ingest::Refused) => {
                            refused += 1;
                            log::warn!(device:% = dev, seq = seq, storage = backend.name(); "ledger batch refused");
                        }
                        Ok(Ingest::New | Ingest::Known | Ingest::Pending) => {}
                        Err(e) => {
                            malformed += 1;
                            log::warn!(device:% = dev, seq = seq, storage = backend.name(), error:% = e; "ledger batch skipped");
                        }
                    }
                }
            }
        }
        let view = self.view()?;
        self.observe_clock(view.max_lamport)?;
        self.watch_freshness(&view, &dir, malformed, refused);
        Ok(forks.into_iter().collect())
    }

    /// After a pull: which devices' batches this device still lacks while
    /// another full device says (`seen`, in its signed batches) that it
    /// holds them, or while batches wait here for a predecessor. The pull
    /// has just asked every storage for them; a gap that stays for
    /// `WITHHOLD_PULLS` pulls in a row is reported as a storage that may be
    /// withholding batches (`LedgerHealth::warnings`).
    fn watch_freshness(
        &mut self,
        view: &LedgerView,
        dir: &KeyDirectory,
        malformed: u64,
        refused: u64,
    ) {
        let me = self.vault.device_id.clone();
        // device -> (held, seen, source)
        let mut lacking: BTreeMap<DeviceId, (u64, u64, &'static str)> = BTreeMap::new();
        for (reader, acks) in &view.acks {
            if reader == &me {
                continue;
            }
            for (dev, seen) in acks {
                if dev == &me || !dir.contains_key(dev) {
                    continue;
                }
                // Never beyond a removed device's cut-off.
                let seen = match self.devices.revoked.get(dev) {
                    Some(r) => (*seen).min(r.cutoff_seq),
                    None => *seen,
                };
                let held = self.ledger.head(dev).seq;
                if seen > held {
                    let e = lacking.entry(dev.clone()).or_insert((held, 0, "acks"));
                    e.1 = e.1.max(seen);
                }
            }
        }
        // What a peer says it holds (head statements, section 74).
        for (dev, reach) in self.peer_reach(dir) {
            let held = self.ledger.head(&dev).seq;
            if reach > held {
                let e = lacking.entry(dev).or_insert((held, 0, "peer"));
                if reach > e.1 {
                    e.1 = reach;
                    e.2 = "peer";
                }
            }
        }
        for dev in dir.keys().filter(|d| **d != me) {
            if let Some(&waiting) = self.ledger.pending_seqs(dev).last() {
                let held = self.ledger.head(dev).seq;
                let e = lacking.entry(dev.clone()).or_insert((held, 0, "pending"));
                e.1 = e.1.max(waiting);
            }
        }
        let watch = &mut self.ledger_alarm.watch;
        let before = std::mem::take(&mut watch.behind);
        for (dev, (held, seen, source)) in lacking {
            let pulls = before
                .get(&dev)
                .map(|b| if b.held == held { b.pulls + 1 } else { 1 })
                .unwrap_or(1);
            if pulls == ledger_recovery::WITHHOLD_PULLS {
                log::warn!(device:% = dev, held = held, seen = seen; "a storage may be withholding ledger batches");
            }
            let name = view
                .devices
                .get(&dev)
                .cloned()
                .unwrap_or_else(|| dev.short().to_string());
            watch.behind.insert(
                dev.clone(),
                ledger_recovery::LedgerBehind {
                    device: dev.to_string(),
                    name,
                    held,
                    seen,
                    pulls,
                    source: source.into(),
                },
            );
        }
        watch.malformed = malformed;
        watch.refused += refused;
        watch.events_refused = view.events_refused;
        watch.save(&self.home);
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::ledger3::events::{Event as Event3, PackStored};
    use crate::ledger3::LedgerObject as Object3;
    use crate::storage::{CallCounts, StorageCalls};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const PASS: &str = "correct horse battery staple";

    /// A plausible event for synthetic batch `i` of device number `d`: a
    /// claim of a pack of `folder` on the storage "box".
    fn synthetic_events(d: u64, i: u64, folder: &FolderId) -> Vec<Event3> {
        vec![Event3::PackStored(PackStored {
            storage: "box".into(),
            pack: crypto::hash(&[d.to_le_bytes(), i.to_le_bytes()].concat()),
            class: 0,
            folder: crate::record::id16(folder).unwrap_or([0; 16]),
            map_seq: 0,
        })]
    }

    /// Append `n` synthetic batches to this device's ledger without pushing.
    pub(crate) fn append_synthetic(e: &mut Engine, d: u64, n: u64, folder: &FolderId) {
        let me = e.me3();
        for i in 0..n {
            let lamport = e.tick().unwrap();
            let (key_id, key) = e.ledger_key3().unwrap();
            let seen = e.f3.ledger.vault_seen(&me);
            let raw = synthetic_events(d, i, folder)
                .iter()
                .map(Event3::to_raw)
                .collect();
            e.f3.ledger
                .append_own(
                    &me,
                    raw,
                    seen,
                    lamport,
                    &key,
                    &key_id,
                    crate::ledger3::NO_FOLDER,
                    &e.keys.signer,
                )
                .unwrap();
        }
    }

    pub(crate) struct Lab {
        pub root: PathBuf,
        pub storage: StorageSpec,
    }

    pub(crate) fn lab(tag: &str) -> (tempfile::TempDir, Lab) {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join(tag);
        let storage = StorageSpec::LocalDir {
            name: "box".into(),
            path: root.join("storage"),
            cold: false,
            carrier: false,
            place: String::new(),
            min_free: None,
        };
        (tmp, Lab { root, storage })
    }

    pub(crate) fn devices(lab: &Lab, n: usize) -> Vec<Engine> {
        let (mut a, key) = Engine::init(&lab.root.join("dev0"), "dev0", PASS).unwrap();
        a.add_storage(lab.storage.clone()).unwrap();
        let mut out = vec![a];
        for i in 1..n {
            let name = format!("dev{i}");
            out.push(
                Engine::join(
                    &lab.root.join(&name),
                    &name,
                    PASS,
                    &key,
                    lab.storage.clone(),
                )
                .unwrap(),
            );
        }
        // Everyone learns everyone's device record.
        for e in out.iter_mut() {
            e.pull_ledger().unwrap();
        }
        out
    }

    fn measure<T>(e: &mut Engine, f: impl FnOnce(&mut Engine) -> T) -> (T, Duration, CallCounts) {
        let calls = Arc::new(StorageCalls::default());
        e.count_storage_calls(calls.clone());
        let t = Instant::now();
        let out = f(e);
        let took = t.elapsed();
        e.storage_calls = None;
        (out, took, calls.snapshot())
    }

    fn report(what: &str, took: Duration, c: CallCounts) {
        eprintln!(
            "{what:<34} {:>9.1} ms  ledger: lists {:>4} (keys {:>6}) gets {:>6} | all: lists {:>4} (keys {:>6}) gets {:>6} puts {:>6} exists {:>5} deletes {:>5}",
            took.as_secs_f64() * 1000.0,
            c.ledger_lists,
            c.ledger_listed_keys,
            c.ledger_gets,
            c.lists,
            c.listed_keys,
            c.gets,
            c.puts,
            c.exists,
            c.deletes
        );
    }

    /// The view kept between calls equals a full replay.
    fn view_is_replay(e: &Engine) {
        assert_eq!(
            e.view3().unwrap().canonical(),
            e.view3_replayed().unwrap().canonical()
        );
    }

    /// Measures the mailbox and the view on a vault with many batches:
    /// `VARSTO_BENCH_BATCHES` (default 20000) synthetic batches from three
    /// devices on one local directory. Run with
    /// `cargo test --release -p varsto-core ledger_scale_benchmark -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn ledger_scale_benchmark() {
        let total: u64 = std::env::var("VARSTO_BENCH_BATCHES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20_000);
        let (_tmp, lab) = lab("bench");
        let mut devs = devices(&lab, 3);
        let folder = FolderId::random();
        let per = total / 3;
        let t = Instant::now();
        for (d, e) in devs.iter_mut().enumerate() {
            append_synthetic(e, d as u64, per, &folder);
            e.push_own_batches().unwrap();
        }
        eprintln!(
            "setup: {} batches signed and pushed in {:.1} s",
            per * 3,
            t.elapsed().as_secs_f64()
        );
        let c = &mut devs[2];
        let (_, took, calls) = measure(c, |e| e.pull_ledger().unwrap());
        report("pull_ledger, first (ingest all)", took, calls);
        let (_, took, calls) = measure(c, |e| e.pull_ledger().unwrap());
        report("pull_ledger, nothing new", took, calls);
        let (view, took, calls) = measure(c, |e| e.view3().unwrap());
        report("view3()", took, calls);
        eprintln!("view: {} batches, {} packs", view.batches, view.packs.len());
    }

    /// After the first pull, a pull with nothing new lists one short range
    /// per device and storage and downloads no batch; a commit writes one.
    #[test]
    fn mailbox_reads_only_what_is_new() {
        let (_tmp, lab) = lab("incremental");
        let mut devs = devices(&lab, 3);
        let folder = FolderId::random();
        for (d, e) in devs.iter_mut().enumerate() {
            append_synthetic(e, d as u64, 12, &folder);
            e.push_own_batches().unwrap();
        }
        let c = &mut devs[2];
        c.pull_ledger().unwrap();
        let before = c.view3().unwrap().batches;
        let (forks, _, calls) = measure(c, |e| e.pull_ledger().unwrap());
        assert!(forks.is_empty());
        assert_eq!(calls.ledger_gets, 0, "nothing new to download: {calls:?}");
        assert_eq!(calls.ledger_listed_keys, 0, "{calls:?}");
        assert_eq!(c.view3().unwrap().batches, before);

        // A new batch of A is the only one B downloads.
        devs[1].pull_ledger().unwrap();
        devs[0].pending.push(Event::FolderAdded {
            folder: folder.clone(),
        });
        let (_, _, calls) = measure(&mut devs[0], |e| e.commit_batch().unwrap());
        assert_eq!(calls.puts, 1, "{calls:?}");
        assert_eq!(calls.ledger_listed_keys, 0, "{calls:?}");
        let ledger_gets = |e: &mut Engine| {
            let calls = Arc::new(StorageCalls::default());
            e.count_storage_calls(calls.clone());
            let before = e.view3().unwrap().batches;
            e.pull_ledger().unwrap();
            e.storage_calls = None;
            (e.view3().unwrap().batches - before, calls.snapshot())
        };
        let (new, calls) = ledger_gets(&mut devs[1]);
        assert_eq!(new, 1);
        assert_eq!(calls.ledger_gets, 1, "{calls:?}");
    }

    /// A storage that lost this device's batches (or a new storage under a
    /// known name) is filled again from the first batch.
    #[test]
    fn push_refills_a_storage_that_lost_batches() {
        let (_tmp, lab) = lab("refill");
        let mut devs = devices(&lab, 1);
        let folder = FolderId::random();
        let a = &mut devs[0];
        append_synthetic(a, 0, 5, &folder);
        a.push_own_batches().unwrap();
        let head = a.own_head3();
        let dir = lab
            .root
            .join("storage/ledger")
            .join(a.vault.device_id.as_str());
        fs::remove_dir_all(&dir).unwrap();
        a.push_own_batches().unwrap();
        let n = fs::read_dir(&dir).unwrap().count() as u64;
        assert_eq!(n, head);
    }

    /// A copy of this device restored from an old backup sees its newer
    /// batches after its own head and refuses to sign.
    #[test]
    fn restored_copy_is_fenced_by_incremental_listing() {
        let (_tmp, lab) = lab("fence");
        let mut devs = devices(&lab, 2);
        let folder = FolderId::random();
        let home = devs[0].home.clone();
        let backup = lab.root.join("backup");
        copy_tree(&home, &backup);
        append_synthetic(&mut devs[0], 0, 3, &folder);
        devs[0].push_own_batches().unwrap();
        drop(devs);
        fs::remove_dir_all(&home).unwrap();
        copy_tree(&backup, &home);
        let mut restored = Engine::open(&home, PASS).unwrap();
        let forks = restored.pull_ledger().unwrap();
        assert_eq!(forks, vec![restored.vault.device_id.clone()]);
        assert!(restored.forked_self);
        restored.pending.push(Event::FolderAdded { folder });
        assert!(restored.commit_batch().is_err());
    }

    /// The view is saved, picked up again after a restart and brought up
    /// to date with batches that arrived meanwhile; a damaged file is
    /// rebuilt from the batches.
    #[test]
    fn cached_view_survives_restarts() {
        let (_tmp, lab) = lab("cache");
        let mut devs = devices(&lab, 2);
        let folder = FolderId::random();
        append_synthetic(&mut devs[0], 0, 40, &folder);
        devs[0].push_own_batches().unwrap();
        let b = &mut devs[1];
        b.pull_ledger().unwrap();
        let path = b.view3_path();
        assert!(path.exists());
        let home = b.home.clone();
        drop(devs);
        let mut b = Engine::open(&home, PASS).unwrap();
        assert!(b.load_view3().is_some());
        view_is_replay(&b);
        append_synthetic(&mut b, 1, 3, &folder);
        view_is_replay(&b);
        drop(b);
        fs::write(&path, b"garbage").unwrap();
        let b = Engine::open(&home, PASS).unwrap();
        view_is_replay(&b);
        assert!(b.view3().unwrap().packs.len() >= 43);
    }

    fn folder_with_files(e: &mut Engine, root: &Path, name: &str, files: &[(&str, &[u8])]) {
        let dir = root.join(name);
        e.add_folder(name, &dir).unwrap();
        for (f, data) in files {
            fs::write(dir.join(f), data).unwrap();
        }
    }

    fn own_head(e: &Engine) -> u64 {
        e.own_head3()
    }

    /// A sync of several folders seals one batch, not a pull and a push
    /// batch per folder.
    #[test]
    fn sync_seals_one_batch() {
        let (_tmp, lab) = lab("one-batch");
        let mut devs = devices(&lab, 1);
        let a = &mut devs[0];
        a.chunker = ChunkerParams::SMALL;
        folder_with_files(a, &lab.root, "docs", &[("a.txt", b"alpha")]);
        folder_with_files(a, &lab.root, "pics", &[("b.txt", b"beta")]);
        let before = own_head(a);
        let reports = a.sync(None).unwrap();
        assert_eq!(reports.len(), 2);
        assert_eq!(own_head(a), before + 1);
        assert!(reports.iter().all(|(_, p)| p.batch_seq == Some(before + 1)));
        fs::write(lab.root.join("docs/a.txt"), b"alpha 2").unwrap();
        fs::write(lab.root.join("pics/c.txt"), b"gamma").unwrap();
        a.sync(None).unwrap();
        assert_eq!(own_head(a), before + 2);
        // Nothing changed: no batch at all.
        a.sync(None).unwrap();
        assert_eq!(own_head(a), before + 2);
        view_is_replay(a);
    }

    /// Fetching a file makes no batch: the device says it holds the file
    /// with the `held` flag of its next manifest (format 3 has no
    /// per-block "on device" event).
    #[test]
    fn a_fetch_is_announced_by_the_next_manifest() {
        let (_tmp, lab) = lab("deferred");
        let mut devs = devices(&lab, 2);
        devs[0].chunker = ChunkerParams::SMALL;
        folder_with_files(
            &mut devs[0],
            &lab.root,
            "photos",
            &[("one.jpg", &[7u8; 20_000])],
        );
        devs[0].sync(None).unwrap();
        let b_id = devs[1].me3();
        let req = devs[1].f3_folder_request("photos", "editor").unwrap();
        devs[0]
            .f3_approve("photos", "dev1", None, Some(&req.fingerprint))
            .unwrap();
        let b = &mut devs[1];
        b.pull_ledger().unwrap();
        b.attach_folder("photos", &lab.root.join("b-photos"), true)
            .unwrap();
        b.sync(None).unwrap();
        let head = own_head(b);
        b.fetch_file("photos", "one.jpg").unwrap();
        assert_eq!(own_head(b), head, "no batch for a fetch");
        b.sync(None).unwrap();
        assert_eq!(own_head(b), head + 1, "the manifest with `held`");
        let a = &mut devs[0];
        a.sync(None).unwrap();
        let folder = crate::record::id16(&a.keyring.find("photos").unwrap().folder_id).unwrap();
        let held = a.load_manifests3(&folder).held_index();
        let state = a.load_state(&FolderId::from_bytes(&folder)).unwrap();
        let object = &state.files["one.jpg"].chunks[0].object;
        let obj = crate::storages3::object_bin(object).unwrap();
        assert!(held.held_by(&obj, &b_id), "B holds the file now");
        view_is_replay(a);
    }

    /// Events recorded before a failure inside `one_batch` are still sealed.
    #[test]
    fn one_batch_seals_on_failure() {
        let (_tmp, lab) = lab("fail");
        let mut devs = devices(&lab, 1);
        let a = &mut devs[0];
        let head = own_head(a);
        let folder = FolderId::random();
        let r: Result<()> = a.one_batch(|e| {
            e.pending.push(Event::FolderAdded {
                folder: folder.clone(),
            });
            e.commit_batch()?;
            e.pending.push(Event::FolderAdded {
                folder: folder.clone(),
            });
            bail!("interrupted")
        });
        assert!(r.is_err());
        assert_eq!(own_head(a), head + 1);
        assert!(a.pending.is_empty());
    }

    fn stored(lab: &Lab, device: &DeviceId) -> BTreeSet<Object3> {
        fs::read_dir(lab.root.join("storage/ledger").join(device.as_str()))
            .unwrap()
            .filter_map(|e| Object3::parse(&e.unwrap().file_name().to_string_lossy()))
            .collect()
    }

    fn batches3(objects: &BTreeSet<Object3>) -> BTreeSet<u64> {
        objects
            .iter()
            .filter_map(|o| match o {
                Object3::Batch(s) => Some(*s),
                Object3::Checkpoint(..) => None,
            })
            .collect()
    }

    /// A device writes a checkpoint, the others acknowledge it, and only
    /// then its old batches go from the storage and from every device; a
    /// device that joins later starts from the checkpoint and sees the same
    /// view; a copy restored from a backup older than the checkpoint is
    /// still fenced.
    #[test]
    fn checkpoints_prune_after_everyone_has_seen_them() {
        let (_tmp, lab) = lab("prune");
        let mut devs = devices(&lab, 3);
        for e in devs.iter_mut() {
            e.ledger_policy = LedgerPolicy {
                checkpoint_every: 10,
                keep_before: 2,
            };
        }
        let folder = FolderId::random();
        let a_dev = devs[0].vault.device_id.clone();
        let a_id = devs[0].me3();
        let a_home = devs[0].home.clone();
        let backup = lab.root.join("a-backup");
        copy_tree(&a_home, &backup);
        append_synthetic(&mut devs[0], 0, 30, &folder);
        devs[0].push_own_batches().unwrap();
        devs[0].ledger_upkeep().unwrap();
        let head = devs[0].f3.ledger.head(&a_id);
        let n = head.base.as_ref().expect("a checkpoint").seq;
        assert_eq!(n, head.seq);
        // Nobody has acknowledged it: everything stays.
        assert_eq!(stored(&lab, &a_dev).len() as u64, head.seq + 1);

        for e in devs[1..].iter_mut() {
            e.pull_ledger().unwrap();
            e.ledger_upkeep().unwrap();
            assert_eq!(e.f3.ledger.head(&a_id).base.map(|b| b.seq), Some(n));
        }
        devs[0].pull_ledger().unwrap();
        devs[0].ledger_upkeep().unwrap();
        let left = stored(&lab, &a_dev);
        assert!(left.contains(&Object3::Checkpoint(n, 0)));
        assert_eq!(
            batches3(&left),
            (n - 1..=head.seq).collect::<BTreeSet<u64>>(),
            "the batches before the checkpoint went, except the last two"
        );
        assert!(devs[0].f3.ledger.get(&a_id, 1).unwrap().is_none());
        // B drops its copies of A's old batches as well.
        devs[1].pull_ledger().unwrap();
        devs[1].ledger_upkeep().unwrap();
        assert!(devs[1].f3.ledger.get(&a_id, n).unwrap().is_none());
        for e in &devs {
            view_is_replay(e);
        }

        // A device joining now reads the checkpoint, not A's old batches.
        let key = devs[0].export_vault_key().unwrap();
        let mut d = Engine::join(
            &lab.root.join("dev3"),
            "dev3",
            PASS,
            &key,
            lab.storage.clone(),
        )
        .unwrap();
        assert_eq!(d.f3.ledger.head(&a_id).base.map(|b| b.seq), Some(n));
        assert!(d.f3.ledger.get(&a_id, n - 1).unwrap().is_none());
        devs[1].pull_ledger().unwrap();
        d.pull_ledger().unwrap();
        let (vb, vd) = (devs[1].view3().unwrap(), d.view3().unwrap());
        assert_eq!(vb.canonical().packs, vd.canonical().packs);
        view_is_replay(&d);

        // A copy of A restored from before the checkpoint is fenced.
        drop(devs);
        fs::remove_dir_all(&a_home).unwrap();
        copy_tree(&backup, &a_home);
        let mut restored = Engine::open(&a_home, PASS).unwrap();
        let forks = restored.pull_ledger().unwrap();
        assert!(forks.contains(&a_dev));
        restored.pending.push(Event::FolderAdded { folder });
        assert!(restored.commit_batch().is_err());
    }

    pub(crate) fn copy_tree(from: &Path, to: &Path) {
        for e in walkdir::WalkDir::new(from)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let rel = e.path().strip_prefix(from).unwrap();
            let dst = to.join(rel);
            if e.file_type().is_dir() {
                fs::create_dir_all(&dst).unwrap();
            } else {
                fs::copy(e.path(), &dst).unwrap();
            }
        }
    }
}
