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

pub(super) fn load_deferred(home: &Path) -> Vec<Event> {
    util::read_json_or_default(&home.join(DEFERRED_FILE)).unwrap_or_default()
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
    /// does not verify or open is skipped (the batches still count).
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
        match self.key_for_id(&cp.key_id) {
            Some(key) if cp.open(&key).is_ok() => self.ledger.ingest_checkpoint(cp),
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
        if self.vault.member || self.forked_self || self.removal.is_some() {
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
        *unsaved += self.ledger.update_view(
            c,
            |id| self.key_for_id(id),
            |d, seq| self.batch_accepted(d, seq),
        )?;
        if *unsaved >= VIEW_SAVE_EVERY && self.save_view_cache(c).is_ok() {
            *unsaved = 0;
        }
        if self.pending.is_empty() {
            return Ok(self.ledger.finish(&c.raw));
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
        Ok(self.ledger.finish_owned(raw))
    }

    /// The view replayed from every local batch, without the cache (and
    /// without events not sealed into a batch yet).
    pub fn view_replayed(&self) -> Result<LedgerView> {
        self.ledger.view_filtered(
            |id| self.key_for_id(id),
            |d, seq| self.batch_accepted(d, seq),
        )
    }

    /// Fingerprint of what decides which batches count: every key id this
    /// device can open (with a hash of the key) and every revocation cut-off.
    fn view_context(&self) -> String {
        let mut ids = vec![KEY_LEDGER.to_string(), KEY_REPLICA.to_string()];
        ids.extend(
            self.epochs
                .keys
                .keys()
                .filter(|e| **e > 0)
                .map(|e| format!("{}{e}", ledger::KEY_LEDGER_EPOCH_PREFIX)),
        );
        ids.extend(self.keyring.folders.keys().map(vault::share_key_id));
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
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        hex::encode(crypto::hash(&crypto::aad("ledger-view-context", &refs)))
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

    /// Push every own batch (and the newest own checkpoint) that a storage
    /// does not have yet; detect forks.
    pub(super) fn push_own_batches(&mut self) -> Result<()> {
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
            if let Some(&newest) = present.last() {
                if newest > head.seq {
                    bail!("ledger fork: storage {} holds batch {} of this device, newer than its own last batch {} (restored from an old copy?)", backend.name(), newest, head.seq);
                }
            }
            if let Some(&newest) = checkpoints_of(&objects).last() {
                if newest > head.seq {
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
                            let remote: SignedBatch = serde_json::from_slice(&remote)?;
                            if remote.hash != batch.hash {
                                bail!("ledger fork: storage {} already holds a different batch {} of this device (restored from an old copy?)", backend.name(), seq);
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
                    bail!(
                        "ledger fork: batch {} of this device appeared on {} concurrently",
                        seq,
                        backend.name()
                    );
                }
            }
            self.ledger.set_pushed(spec.name(), head.seq)?;
        }
        Ok(())
    }

    /// Pull everyone's new batches from every hot storage: for each device
    /// with a known key, only the batches after the local head, and its
    /// newest checkpoint when that is newer than the one held here.
    pub(super) fn pull_ledger(&mut self) -> Result<Vec<DeviceId>> {
        self.pull_registry()?;
        self.sync_membership()?;
        let dir = self.key_directory()?;
        let me = self.vault.device_id.clone();
        let mut devices: Vec<DeviceId> = dir.keys().cloned().collect();
        devices.sort();
        let mut forks = BTreeSet::new();
        for (_, backend) in self.metadata_storages(false)? {
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
                let pk = &dir[dev];
                if dev == &me {
                    if checkpoints_of(&objects)
                        .last()
                        .is_some_and(|n| *n > self.ledger.head(&me).seq)
                    {
                        forks.insert(me.clone());
                        self.mark_forked(&me)?;
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
                    if self.ledger.get(dev, seq)?.is_some() && !head.forked {
                        continue;
                    }
                    let Some(blob) = backend.get(&SignedBatch::storage_key(dev, seq))? else {
                        continue;
                    };
                    let signed: SignedBatch = serde_json::from_slice(&blob)?;
                    if &signed.device != dev || signed.seq != seq {
                        continue;
                    }
                    // A batch under a key this device lacks is kept unread.
                    let key = self.key_for_id(&signed.key_id);
                    if dev == &me && seq > self.ledger.head(&me).seq {
                        // Another copy of this device identity published ahead of us.
                        forks.insert(me.clone());
                        let _ = self.ledger.ingest_with(signed, pk, key.as_ref());
                        self.mark_forked(&me)?;
                        continue;
                    }
                    match self.ledger.ingest_with(signed, pk, key.as_ref())? {
                        Ingest::Fork => {
                            forks.insert(dev.clone());
                        }
                        Ingest::New | Ingest::Known => {}
                    }
                }
            }
        }
        let view = self.view()?;
        self.observe_clock(view.max_lamport)?;
        Ok(forks.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{CallCounts, StorageCalls};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const PASS: &str = "correct horse battery staple";

    /// A few plausible events for synthetic batch `i` of device number `d`.
    fn synthetic_events(d: u64, i: u64, folder: &FolderId) -> Vec<Event> {
        let chunk =
            ChunkId::from_bytes(&crypto::hash(&[d.to_le_bytes(), i.to_le_bytes()].concat()));
        let object = ObjectName::from_bytes(&crypto::hash(chunk.as_str().as_bytes()));
        let mut evs = vec![
            Event::ChunkStored {
                folder: folder.clone(),
                chunk: chunk.clone(),
                object: object.clone(),
                storage: "box".into(),
                size: 4096 + i,
            },
            Event::ChunkOnDevice {
                folder: folder.clone(),
                chunk: chunk.clone(),
                object: object.clone(),
                size: 4096 + i,
            },
        ];
        if i % 3 == 0 && i > 0 {
            // Verify a chunk another device wrote earlier.
            let other = ChunkId::from_bytes(&crypto::hash(
                &[((d + 1) % 3).to_le_bytes(), (i - 1).to_le_bytes()].concat(),
            ));
            evs.push(Event::ChunkVerified {
                folder: folder.clone(),
                object: ObjectName::from_bytes(&crypto::hash(other.as_str().as_bytes())),
                chunk: other,
                storage: "box".into(),
            });
        }
        evs
    }

    /// Append `n` synthetic batches to this device's ledger without pushing.
    pub(crate) fn append_synthetic(e: &mut Engine, d: u64, n: u64, folder: &FolderId) {
        for i in 0..n {
            let lamport = e.tick().unwrap();
            let (key_id, key) = e.ledger_key_now();
            e.ledger
                .append_own_with(
                    &e.vault.device_id.clone(),
                    synthetic_events(d, i, folder),
                    lamport,
                    &key,
                    &key_id,
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
        let (view, took, calls) = measure(c, |e| e.view().unwrap());
        report("view()", took, calls);
        eprintln!(
            "view: {} batches, {} chunks",
            view.batches,
            view.chunks.len()
        );
        let (_, took, calls) = measure(c, |e| e.view().unwrap());
        report("view(), again", took, calls);
        let (_, took, calls) = measure(c, |e| {
            e.pending.push(Event::FolderAdded {
                folder: folder.clone(),
            });
            e.commit_batch().unwrap()
        });
        report("commit_batch (one event, push)", took, calls);
        let (_, took, calls) = measure(c, |e| {
            e.pending.push(Event::FolderAdded {
                folder: folder.clone(),
            });
            e.commit_batch().unwrap()
        });
        report("commit_batch, again", took, calls);
        let home = c.home.clone();
        let cache_bytes = fs::metadata(c.view_cache_path())
            .map(|m| m.len())
            .unwrap_or(0);
        drop(devs);
        let mut c = Engine::open(&home, PASS).unwrap();
        let (_, took, calls) = measure(&mut c, |e| e.view().unwrap());
        report("view() after a restart", took, calls);
        eprintln!("ledger/view.enc: {:.1} MB", cache_bytes as f64 / 1e6);
        let usage = || {
            let files: Vec<u64> = walkdir::WalkDir::new(lab.root.join("storage/ledger"))
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .map(|e| e.metadata().map(|m| m.len()).unwrap_or(0))
                .collect();
            eprintln!(
                "storage ledger/: {} objects, {:.1} MB",
                files.len(),
                files.iter().sum::<u64>() as f64 / 1e6
            );
        };
        usage();

        // Checkpoints with the default policy, acknowledgements, pruning.
        drop(c);
        let homes: Vec<PathBuf> = (0..3).map(|i| lab.root.join(format!("dev{i}"))).collect();
        let mut devs: Vec<Engine> = homes
            .iter()
            .map(|h| Engine::open(h, PASS).unwrap())
            .collect();
        for e in devs.iter_mut() {
            // A and B have not read the others' batches yet.
            e.pull_ledger().unwrap();
        }
        let t = Instant::now();
        for _ in 0..3 {
            for e in devs.iter_mut() {
                e.pull_ledger().unwrap();
                e.ledger_upkeep().unwrap();
            }
        }
        eprintln!(
            "checkpoints, acknowledgements and pruning: {:.1} s",
            t.elapsed().as_secs_f64()
        );
        for e in &devs {
            let me = e.vault.device_id.clone();
            let cp = e.ledger.checkpoint(&me).unwrap().expect("a checkpoint");
            eprintln!(
                "checkpoint of {}: through {}, {:.2} MB",
                e.vault.device_name,
                cp.seq,
                cp.body_hex.len() as f64 / 2e6
            );
        }
        usage();
        let c = &mut devs[2];
        let (_, took, calls) = measure(c, |e| e.pull_ledger().unwrap());
        report("pull_ledger, nothing new", took, calls);
        let (_, took, calls) = measure(c, |e| e.view().unwrap());
        report("view()", took, calls);
        let t = Instant::now();
        let key = devs[0].export_vault_key().unwrap();
        let mut e = Engine::join(
            &lab.root.join("late"),
            "late",
            PASS,
            &key,
            lab.storage.clone(),
        )
        .unwrap();
        eprintln!(
            "join of a new device (first pull included): {:.1} s",
            t.elapsed().as_secs_f64()
        );
        let (view, took, calls) = measure(&mut e, |e| e.view().unwrap());
        report("view() on the new device", took, calls);
        eprintln!(
            "view: {} batches, {} chunks",
            view.batches,
            view.chunks.len()
        );
    }

    /// After the first pull, a pull with nothing new lists one short range
    /// per device and storage and downloads nothing; a commit lists only
    /// the newest own batches.
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
        let (_, _, calls) = measure(c, |e| {
            let mut out = Vec::new();
            for (_, b) in e.metadata_storages(false).unwrap() {
                for dev in e.key_directory().unwrap().keys() {
                    out.push(remote_objects(b.as_ref(), dev, e.ledger.head(dev).seq).unwrap());
                }
            }
            out
        });
        assert_eq!(calls.listed_keys, 0, "nothing new after the heads");
        let before = c.view().unwrap().batches;
        let (forks, _, calls) = measure(c, |e| e.pull_ledger().unwrap());
        assert!(forks.is_empty());
        assert_eq!(calls.ledger_gets, 0, "nothing new to download: {calls:?}");
        assert_eq!(calls.ledger_listed_keys, 0, "{calls:?}");
        assert_eq!(c.view().unwrap().batches, before);

        // A new batch of A is the only one B downloads.
        devs[1].pull_ledger().unwrap();
        devs[0].pending.push(Event::FolderAdded {
            folder: folder.clone(),
        });
        let (_, _, calls) = measure(&mut devs[0], |e| e.commit_batch().unwrap());
        assert_eq!(calls.puts, 1, "{calls:?}");
        assert!(calls.ledger_listed_keys <= 1, "{calls:?}");
        let ledger_gets = |e: &mut Engine| {
            let calls = Arc::new(StorageCalls::default());
            e.count_storage_calls(calls.clone());
            let before = e.view().unwrap().batches;
            e.pull_ledger().unwrap();
            e.storage_calls = None;
            (e.view().unwrap().batches - before, calls.snapshot())
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
        let head = a.ledger.head(&a.vault.device_id).seq;
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
    /// batches after its own head and refuses to push.
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
        let _ = folder;
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
        let path = b.view_cache_path();
        assert!(path.exists());
        let home = b.home.clone();
        drop(devs);
        let mut b = Engine::open(&home, PASS).unwrap();
        assert!(b.load_view_cache().is_some());
        assert_eq!(b.view().unwrap(), b.view_replayed().unwrap());
        append_synthetic(&mut b, 1, 3, &folder);
        assert_eq!(b.view().unwrap(), b.view_replayed().unwrap());
        drop(b);
        fs::write(&path, b"garbage").unwrap();
        let b = Engine::open(&home, PASS).unwrap();
        let v = b.view().unwrap();
        assert_eq!(v, b.view_replayed().unwrap());
        assert!(v.chunks.len() >= 43);
    }

    fn folder_with_files(e: &mut Engine, root: &Path, name: &str, files: &[(&str, &[u8])]) {
        let dir = root.join(name);
        e.add_folder(name, &dir).unwrap();
        for (f, data) in files {
            fs::write(dir.join(f), data).unwrap();
        }
    }

    fn own_head(e: &Engine) -> u64 {
        e.ledger.head(&e.vault.device_id).seq
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
        assert_eq!(a.view().unwrap(), a.view_replayed().unwrap());
    }

    /// Fetching a file records its blocks with the next batch: kept on disk
    /// across a restart, counted in this device's view meanwhile.
    #[test]
    fn fetch_is_sealed_with_the_next_batch() {
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
        let b = &mut devs[1];
        b.pull_ledger().unwrap();
        b.attach_folder("photos", &lab.root.join("b-photos"), true)
            .unwrap();
        b.sync(None).unwrap();
        let me = b.vault.device_id.clone();
        let on_b = |e: &Engine| {
            e.view()
                .unwrap()
                .chunks
                .values()
                .filter(|c| c.devices.contains(&me))
                .count()
        };
        assert_eq!(on_b(b), 0);
        let head = own_head(b);
        b.fetch_file("photos", "one.jpg").unwrap();
        assert_eq!(own_head(b), head, "no batch for a fetch");
        assert!(on_b(b) > 0, "the fetch counts in this device's view");
        assert!(b.home.join(DEFERRED_FILE).exists());
        let home = b.home.clone();
        drop(devs);
        let mut b = Engine::open(&home, PASS).unwrap();
        assert!(on_b(&b) > 0, "kept across a restart");
        b.sync(None).unwrap();
        assert_eq!(own_head(&b), head + 1);
        assert!(!b.home.join(DEFERRED_FILE).exists());
        assert!(b.pending.is_empty());
        assert_eq!(b.view().unwrap(), b.view_replayed().unwrap());
        assert!(on_b(&b) > 0);
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

    fn stored(lab: &Lab, device: &DeviceId) -> BTreeSet<LedgerObject> {
        fs::read_dir(lab.root.join("storage/ledger").join(device.as_str()))
            .unwrap()
            .filter_map(|e| LedgerObject::parse(&e.unwrap().file_name().to_string_lossy()))
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
        let a_id = devs[0].vault.device_id.clone();
        let a_home = devs[0].home.clone();
        let backup = lab.root.join("a-backup");
        copy_tree(&a_home, &backup);
        append_synthetic(&mut devs[0], 0, 30, &folder);
        devs[0].push_own_batches().unwrap();
        devs[0].ledger_upkeep().unwrap();
        let head = devs[0].ledger.head(&a_id);
        let n = head.base.as_ref().expect("a checkpoint").seq;
        assert_eq!(n, head.seq);
        // Nobody has acknowledged it: everything stays.
        assert_eq!(stored(&lab, &a_id).len() as u64, head.seq + 1);

        for e in devs[1..].iter_mut() {
            e.pull_ledger().unwrap();
            e.ledger_upkeep().unwrap();
            assert_eq!(e.ledger.head(&a_id).base.map(|b| b.seq), Some(n));
        }
        devs[0].pull_ledger().unwrap();
        devs[0].ledger_upkeep().unwrap();
        let left = stored(&lab, &a_id);
        assert!(left.contains(&LedgerObject::Checkpoint(n)));
        assert_eq!(
            batches_of(&left),
            (n - 1..=head.seq).collect::<BTreeSet<u64>>(),
            "the batches before the checkpoint went, except the last two"
        );
        assert!(devs[0].ledger.get(&a_id, 1).unwrap().is_none());
        // B drops its copies of A's old batches as well.
        devs[1].pull_ledger().unwrap();
        devs[1].ledger_upkeep().unwrap();
        assert!(devs[1].ledger.get(&a_id, n).unwrap().is_none());
        for e in &devs {
            assert_eq!(e.view().unwrap(), e.view_replayed().unwrap());
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
        assert_eq!(d.ledger.head(&a_id).base.map(|b| b.seq), Some(n));
        assert!(d.ledger.get(&a_id, n - 1).unwrap().is_none());
        devs[1].pull_ledger().unwrap();
        d.pull_ledger().unwrap();
        let (vb, vd) = (devs[1].view().unwrap(), d.view().unwrap());
        assert_eq!(vb.chunks, vd.chunks);
        assert_eq!(vb.devices, vd.devices);
        assert_eq!(vb.batches, vd.batches);
        assert_eq!(vd, d.view_replayed().unwrap());

        // A copy of A restored from before the checkpoint is fenced.
        drop(devs);
        fs::remove_dir_all(&a_home).unwrap();
        copy_tree(&backup, &a_home);
        let mut restored = Engine::open(&a_home, PASS).unwrap();
        let forks = restored.pull_ledger().unwrap();
        assert!(forks.contains(&a_id));
        restored.pending.push(Event::FolderAdded { folder });
        assert!(restored.commit_batch().is_err());
    }

    fn copy_tree(from: &Path, to: &Path) {
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
