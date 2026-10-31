// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The local copy of every device's format-3 batches and checkpoints, with
//! heads. The rules are those of the format-2 store (`crate::ledger`):
//! a device's head is the end of the unbroken chain held here; a batch
//! whose predecessor is missing waits in `<device>/pending/` without moving
//! the head; two different batches under one number mark the device
//! forked; a checkpoint stands in for the batches it covers, which can then
//! be dropped; a batch or checkpoint more than `MAX_AHEAD` beyond the head
//! is refused (a checkpoint is kept beside the batch it ends at). Only the
//! object format differs: every batch is a signed record of kind `batch`
//! whose `body_hash` is the chain hash, and checkpoints come in parts.
//!
//! Local layout under the store directory, per device (hex):
//! `<device>/<seq 16>-0000.rec` (the record as stored),
//! `<device>/checkpoint-<seq 16>-<part 4>.rec`, `<device>/pending/<seq 16>.pend`,
//! and `heads.json`, `pushed.json` as in format 2.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use super::checkpoint::{Checkpoint, LedgerObject, CHECKPOINT_PREFIX};
use super::envelope::{self, kind, Header, LedgerRecord, SignedRecord};
use super::events::{split_events, Batch, RawEvent, MAX_BATCH_PLAIN};
use super::scope::{EventScope, FolderRoles, NoRoles};
use super::view::LedgerView;
use super::{DeviceBin, FolderBin, Hash32, Ingest, MAX_AHEAD, MAX_BATCH_BODY};
use crate::crypto::{self, SecretKey, SigningKey, VerifyingKey};
use crate::ledger::{set_aside, Base, Head, Rescan};
use crate::util;

const PENDING_DIR: &str = "pending";

fn hexd(d: &DeviceBin) -> String {
    hex::encode(d)
}

fn parse_dev(s: &str) -> Option<DeviceBin> {
    let b = hex::decode(s).ok()?;
    b.try_into().ok()
}

fn hash_hex(h: &Hash32) -> String {
    hex::encode(h)
}

fn hash_bin(s: &str) -> Option<Hash32> {
    hex::decode(s).ok()?.try_into().ok()
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct HeadsFile {
    /// By device id (hex).
    heads: BTreeMap<String, Head>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct PushedFile {
    storages: BTreeMap<String, u64>,
    #[serde(default)]
    pruned: BTreeMap<String, u64>,
    /// Per storage, the highest batch number that is a real prefix: every
    /// batch from the first one still kept through this number is on that
    /// storage. The watermark in `storages` can sit past a gap; this does not.
    #[serde(default)]
    prefix: BTreeMap<String, u64>,
}

/// A batch held while its predecessor is missing.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingBatch {
    record: Vec<u8>,
    opened: bool,
    prev: Option<Hash32>,
}

fn read_or_set_aside<T: serde::de::DeserializeOwned + Default>(
    path: &Path,
    damaged: &mut Vec<String>,
) -> Result<T> {
    if !path.exists() {
        return Ok(T::default());
    }
    match util::read_json(path) {
        Ok(v) => Ok(v),
        Err(_) => {
            set_aside(path)?;
            damaged.push(
                path.file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default(),
            );
            Ok(T::default())
        }
    }
}

/// Check a batch record against what a batch of this vault must be, and
/// its signature, through the acceptance rule of every record
/// (`record::Acceptor`, steps 1 to 4) under its canonical storage name;
/// returns the body when `key` opens it.
pub fn check_batch(
    rec: &SignedRecord,
    vault: &[u8; 16],
    pubkey: &VerifyingKey,
    key: Option<&SecretKey>,
) -> Result<Option<Batch>> {
    check_batch_named(&envelope::storage_name(rec), rec, vault, pubkey, key)
}

/// `check_batch` for a record read under `name` (a storage listing): the
/// name must be the one the envelope gives.
pub fn check_batch_named(
    name: &str,
    rec: &SignedRecord,
    vault: &[u8; 16],
    pubkey: &VerifyingKey,
    key: Option<&SecretKey>,
) -> Result<Option<Batch>> {
    if rec.kind != kind::BATCH || &rec.vault != vault || rec.part != 0 || rec.parts != 1 {
        bail!("not a batch record of this vault");
    }
    if rec.body.len() > envelope::padded_body_len(MAX_BATCH_BODY) {
        bail!("batch body of {} bytes is over the limit", rec.body.len());
    }
    let (_, plain) =
        envelope::accept_part(name, &rec.encode(), vault, pubkey, key, MAX_BATCH_PLAIN)
            .with_context(|| format!("batch {}/{}", hexd(&rec.device), rec.seq))?;
    let Some(plain) = plain else {
        return Ok(None);
    };
    let batch = Batch::from_postcard(&plain)?;
    if batch.device != rec.device || batch.seq != rec.seq {
        bail!("batch body does not match its envelope");
    }
    Ok(Some(batch))
}

/// Local copy of every device's batches, plus heads.
pub struct LedgerStore {
    dir: PathBuf,
    vault: [u8; 16],
    heads: HeadsFile,
    pushed: PushedFile,
    heads_absent: bool,
    damaged: Vec<String>,
}

impl LedgerStore {
    pub fn open(dir: &Path, vault: [u8; 16]) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let mut damaged = Vec::new();
        let heads_path = dir.join("heads.json");
        let heads_absent = !heads_path.exists();
        let heads = read_or_set_aside(&heads_path, &mut damaged)?;
        let pushed = read_or_set_aside(&dir.join("pushed.json"), &mut damaged)?;
        Ok(LedgerStore {
            dir: dir.to_path_buf(),
            vault,
            heads,
            pushed,
            heads_absent,
            damaged,
        })
    }

    pub fn vault(&self) -> &[u8; 16] {
        &self.vault
    }

    pub fn heads_absent(&self) -> bool {
        self.heads_absent
    }

    pub fn damaged(&self) -> &[String] {
        &self.damaged
    }

    pub fn pushed_max(&self) -> u64 {
        self.pushed.storages.values().copied().max().unwrap_or(0)
    }

    pub fn pushed(&self, storage: &str) -> u64 {
        self.pushed.storages.get(storage).copied().unwrap_or(0)
    }

    /// Batches `1..=` this number are known to be on `storage`, with no gap.
    /// Absent on older `pushed.json` files (treated as nothing confirmed).
    pub fn pushed_prefix(&self, storage: &str) -> u64 {
        self.pushed.prefix.get(storage).copied().unwrap_or(0)
    }

    pub fn pruned(&self, storage: &str) -> u64 {
        self.pushed.pruned.get(storage).copied().unwrap_or(0)
    }

    pub fn set_pruned(&mut self, storage: &str, seq: u64) -> Result<()> {
        self.pushed.pruned.insert(storage.to_string(), seq);
        util::write_json(&self.dir.join("pushed.json"), &self.pushed)
    }

    pub fn set_pushed(&mut self, storage: &str, seq: u64) -> Result<()> {
        if self.pushed.storages.get(storage) == Some(&seq) {
            return Ok(());
        }
        self.pushed.storages.insert(storage.to_string(), seq);
        util::write_json(&self.dir.join("pushed.json"), &self.pushed)
    }

    /// `storage` holds every kept batch through `seq`. The watermark and the
    /// confirmed prefix both move there, including backward when a gap was
    /// found under an earlier watermark.
    pub fn set_pushed_prefix(&mut self, storage: &str, seq: u64) -> Result<()> {
        if self.pushed.storages.get(storage) == Some(&seq)
            && self.pushed.prefix.get(storage) == Some(&seq)
        {
            return Ok(());
        }
        self.pushed.storages.insert(storage.to_string(), seq);
        self.pushed.prefix.insert(storage.to_string(), seq);
        util::write_json(&self.dir.join("pushed.json"), &self.pushed)
    }

    pub fn clear_fork(&mut self, device: &DeviceBin) -> Result<()> {
        if let Some(h) = self.heads.heads.get_mut(&hexd(device)) {
            if h.forked {
                h.forked = false;
                self.save_heads()?;
            }
        }
        Ok(())
    }

    pub fn save(&mut self) -> Result<()> {
        self.save_heads()?;
        self.heads_absent = false;
        Ok(())
    }

    fn save_heads(&self) -> Result<()> {
        util::write_json(&self.dir.join("heads.json"), &self.heads)
    }

    fn dev_dir(&self, device: &DeviceBin) -> PathBuf {
        self.dir.join(hexd(device))
    }

    fn batch_path(&self, device: &DeviceBin, seq: u64) -> PathBuf {
        self.dev_dir(device).join(format!("{seq:016}-0000.rec"))
    }

    fn pending_path(&self, device: &DeviceBin, seq: u64) -> PathBuf {
        self.dev_dir(device)
            .join(PENDING_DIR)
            .join(format!("{seq:016}.pend"))
    }

    fn checkpoint_path(&self, device: &DeviceBin, seq: u64, part: u16) -> PathBuf {
        self.dev_dir(device)
            .join(format!("{CHECKPOINT_PREFIX}{seq:016}-{part:04}.rec"))
    }

    fn write_record(path: &Path, rec: &SignedRecord) -> Result<()> {
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)?;
        }
        util::write_atomic(path, &rec.encode())
    }

    fn read_record(path: &Path) -> Result<Option<SignedRecord>> {
        match std::fs::read(path) {
            Ok(b) => Ok(Some(SignedRecord::decode(&b)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn head(&self, device: &DeviceBin) -> Head {
        self.heads
            .heads
            .get(&hexd(device))
            .cloned()
            .unwrap_or_default()
    }

    fn set_head(&mut self, device: &DeviceBin, h: Head) {
        self.heads.heads.insert(hexd(device), h);
    }

    pub fn devices(&self) -> Vec<DeviceBin> {
        self.heads
            .heads
            .keys()
            .filter_map(|k| parse_dev(k))
            .collect()
    }

    pub fn is_forked(&self, device: &DeviceBin) -> bool {
        self.head(device).forked
    }

    pub fn get(&self, device: &DeviceBin, seq: u64) -> Result<Option<SignedRecord>> {
        Self::read_record(&self.batch_path(device, seq))
    }

    /// The chain hash of batch `seq` of `device` as held here (the batch's
    /// body hash, or the newest checkpoint's head when it ends there).
    pub fn hash_at(&self, device: &DeviceBin, seq: u64) -> Result<Option<Hash32>> {
        if seq == 0 {
            return Ok(None);
        }
        if let Some(b) = self.get(device, seq)? {
            return Ok(Some(b.body_hash));
        }
        Ok(self
            .head(device)
            .base
            .filter(|b| b.seq == seq)
            .and_then(|b| hash_bin(&b.head_hash)))
    }

    /// Move this device's own newest batch aside (never published; another
    /// batch holds its number on the storages).
    pub fn discard_own(&mut self, device: &DeviceBin, seq: u64) -> Result<()> {
        let mut h = self.head(device);
        if seq != h.seq || seq == 0 {
            bail!("only the newest batch can be set aside");
        }
        let from = self.batch_path(device, seq);
        let to = self.dir.join("discarded").join(format!(
            "{}-{seq:016}-{}.rec",
            hexd(device),
            util::now_utc()
        ));
        std::fs::create_dir_all(to.parent().expect("has a parent"))?;
        if from.exists() {
            std::fs::rename(&from, &to)?;
        }
        h.seq = seq - 1;
        h.hash = self.hash_at(device, h.seq)?.map(|x| hash_hex(&x));
        self.set_head(device, h);
        self.save_heads()
    }

    /// Rebuild the heads from the files held here (a lost or damaged heads
    /// file), as the format-2 store does.
    pub fn rescan(&mut self) -> Result<Rescan> {
        let mut out = Rescan::default();
        let mut heads = BTreeMap::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let Some(device) = parse_dev(&entry.file_name().to_string_lossy()) else {
                continue;
            };
            let mut batches: BTreeMap<u64, Hash32> = BTreeMap::new();
            let mut checkpoints: BTreeMap<u64, (String, Option<Hash32>)> = BTreeMap::new();
            for f in std::fs::read_dir(entry.path())? {
                let f = f?;
                let name = f.file_name().to_string_lossy().to_string();
                let Some(obj) = LedgerObject::parse(&name) else {
                    continue;
                };
                let rec = std::fs::read(f.path())
                    .ok()
                    .and_then(|b| SignedRecord::decode(&b).ok());
                match (obj, rec) {
                    (LedgerObject::Batch(seq), Some(r))
                        if r.kind == kind::BATCH && r.device == device && r.seq == seq =>
                    {
                        batches.insert(seq, r.body_hash);
                    }
                    (LedgerObject::Checkpoint(seq, part), Some(r))
                        if r.kind == kind::CHECKPOINT && r.device == device && r.seq == seq =>
                    {
                        if part == 0 {
                            checkpoints.insert(seq, (r.key_id.clone(), None));
                        }
                    }
                    _ => {
                        set_aside(&f.path())?;
                        out.damaged.push(format!("{}/{name}", hexd(&device)));
                    }
                }
            }
            // The head hash of a checkpoint is in its body; the batch it
            // ends at, when held, gives it too. Without either, the
            // checkpoint is not used as a base here (it is fetched again).
            for (seq, v) in checkpoints.iter_mut() {
                v.1 = batches.get(seq).copied().or_else(|| {
                    self.head(&device)
                        .base
                        .filter(|b| b.seq == *seq)
                        .and_then(|b| hash_bin(&b.head_hash))
                });
            }
            if batches.is_empty() && checkpoints.is_empty() {
                continue;
            }
            out.devices += 1;
            out.batches += batches.len() as u64;
            out.checkpoints += checkpoints.len() as u64;
            let base = checkpoints.iter().rev().find_map(|(seq, (key_id, h))| {
                h.map(|h| Base {
                    seq: *seq,
                    key_id: key_id.clone(),
                    head_hash: hash_hex(&h),
                })
            });
            let start = base.as_ref().map(|b| b.seq).unwrap_or(0);
            let mut seq = start;
            let mut hash = base.as_ref().map(|b| b.head_hash.clone());
            while let Some(h) = batches.get(&(seq + 1)) {
                seq += 1;
                hash = Some(hash_hex(h));
            }
            let first = batches.keys().next().copied().unwrap_or(0);
            let dropped = if first > 1 { (first - 1).min(start) } else { 0 };
            let forked = self.head(&device).forked;
            heads.insert(
                hexd(&device),
                Head {
                    seq,
                    hash,
                    forked,
                    base,
                    dropped,
                },
            );
        }
        self.heads.heads = heads;
        self.save()?;
        for d in self.devices() {
            self.promote_pending(&d)?;
        }
        self.damaged.extend(out.damaged.iter().cloned());
        Ok(out)
    }

    /// Seal one batch of this device's own events.
    #[allow(clippy::too_many_arguments)]
    pub fn append_own(
        &mut self,
        device: &DeviceBin,
        events: Vec<RawEvent>,
        seen: Vec<(DeviceBin, u64)>,
        lamport: u64,
        key: &SecretKey,
        key_id: &str,
        scope: FolderBin,
        signer: &SigningKey,
    ) -> Result<SignedRecord> {
        let head = self.head(device);
        if head.forked {
            bail!(
                "this device's ledger is forked (restored from an old copy?); refusing to append"
            );
        }
        let prev = match &head.hash {
            Some(h) => {
                hash_bin(h).ok_or_else(|| anyhow!("head hash of {} is damaged", hexd(device)))?
            }
            None => [0; 32],
        };
        let batch = Batch {
            device: *device,
            seq: head.seq + 1,
            prev,
            lamport,
            created_utc: util::now_utc(),
            seen,
            events,
        };
        let h = Header {
            kind: kind::BATCH,
            vault: self.vault,
            scope,
            device: *device,
            seq: batch.seq,
            part: 0,
            parts: 1,
            key_id: key_id.to_string(),
        };
        let packed = zstd::bulk::compress(&batch.to_postcard()?, 3)?;
        if packed.len() > MAX_BATCH_BODY {
            bail!(
                "batch body of {} compressed bytes is over the limit",
                packed.len()
            );
        }
        let rec = SignedRecord::seal_raw(&h, key, &packed, signer)?;
        Self::write_record(&self.batch_path(device, rec.seq), &rec)?;
        self.set_head(
            device,
            Head {
                seq: rec.seq,
                hash: Some(hash_hex(&rec.body_hash)),
                forked: false,
                ..head
            },
        );
        self.save_heads()?;
        Ok(rec)
    }

    /// Seal the events of one action: one batch, or more when they exceed
    /// `MAX_EVENTS` or `MAX_BATCH_BODY` (each further batch takes the next
    /// Lamport time from `tick`; `seen` goes in every one).
    #[allow(clippy::too_many_arguments)]
    pub fn append_action(
        &mut self,
        device: &DeviceBin,
        events: Vec<RawEvent>,
        seen: Vec<(DeviceBin, u64)>,
        mut tick: impl FnMut() -> u64,
        key: &SecretKey,
        key_id: &str,
        scope: FolderBin,
        signer: &SigningKey,
    ) -> Result<Vec<SignedRecord>> {
        split_events(events)
            .into_iter()
            .map(|evs| {
                self.append_own(
                    device,
                    evs,
                    seen.clone(),
                    tick(),
                    key,
                    key_id,
                    scope,
                    signer,
                )
            })
            .collect()
    }

    /// Store a batch received from a mailbox after checking its signature.
    pub fn ingest(
        &mut self,
        rec: SignedRecord,
        pubkey: &VerifyingKey,
        key: Option<&SecretKey>,
    ) -> Result<Ingest> {
        self.ingest_inner(None, rec, pubkey, key, u64::MAX, false)
    }

    /// `ingest` for a batch read under `name` from a storage or a peer:
    /// the name must be the one its envelope gives.
    pub fn ingest_named(
        &mut self,
        name: &str,
        rec: SignedRecord,
        pubkey: &VerifyingKey,
        key: Option<&SecretKey>,
        lamport_limit: u64,
    ) -> Result<Ingest> {
        self.ingest_inner(Some(name), rec, pubkey, key, lamport_limit, false)
    }

    /// Like `ingest`; a batch with a Lamport time above `lamport_limit` is
    /// refused and not kept.
    pub fn ingest_limited(
        &mut self,
        rec: SignedRecord,
        pubkey: &VerifyingKey,
        key: Option<&SecretKey>,
        lamport_limit: u64,
    ) -> Result<Ingest> {
        self.ingest_inner(None, rec, pubkey, key, lamport_limit, false)
    }

    /// A device taking its own batches back after it lost its local
    /// ledger: its head moves past a gap no storage can fill.
    pub fn ingest_own_restored(
        &mut self,
        rec: SignedRecord,
        pubkey: &VerifyingKey,
        key: Option<&SecretKey>,
    ) -> Result<Ingest> {
        self.ingest_inner(None, rec, pubkey, key, u64::MAX, true)
    }

    fn ingest_inner(
        &mut self,
        name: Option<&str>,
        rec: SignedRecord,
        pubkey: &VerifyingKey,
        key: Option<&SecretKey>,
        lamport_limit: u64,
        over_gap: bool,
    ) -> Result<Ingest> {
        let batch = match name {
            Some(n) => check_batch_named(n, &rec, &self.vault, pubkey, key)?,
            None => check_batch(&rec, &self.vault, pubkey, key)?,
        };
        if batch.as_ref().is_some_and(|b| b.lamport > lamport_limit) {
            return Ok(Ingest::Refused);
        }
        let dev = rec.device;
        let base = self.head(&dev).base;
        let hash = hash_hex(&rec.body_hash);
        if let Some(base) = base.as_ref().filter(|b| rec.seq <= b.seq) {
            if self.get(&dev, rec.seq)?.is_none() {
                if rec.seq == base.seq && hash != base.head_hash {
                    return self.mark_fork(&dev);
                }
                return Ok(Ingest::Known);
            }
        }
        if let Some(existing) = self.get(&dev, rec.seq)? {
            if existing.body_hash == rec.body_hash {
                let mut h = self.head(&dev);
                if rec.seq > h.seq {
                    h.seq = rec.seq;
                    h.hash = Some(hash);
                    self.set_head(&dev, h);
                    self.save_heads()?;
                }
                return Ok(Ingest::Known);
            }
            return self.mark_fork(&dev);
        }
        if let Some(waiting) = self.pending(&dev, rec.seq)? {
            if SignedRecord::decode(&waiting.record).is_ok_and(|w| w.body_hash == rec.body_hash) {
                return Ok(Ingest::Known);
            }
            return self.mark_fork(&dev);
        }
        let head_seq = self.head(&dev).seq;
        let floor = head_seq.max(base.as_ref().map(|b| b.seq).unwrap_or(0));
        if rec.seq > floor.saturating_add(MAX_AHEAD) {
            return Ok(Ingest::Refused);
        }
        if let (true, Some(batch)) = (rec.seq > 1, &batch) {
            if let Some(prev) = self.hash_at(&dev, rec.seq - 1)? {
                if batch.prev != prev {
                    return self.mark_fork(&dev);
                }
            }
        }
        if rec.seq > head_seq + 1 && !over_gap {
            let waiting = PendingBatch {
                record: rec.encode(),
                opened: batch.is_some(),
                prev: batch.map(|b| b.prev),
            };
            let p = self.pending_path(&dev, rec.seq);
            std::fs::create_dir_all(p.parent().expect("has a parent"))?;
            util::write_atomic(&p, &postcard::to_allocvec(&waiting)?)?;
            return Ok(Ingest::Pending);
        }
        Self::write_record(&self.batch_path(&dev, rec.seq), &rec)?;
        let mut h = self.head(&dev);
        if rec.seq > h.seq {
            h.seq = rec.seq;
            h.hash = Some(hash);
        }
        self.set_head(&dev, h);
        self.save_heads()?;
        self.promote_pending(&dev)?;
        Ok(Ingest::New)
    }

    fn pending(&self, device: &DeviceBin, seq: u64) -> Result<Option<PendingBatch>> {
        let p = self.pending_path(device, seq);
        let Ok(bytes) = std::fs::read(&p) else {
            return Ok(None);
        };
        match postcard::from_bytes(&bytes) {
            Ok(w) => Ok(Some(w)),
            Err(_) => {
                let _ = std::fs::remove_file(&p);
                Ok(None)
            }
        }
    }

    pub fn has_pending(&self, device: &DeviceBin, seq: u64) -> bool {
        self.pending_path(device, seq).exists()
    }

    pub fn pending_seqs(&self, device: &DeviceBin) -> Vec<u64> {
        let Ok(rd) = std::fs::read_dir(self.dev_dir(device).join(PENDING_DIR)) else {
            return Vec::new();
        };
        let mut out: Vec<u64> = rd
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                e.file_name()
                    .to_string_lossy()
                    .strip_suffix(".pend")
                    .and_then(|n| n.parse().ok())
            })
            .collect();
        out.sort_unstable();
        out
    }

    fn promote_pending(&mut self, device: &DeviceBin) -> Result<()> {
        for seq in self.pending_seqs(device) {
            let mut h = self.head(device);
            if seq <= h.seq {
                let covered = self.pending(device, seq)?;
                let _ = std::fs::remove_file(self.pending_path(device, seq));
                if let Some(w) = covered.and_then(|w| SignedRecord::decode(&w.record).ok()) {
                    let agrees = match self.get(device, seq)? {
                        Some(b) => b.body_hash == w.body_hash,
                        None => h
                            .base
                            .as_ref()
                            .filter(|b| b.seq == seq)
                            .is_none_or(|b| b.head_hash == hash_hex(&w.body_hash)),
                    };
                    if !agrees {
                        self.mark_fork(device)?;
                    }
                }
                continue;
            }
            if seq != h.seq + 1 {
                break;
            }
            let Some(w) = self.pending(device, seq)? else {
                break;
            };
            let head_hash = h.hash.as_deref().and_then(hash_bin);
            if w.opened && w.prev != head_hash.or(Some([0; 32])) {
                self.mark_fork(device)?;
                break;
            }
            let rec = SignedRecord::decode(&w.record)?;
            Self::write_record(&self.batch_path(device, seq), &rec)?;
            let _ = std::fs::remove_file(self.pending_path(device, seq));
            h.seq = seq;
            h.hash = Some(hash_hex(&rec.body_hash));
            self.set_head(device, h);
            self.save_heads()?;
        }
        Ok(())
    }

    fn mark_fork(&mut self, device: &DeviceBin) -> Result<Ingest> {
        let mut h = self.head(device);
        h.forked = true;
        self.set_head(device, h);
        self.save_heads()?;
        Ok(Ingest::Fork)
    }

    // ---- checkpoints -----------------------------------------------------

    /// The parts of the newest checkpoint of `device` held here.
    pub fn checkpoint(&self, device: &DeviceBin) -> Result<Option<Vec<SignedRecord>>> {
        let Some(base) = self.head(device).base else {
            return Ok(None);
        };
        let mut parts = Vec::new();
        let mut part = 0u16;
        loop {
            match Self::read_record(&self.checkpoint_path(device, base.seq, part))? {
                Some(r) => {
                    let n = r.parts;
                    parts.push(r);
                    part += 1;
                    if part >= n {
                        break;
                    }
                }
                None if part == 0 => return Ok(None),
                None => bail!(
                    "checkpoint {} of {} misses part {part}",
                    base.seq,
                    hexd(device)
                ),
            }
        }
        Ok(Some(parts))
    }

    /// Keep a checkpoint as the newest of its device. The caller verified
    /// every part's signature and opened it (`cp`). A checkpoint far ahead
    /// is kept only beside the batch it ends at (`anchor`, signature
    /// checked by the caller, body hash equal to the checkpoint's head).
    pub fn ingest_checkpoint(
        &mut self,
        parts: &[SignedRecord],
        cp: &Checkpoint,
        anchor: Option<&SignedRecord>,
    ) -> Result<Ingest> {
        let Some(first) = parts.first() else {
            bail!("a checkpoint without parts");
        };
        if first.kind != kind::CHECKPOINT || first.vault != self.vault {
            bail!("not a checkpoint of this vault");
        }
        let device = cp.device;
        let mut h = self.head(&device);
        let floor = h.seq.max(h.base.as_ref().map(|b| b.seq).unwrap_or(0));
        let anchored = anchor.is_some_and(|b| {
            b.kind == kind::BATCH
                && b.device == device
                && b.seq == cp.seq
                && b.body_hash == cp.head_hash
        });
        if cp.seq > floor.saturating_add(MAX_AHEAD) && !anchored {
            return Ok(Ingest::Refused);
        }
        let head_hash = hash_hex(&cp.head_hash);
        if let Some(base) = &h.base {
            if base.seq == cp.seq {
                if base.head_hash == head_hash {
                    return Ok(Ingest::Known);
                }
                return self.mark_fork(&device);
            }
            if base.seq > cp.seq {
                return Ok(Ingest::Known);
            }
        }
        if let Some(b) = self.get(&device, cp.seq)? {
            if b.body_hash != cp.head_hash {
                return self.mark_fork(&device);
            }
        }
        for p in parts {
            Self::write_record(&self.checkpoint_path(&device, cp.seq, p.part), p)?;
        }
        if let Some(old) = &h.base {
            self.remove_checkpoint(&device, old.seq);
        }
        h.base = Some(Base {
            seq: cp.seq,
            key_id: first.key_id.clone(),
            head_hash: head_hash.clone(),
        });
        if cp.seq > h.seq {
            h.seq = cp.seq;
            h.hash = Some(head_hash);
        }
        self.set_head(&device, h);
        self.save_heads()?;
        self.promote_pending(&device)?;
        Ok(Ingest::New)
    }

    fn remove_checkpoint(&self, device: &DeviceBin, seq: u64) {
        for part in 0..super::envelope::MAX_PARTS {
            if std::fs::remove_file(self.checkpoint_path(device, seq, part)).is_err() {
                break;
            }
        }
    }

    /// What `device`'s batches up to `seq` add to the view (its checkpoint
    /// when not newer, then the batches after it). Fails when one of them
    /// is missing or does not open: a checkpoint must not leave anything
    /// out.
    pub fn contribution(
        &self,
        device: &DeviceBin,
        seq: u64,
        key_for: impl Fn(&str) -> Option<SecretKey>,
    ) -> Result<LedgerView> {
        let mut view = LedgerView::default();
        let head = self.head(device);
        let base = head.base.as_ref().map(|b| b.seq).filter(|b| *b <= seq);
        if let Some(b) = base {
            let parts = self
                .checkpoint(device)?
                .ok_or_else(|| anyhow!("checkpoint {b} of {} is missing", hexd(device)))?;
            let key = key_for(&parts[0].key_id)
                .ok_or_else(|| anyhow!("no key for checkpoint {b} of {}", hexd(device)))?;
            view.merge(&Checkpoint::open(&parts, &key)?.view.restricted_to(device));
        }
        for s in base.unwrap_or(0) + 1..=seq {
            let rec = self
                .get(device, s)?
                .ok_or_else(|| anyhow!("batch {s} of {} is missing", hexd(device)))?;
            let key = key_for(&rec.key_id)
                .ok_or_else(|| anyhow!("no key for batch {s} of {}", hexd(device)))?;
            let batch = Batch::from_postcard(&rec.open(&key, MAX_BATCH_PLAIN)?)?;
            view.apply(&batch);
        }
        Ok(view)
    }

    /// Seal `view` (the `contribution` up to `seq`) as this device's newest
    /// checkpoint.
    pub fn seal_checkpoint(
        &mut self,
        device: &DeviceBin,
        seq: u64,
        view: LedgerView,
        key: &SecretKey,
        key_id: &str,
        signer: &SigningKey,
    ) -> Result<Vec<SignedRecord>> {
        let head_hash = self
            .get(device, seq)?
            .ok_or_else(|| anyhow!("batch {seq} of {} is missing", hexd(device)))?
            .body_hash;
        let cp = Checkpoint {
            device: *device,
            seq,
            head_hash,
            created_utc: util::now_utc(),
            view,
        };
        let parts = cp.seal(&self.vault, key, key_id, signer)?;
        if self.ingest_checkpoint(&parts, &cp, None)? == Ingest::Fork {
            bail!(
                "checkpoint {seq} of {} contradicts this device's ledger",
                hexd(device)
            );
        }
        Ok(parts)
    }

    pub fn make_checkpoint(
        &mut self,
        device: &DeviceBin,
        seq: u64,
        key_for: impl Fn(&str) -> Option<SecretKey>,
        key: &SecretKey,
        key_id: &str,
        signer: &SigningKey,
    ) -> Result<Vec<SignedRecord>> {
        let view = self.contribution(device, seq, key_for)?;
        self.seal_checkpoint(device, seq, view, key, key_id, signer)
    }

    /// Delete the local batches of `device` up to `seq`; never beyond its
    /// newest checkpoint.
    pub fn drop_through(&mut self, device: &DeviceBin, seq: u64) -> Result<u64> {
        let mut h = self.head(device);
        let upto = seq.min(h.base.as_ref().map(|b| b.seq).unwrap_or(0));
        if upto <= h.dropped {
            return Ok(0);
        }
        let mut n = 0;
        for s in self.held_batches(device)?.range(h.dropped + 1..=upto) {
            match std::fs::remove_file(self.batch_path(device, *s)) {
                Ok(()) => n += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        h.dropped = upto;
        self.set_head(device, h);
        self.save_heads()?;
        Ok(n)
    }

    fn held_batches(&self, device: &DeviceBin) -> Result<BTreeSet<u64>> {
        let mut out = BTreeSet::new();
        let rd = match std::fs::read_dir(self.dev_dir(device)) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for f in rd {
            if let Some(LedgerObject::Batch(s)) =
                LedgerObject::parse(&f?.file_name().to_string_lossy())
            {
                out.insert(s);
            }
        }
        Ok(out)
    }

    /// Every locally held batch in (device, seq) order.
    pub fn all(&self) -> Result<Vec<SignedRecord>> {
        let mut out = Vec::new();
        for device in self.devices() {
            let head = self.head(&device);
            for seq in self
                .held_batches(&device)?
                .range(head.dropped + 1..=head.seq)
            {
                if let Some(b) = self.get(&device, *seq)? {
                    out.push(b);
                }
            }
        }
        Ok(out)
    }

    fn usable_base(
        head: &Head,
        device: &DeviceBin,
        key_for: &impl Fn(&str) -> Option<SecretKey>,
        keep: &impl Fn(&DeviceBin, u64) -> bool,
        scope: &impl Fn(&DeviceBin, &str) -> Option<EventScope>,
    ) -> u64 {
        match &head.base {
            Some(b)
                if keep(device, b.seq)
                    && key_for(&b.key_id).is_some()
                    && scope(device, &b.key_id) == Some(EventScope::Full) =>
            {
                b.seq
            }
            _ => 0,
        }
    }

    fn apply_checkpoint(
        &self,
        view: &mut LedgerView,
        device: &DeviceBin,
        key_for: &impl Fn(&str) -> Option<SecretKey>,
    ) -> Result<()> {
        let Some(parts) = self.checkpoint(device)? else {
            return Ok(());
        };
        if let Some(cp) = key_for(&parts[0].key_id).and_then(|k| Checkpoint::open(&parts, &k).ok())
        {
            if &cp.device == device {
                // A checkpoint speaks for its signer only.
                view.merge(&cp.view.restricted_to(device));
            }
        }
        Ok(())
    }

    /// Replay every batch (from each device's usable checkpoint) under the
    /// keys `key_for` gives, the batches `keep` accepts and the scope
    /// `scope(signer, key_id)` gives (`None`: the batch does not count).
    pub fn view_scoped(
        &self,
        key_for: impl Fn(&str) -> Option<SecretKey>,
        keep: impl Fn(&DeviceBin, u64) -> bool,
        scope: impl Fn(&DeviceBin, &str) -> Option<EventScope>,
    ) -> Result<LedgerView> {
        self.view_with_roles(key_for, keep, scope, &NoRoles)
    }

    /// `view_scoped` with the folder roles of full devices
    /// (`scope::FolderRoles`).
    pub fn view_with_roles(
        &self,
        key_for: impl Fn(&str) -> Option<SecretKey>,
        keep: impl Fn(&DeviceBin, u64) -> bool,
        scope: impl Fn(&DeviceBin, &str) -> Option<EventScope>,
        roles: &dyn FolderRoles,
    ) -> Result<LedgerView> {
        let mut view = LedgerView::default();
        for device in self.devices() {
            let head = self.head(&device);
            let base = Self::usable_base(&head, &device, &key_for, &keep, &scope);
            if base > 0 {
                self.apply_checkpoint(&mut view, &device, &key_for)?;
            }
            for seq in (base.max(head.dropped) + 1)..=head.seq {
                if let Some(rec) = self.get(&device, seq)? {
                    apply_record(&mut view, &rec, &key_for, &keep, &scope, roles);
                }
            }
        }
        Ok(self.finish(&view))
    }

    /// Bring a cached raw view up to date with the local batches; the
    /// result equals a full replay under the same keys, cut-offs and
    /// scopes (`cached_view_equals_full_replay`).
    pub fn update_view_scoped(
        &self,
        cache: &mut ViewCache,
        key_for: impl Fn(&str) -> Option<SecretKey>,
        keep: impl Fn(&DeviceBin, u64) -> bool,
        scope: impl Fn(&DeviceBin, &str) -> Option<EventScope>,
    ) -> Result<u64> {
        self.update_view_with_roles(cache, key_for, keep, scope, &NoRoles)
    }

    /// `update_view_scoped` with the folder roles of full devices. The
    /// caller puts what the roles depend on into the cache's `context`, so
    /// a change of roles replays from the start.
    pub fn update_view_with_roles(
        &self,
        cache: &mut ViewCache,
        key_for: impl Fn(&str) -> Option<SecretKey>,
        keep: impl Fn(&DeviceBin, u64) -> bool,
        scope: impl Fn(&DeviceBin, &str) -> Option<EventScope>,
        roles: &dyn FolderRoles,
    ) -> Result<u64> {
        let mut applied = 0;
        let devices = self.devices();
        let bases: BTreeMap<DeviceBin, u64> = devices
            .iter()
            .map(|d| {
                (
                    *d,
                    Self::usable_base(&self.head(d), d, &key_for, &keep, &scope),
                )
            })
            .filter(|(_, b)| *b > 0)
            .collect();
        if bases != cache.bases {
            *cache = ViewCache {
                bases,
                ..ViewCache::new(std::mem::take(&mut cache.context))
            };
            for (device, seq) in cache.bases.clone() {
                self.apply_checkpoint(&mut cache.raw, &device, &key_for)?;
                cache.applied.insert(device, seq);
                applied += 1;
            }
        }
        for device in devices {
            let head = self.head(&device);
            if let Some(gaps) = cache.gaps.get_mut(&device) {
                let filled: Vec<u64> = gaps
                    .iter()
                    .copied()
                    .filter(|seq| self.batch_path(&device, *seq).exists())
                    .collect();
                for seq in filled {
                    if let Some(rec) = self.get(&device, seq)? {
                        apply_record(&mut cache.raw, &rec, &key_for, &keep, &scope, roles);
                        applied += 1;
                    }
                    gaps.remove(&seq);
                }
                if gaps.is_empty() {
                    cache.gaps.remove(&device);
                }
            }
            let from = cache
                .applied
                .get(&device)
                .copied()
                .unwrap_or(0)
                .max(head.dropped);
            for seq in from + 1..=head.seq {
                match self.get(&device, seq)? {
                    Some(rec) => {
                        apply_record(&mut cache.raw, &rec, &key_for, &keep, &scope, roles);
                        applied += 1;
                    }
                    None => {
                        cache.gaps.entry(device).or_default().insert(seq);
                    }
                }
            }
            if head.seq > from {
                cache.applied.insert(device, head.seq);
            }
        }
        Ok(applied)
    }

    pub fn cache_fits(&self, cache: &ViewCache) -> bool {
        cache
            .applied
            .iter()
            .all(|(device, seq)| *seq <= self.head(device).seq)
    }

    /// The view as callers see it: members' events decided, forked devices
    /// marked. `raw` is left as it was.
    pub fn finish(&self, raw: &LedgerView) -> LedgerView {
        let forked: Vec<DeviceBin> = self
            .devices()
            .into_iter()
            .filter(|d| self.head(d).forked)
            .collect();
        raw.finish(forked)
    }

    /// The `seen` of this device's next vault batch: the newest batch of
    /// every other device held here.
    pub fn vault_seen(&self, me: &DeviceBin) -> Vec<(DeviceBin, u64)> {
        self.devices()
            .into_iter()
            .filter(|d| d != me)
            .map(|d| (d, self.head(&d).seq))
            .filter(|(_, seq)| *seq > 0)
            .collect()
    }

    /// The `seen` of a member's next folder-scoped batch: only the
    /// folder's devices (`folder_devices`, from the folder record).
    pub fn folder_seen(
        &self,
        me: &DeviceBin,
        folder_devices: &BTreeSet<DeviceBin>,
    ) -> Vec<(DeviceBin, u64)> {
        self.vault_seen(me)
            .into_iter()
            .filter(|(d, _)| folder_devices.contains(d))
            .collect()
    }
}

/// Apply one stored batch to a view if `keep` accepts it, its key is
/// known, its signer has a scope and the envelope's scope field matches it.
fn apply_record(
    view: &mut LedgerView,
    rec: &SignedRecord,
    key_for: &impl Fn(&str) -> Option<SecretKey>,
    keep: &impl Fn(&DeviceBin, u64) -> bool,
    scope: &impl Fn(&DeviceBin, &str) -> Option<EventScope>,
    roles: &dyn FolderRoles,
) {
    if !keep(&rec.device, rec.seq) {
        return;
    }
    let Some(key) = key_for(&rec.key_id) else {
        return;
    };
    let Some(scope) = scope(&rec.device, &rec.key_id) else {
        return;
    };
    if rec.scope != scope.record_scope() {
        return;
    }
    let Ok(batch) = rec
        .open(&key, MAX_BATCH_PLAIN)
        .and_then(|p| Batch::from_postcard(&p))
    else {
        return;
    };
    if batch.device == rec.device && batch.seq == rec.seq {
        view.apply_scoped_with(&batch, &scope, roles);
    }
}

/// A raw view kept between runs (`ledger/view.rec`), with what was applied
/// and under which keys, cut-offs and scopes (`context`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewCache {
    pub format: u32,
    pub context: String,
    pub applied: BTreeMap<DeviceBin, u64>,
    pub gaps: BTreeMap<DeviceBin, BTreeSet<u64>>,
    pub bases: BTreeMap<DeviceBin, u64>,
    pub raw: LedgerView,
}

impl ViewCache {
    /// View format 1 of format 3.
    pub const FORMAT: u32 = 1;

    pub fn new(context: String) -> Self {
        ViewCache {
            format: Self::FORMAT,
            context,
            ..Default::default()
        }
    }

    /// postcard, zstd, then AEAD under a local key.
    pub fn seal(&self, key: &SecretKey, aad: &[u8]) -> Result<Vec<u8>> {
        let packed = zstd::bulk::compress(&postcard::to_allocvec(self)?, 3)?;
        crypto::encrypt(key, aad, &packed)
    }

    pub fn open(blob: &[u8], key: &SecretKey, aad: &[u8]) -> Result<Self> {
        let packed = crypto::decrypt(key, aad, blob)?;
        let plain = zstd::bulk::decompress(&packed, 1 << 31)?;
        Ok(postcard::from_bytes(&plain)?)
    }
}
