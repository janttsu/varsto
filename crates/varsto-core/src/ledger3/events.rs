// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Ledger events and the batch body of format 3
//! (`docs/spec/format-3-design.md` section 4).
//!
//! Each event travels as `RawEvent { code, payload }` with the postcard
//! encoding of its fields as payload, so a reader skips codes it does not
//! know (counted as `unknown`) and the rest of the batch still counts.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::{DeviceBin, FolderBin, Hash32, PackId, MAX_BATCH_BODY, MAX_EVENTS};

/// Event codes (section 4's table).
pub mod code {
    pub const DEVICE_ENROLLED: u16 = 1;
    pub const FOLDER_ADDED: u16 = 2;
    pub const PACK_STORED: u16 = 3;
    pub const PACK_VERIFIED: u16 = 4;
    pub const PACK_DROPPED: u16 = 5;
    pub const RECORD_PUBLISHED: u16 = 6;
    pub const STORAGE_RETIRED: u16 = 7;
    pub const SNAPSHOT_TAKEN: u16 = 8;
    pub const SNAPSHOT_EXPIRED: u16 = 9;
    pub const BACKUP_STOPPED: u16 = 10;
}

/// Longest device name and storage name an event may carry.
pub const MAX_NAME: usize = 128;
pub const MAX_STORAGE_NAME: usize = 64;
/// Size classes of packs (section 2): 0 = 256 KiB, 1 = 1 MiB, 2 = 4,
/// 3 = 16, 4 = 64, 5 = 256 MiB (cold storages only; the ledger does not
/// know which storages are cold, the pack reader checks that).
pub const MAX_CLASS: u8 = 5;

/// Bytes of a pack of size class `class`.
pub fn class_bytes(class: u8) -> Option<u64> {
    (class <= MAX_CLASS).then(|| 1u64 << (18 + 2 * class as u32))
}

/// One event as it travels in a batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEvent {
    pub code: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEnrolled {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderAdded {
    pub folder: FolderBin,
}

/// This device wrote (or copied whole) `pack` to `storage`: a claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackStored {
    pub storage: String,
    pub pack: PackId,
    pub class: u8,
    /// Zeros from a replica (and from a device that copies a pack whole
    /// without knowing its folder).
    pub folder: FolderBin,
    /// The writer's block-map record that lists the pack's members; 0 from
    /// a replica.
    pub map_seq: u64,
}

/// This device read the whole pack back from `storage` and its BLAKE3 was
/// the pack id; or it deliberately removed the pack from `storage`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackOn {
    pub storage: String,
    pub pack: PackId,
}

/// A record of an announced kind (manifest, block map, trash, snapshot)
/// this device published: what a reader checks the record against.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Announcement {
    pub kind: u8,
    pub scope: FolderBin,
    pub seq: u64,
    /// The seq of the base this record builds on; `== seq` for a base.
    pub base: u64,
    pub parts: u16,
    pub body_hash: Hash32,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageRetired {
    pub storage: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotTaken {
    pub backup: FolderBin,
    pub seq: u64,
    pub taken_utc: i64,
    pub expires_utc: i64,
    pub files: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotExpired {
    pub backup: FolderBin,
    pub device: DeviceBin,
    pub seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupStopped {
    pub backup: FolderBin,
}

/// A decoded event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    DeviceEnrolled(DeviceEnrolled),
    FolderAdded(FolderAdded),
    PackStored(PackStored),
    PackVerified(PackOn),
    PackDropped(PackOn),
    RecordPublished(Announcement),
    StorageRetired(StorageRetired),
    SnapshotTaken(SnapshotTaken),
    SnapshotExpired(SnapshotExpired),
    BackupStopped(BackupStopped),
}

/// What a reader makes of one `RawEvent`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decoded {
    Event(Event),
    /// A code this version does not know (a newer writer): skipped.
    Unknown,
    /// A known code whose payload does not parse or breaks a limit: the
    /// event is refused (it counts as refused, the batch still counts).
    Malformed,
}

fn enc<T: Serialize>(code: u16, v: &T) -> RawEvent {
    RawEvent {
        code,
        payload: postcard::to_allocvec(v).expect("postcard encodes plain structs"),
    }
}

impl Event {
    pub fn code(&self) -> u16 {
        match self {
            Event::DeviceEnrolled(_) => code::DEVICE_ENROLLED,
            Event::FolderAdded(_) => code::FOLDER_ADDED,
            Event::PackStored(_) => code::PACK_STORED,
            Event::PackVerified(_) => code::PACK_VERIFIED,
            Event::PackDropped(_) => code::PACK_DROPPED,
            Event::RecordPublished(_) => code::RECORD_PUBLISHED,
            Event::StorageRetired(_) => code::STORAGE_RETIRED,
            Event::SnapshotTaken(_) => code::SNAPSHOT_TAKEN,
            Event::SnapshotExpired(_) => code::SNAPSHOT_EXPIRED,
            Event::BackupStopped(_) => code::BACKUP_STOPPED,
        }
    }

    pub fn to_raw(&self) -> RawEvent {
        let c = self.code();
        match self {
            Event::DeviceEnrolled(e) => enc(c, e),
            Event::FolderAdded(e) => enc(c, e),
            Event::PackStored(e) => enc(c, e),
            Event::PackVerified(e) | Event::PackDropped(e) => enc(c, e),
            Event::RecordPublished(e) => enc(c, e),
            Event::StorageRetired(e) => enc(c, e),
            Event::SnapshotTaken(e) => enc(c, e),
            Event::SnapshotExpired(e) => enc(c, e),
            Event::BackupStopped(e) => enc(c, e),
        }
    }

    /// The limits of section 4 (names, storage names, size classes, parts).
    pub fn valid(&self) -> bool {
        let storage_ok = |s: &str| !s.is_empty() && s.len() <= MAX_STORAGE_NAME;
        match self {
            Event::DeviceEnrolled(e) => e.name.len() <= MAX_NAME,
            Event::FolderAdded(_) | Event::BackupStopped(_) | Event::SnapshotExpired(_) => true,
            Event::PackStored(e) => storage_ok(&e.storage) && e.class <= MAX_CLASS,
            Event::PackVerified(e) | Event::PackDropped(e) => storage_ok(&e.storage),
            Event::RecordPublished(a) => {
                super::envelope::kind::announced(a.kind)
                    && a.seq >= 1
                    && a.base >= 1
                    && a.base <= a.seq
                    && a.parts >= 1
                    && a.parts <= super::envelope::MAX_PARTS
            }
            Event::StorageRetired(e) => storage_ok(&e.storage),
            Event::SnapshotTaken(_) => true,
        }
    }
}

impl RawEvent {
    pub fn decode(&self) -> Decoded {
        fn dec<'a, T: Deserialize<'a>>(p: &'a [u8], f: impl FnOnce(T) -> Event) -> Decoded {
            match postcard::from_bytes::<T>(p) {
                Ok(v) => {
                    let ev = f(v);
                    if ev.valid() {
                        Decoded::Event(ev)
                    } else {
                        Decoded::Malformed
                    }
                }
                Err(_) => Decoded::Malformed,
            }
        }
        let p = self.payload.as_slice();
        match self.code {
            code::DEVICE_ENROLLED => dec(p, Event::DeviceEnrolled),
            code::FOLDER_ADDED => dec(p, Event::FolderAdded),
            code::PACK_STORED => dec(p, Event::PackStored),
            code::PACK_VERIFIED => dec(p, Event::PackVerified),
            code::PACK_DROPPED => dec(p, Event::PackDropped),
            code::RECORD_PUBLISHED => dec(p, Event::RecordPublished),
            code::STORAGE_RETIRED => dec(p, Event::StorageRetired),
            code::SNAPSHOT_TAKEN => dec(p, Event::SnapshotTaken),
            code::SNAPSHOT_EXPIRED => dec(p, Event::SnapshotExpired),
            code::BACKUP_STOPPED => dec(p, Event::BackupStopped),
            _ => Decoded::Unknown,
        }
    }
}

impl From<&Event> for RawEvent {
    fn from(e: &Event) -> Self {
        e.to_raw()
    }
}

/// Plaintext batch body: postcard, then zstd, then sealed in a record of
/// kind `batch` (`super::envelope`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    pub device: DeviceBin,
    pub seq: u64,
    /// Body hash of batch `seq - 1` of this device; zeros for seq 1.
    pub prev: Hash32,
    pub lamport: u64,
    pub created_utc: i64,
    /// The newest batch of other devices this device held when it sealed
    /// this one (full devices: every device; members: their folder's).
    pub seen: Vec<(DeviceBin, u64)>,
    pub events: Vec<RawEvent>,
}

/// Largest plaintext of a batch body a reader decompresses.
pub const MAX_BATCH_PLAIN: usize = 64 << 20;

/// Postcard bytes of events a writer puts in one batch at most: zstd never
/// grows incompressible data by more than a fraction of a percent, so the
/// compressed body stays under `MAX_BATCH_BODY`.
pub const SPLIT_PLAIN_BYTES: usize = MAX_BATCH_BODY - (1 << 20);

impl Batch {
    /// The postcard encoding (the envelope compresses it).
    pub fn to_postcard(&self) -> Result<Vec<u8>> {
        if self.events.len() > MAX_EVENTS {
            bail!(
                "a batch of {} events is over {MAX_EVENTS}",
                self.events.len()
            );
        }
        Ok(postcard::to_allocvec(self)?)
    }

    pub fn from_postcard(bytes: &[u8]) -> Result<Self> {
        let b: Batch = postcard::from_bytes(bytes).context("batch body")?;
        if b.events.len() > MAX_EVENTS {
            bail!("a batch of {} events is over {MAX_EVENTS}", b.events.len());
        }
        Ok(b)
    }

    /// Decoded events with their positions; unknown and malformed ones are
    /// left out and counted.
    pub fn decoded(&self) -> (Vec<(u32, Event)>, u64, u64) {
        let mut out = Vec::with_capacity(self.events.len());
        let (mut unknown, mut malformed) = (0, 0);
        for (i, raw) in self.events.iter().enumerate() {
            match raw.decode() {
                Decoded::Event(e) => out.push((i as u32, e)),
                Decoded::Unknown => unknown += 1,
                Decoded::Malformed => malformed += 1,
            }
        }
        (out, unknown, malformed)
    }
}

/// Cut the events of one action into the batches it needs: at most
/// `MAX_EVENTS` events and `SPLIT_PLAIN_BYTES` of payload each ("one batch
/// per action" bends only here). Never returns an empty list: no events
/// give one empty batch (an acknowledgement).
pub fn split_events(events: Vec<RawEvent>) -> Vec<Vec<RawEvent>> {
    let mut out: Vec<Vec<RawEvent>> = vec![Vec::new()];
    let mut bytes = 0usize;
    for ev in events {
        // Code, length prefix and payload.
        let size = ev.payload.len() + 8;
        let cur = out.last().expect("not empty");
        if !cur.is_empty() && (cur.len() >= MAX_EVENTS || bytes + size > SPLIT_PLAIN_BYTES) {
            out.push(Vec::new());
            bytes = 0;
        }
        bytes += size;
        out.last_mut().expect("not empty").push(ev);
    }
    out
}
