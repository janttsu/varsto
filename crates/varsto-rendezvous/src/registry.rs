// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The in-memory registry: tags → slots → (owner key, blob, last write,
//! expiry). No database: a restart loses everything, and clients write
//! their slots again within minutes (spec 83.4).

use crate::proto::{
    Blob, DeleteSlot, ErrorCode, Hex, Kind, LookupAnswer, PutAnswer, PutSlot, Slot, SlotEntry, Tag,
};
use base64::Engine as _;
use std::collections::HashMap;
use std::sync::Arc;

/// One slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotData {
    pub owner: [u8; 32],
    /// Shared with in-flight lookup answers so a reader does not take
    /// a second copy of the bytes.
    pub blob: Arc<[u8]>,
    /// The `ts` of the last accepted write (writes must rise).
    pub ts: u64,
    pub expires: u64,
}

/// One tag: its kind (fixed by the first slot) and its slots.
#[derive(Clone, Debug)]
pub struct TagData {
    pub kind: Kind,
    pub slots: HashMap<Slot, SlotData>,
}

/// Every tag the server holds.
#[derive(Debug)]
pub struct Registry {
    tags: HashMap<Tag, TagData>,
    slots_total: usize,
    max_slots_total: usize,
    bytes_total: usize,
    max_bytes_total: usize,
}

/// Counts for `/health`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub tags: usize,
    pub slots: usize,
    pub pair_offers: usize,
    pub bytes: usize,
}

impl Registry {
    /// `max_slots_total` and `max_bytes_total` bound the memory the
    /// registry may use; past them a new slot is refused `unavailable`.
    pub fn new(max_slots_total: usize, max_bytes_total: usize) -> Registry {
        Registry {
            tags: HashMap::new(),
            slots_total: 0,
            max_slots_total,
            bytes_total: 0,
            max_bytes_total,
        }
    }

    fn live<'a>(&'a self, tag: &Tag, now: u64) -> Option<&'a TagData> {
        self.tags
            .get(tag)
            .filter(|t| t.slots.values().any(|s| s.expires > now))
    }

    /// Write a slot: the put is checked first (`PutSlot::verify`), then
    /// put-if-absent for a new slot (when the tag has room and is of the
    /// same kind); an existing live slot takes the write only from its owner
    /// key and only with a newer `ts`. An expired slot counts as absent.
    pub fn put(&mut self, p: &PutSlot, now: u64) -> Result<PutAnswer, ErrorCode> {
        p.verify(now)?;
        let expires = now + p.ttl as u64;
        let tag = p.tag.0;
        let slot = p.slot.0;
        self.drop_expired_in(&tag, now);
        let blob: Arc<[u8]> = Arc::from(p.blob.0.clone());
        let blob_len = blob.len();
        let (kind_ok, len, existing) = match self.tags.get(&tag) {
            Some(t) => (t.kind == p.kind, t.slots.len(), t.slots.get(&slot).cloned()),
            None => (true, 0, None),
        };
        if !kind_ok {
            return Err(ErrorCode::TagFull);
        }
        if let Some(old) = existing {
            if old.owner != p.owner.0 {
                return Err(ErrorCode::NotOwner);
            }
            if p.ts <= old.ts {
                return Err(ErrorCode::Stale);
            }
            if self.bytes_total - old.blob.len() + blob_len > self.max_bytes_total {
                return Err(ErrorCode::Unavailable);
            }
            self.bytes_total = self.bytes_total - old.blob.len() + blob_len;
            let t = self.tags.get_mut(&tag).expect("tag present");
            t.slots.insert(
                slot,
                SlotData {
                    owner: p.owner.0,
                    blob: Arc::clone(&blob),
                    ts: p.ts,
                    expires,
                },
            );
            return Ok(PutAnswer {
                expires,
                created: false,
            });
        }
        if !kind_ok || len >= p.kind.slots_max() {
            return Err(ErrorCode::TagFull);
        }
        if self.slots_total >= self.max_slots_total
            || self.bytes_total + blob_len > self.max_bytes_total
        {
            return Err(ErrorCode::Unavailable);
        }
        let t = self.tags.entry(tag).or_insert_with(|| TagData {
            kind: p.kind,
            slots: HashMap::new(),
        });
        t.slots.insert(
            slot,
            SlotData {
                owner: p.owner.0,
                blob: Arc::clone(&blob),
                ts: p.ts,
                expires,
            },
        );
        self.slots_total += 1;
        self.bytes_total += blob_len;
        Ok(PutAnswer {
            expires,
            created: true,
        })
    }

    /// Remove a slot: signed by its owner, inside the replay window, and
    /// newer than the last write.
    pub fn delete(&mut self, d: &DeleteSlot, now: u64) -> Result<(), ErrorCode> {
        d.verify(now)?;
        self.drop_expired_in(&d.tag.0, now);
        let Some(t) = self.tags.get_mut(&d.tag.0) else {
            return Err(ErrorCode::NotFound);
        };
        let Some(s) = t.slots.get(&d.slot.0) else {
            return Err(ErrorCode::NotFound);
        };
        if s.owner != d.owner.0 {
            return Err(ErrorCode::NotOwner);
        }
        if d.ts < s.ts {
            return Err(ErrorCode::Stale);
        }
        let s = t.slots.remove(&d.slot.0).expect("slot present");
        self.slots_total -= 1;
        self.bytes_total -= s.blob.len();
        if t.slots.is_empty() {
            self.tags.remove(&d.tag.0);
        }
        Ok(())
    }

    /// Every live slot of a tag; nothing (not an error) for an unknown tag.
    /// The blobs are the registry's own bytes (`Arc` clones), not copies.
    pub fn lookup_snap(&self, tag: &Tag, now: u64) -> LookupSnap {
        let Some(t) = self.live(tag, now) else {
            return LookupSnap {
                kind: None,
                slots: Vec::new(),
            };
        };
        let mut slots: Vec<LookupSlot> = t
            .slots
            .iter()
            .filter(|(_, s)| s.expires > now)
            .map(|(id, s)| LookupSlot {
                slot: *id,
                ts: s.ts,
                expires: s.expires,
                blob: Arc::clone(&s.blob),
            })
            .collect();
        slots.sort_by_key(|e| e.slot);
        LookupSnap {
            kind: Some(t.kind),
            slots,
        }
    }

    /// Every live slot of a tag; nothing (not an error) for an unknown tag.
    pub fn lookup(&self, tag: &Tag, now: u64) -> LookupAnswer {
        let snap = self.lookup_snap(tag, now);
        LookupAnswer {
            kind: snap.kind,
            slots: snap
                .slots
                .into_iter()
                .map(|s| SlotEntry {
                    slot: Hex(s.slot),
                    ts: s.ts,
                    expires: s.expires,
                    blob: Blob(s.blob.as_ref().to_vec()),
                })
                .collect(),
        }
    }

    /// The owner key of a live slot.
    pub fn owner(&self, tag: &Tag, slot: &Slot, now: u64) -> Option<[u8; 32]> {
        self.tags
            .get(tag)?
            .slots
            .get(slot)
            .filter(|s| s.expires > now)
            .map(|s| s.owner)
    }

    /// The kind of a tag with a live slot.
    pub fn kind(&self, tag: &Tag, now: u64) -> Option<Kind> {
        self.live(tag, now).map(|t| t.kind)
    }

    fn drop_expired_in(&mut self, tag: &Tag, now: u64) {
        let Some(t) = self.tags.get_mut(tag) else {
            return;
        };
        let before = t.slots.len();
        let mut freed = 0;
        t.slots.retain(|_, s| {
            let keep = s.expires > now;
            if !keep {
                freed += s.blob.len();
            }
            keep
        });
        self.slots_total -= before - t.slots.len();
        self.bytes_total -= freed;
        if t.slots.is_empty() {
            self.tags.remove(tag);
        }
    }

    /// Drop every expired slot (and empty tags); returns how many went.
    pub fn expire(&mut self, now: u64) -> usize {
        let before = self.slots_total;
        let tags: Vec<Tag> = self.tags.keys().copied().collect();
        for t in tags {
            self.drop_expired_in(&t, now);
        }
        before - self.slots_total
    }

    pub fn counts(&self) -> Counts {
        Counts {
            tags: self.tags.len(),
            slots: self.slots_total,
            pair_offers: self.tags.values().filter(|t| t.kind == Kind::Pair).count(),
            bytes: self.bytes_total,
        }
    }
}

/// One live slot as a lookup will send it. `blob` is the registry's copy.
#[derive(Clone, Debug)]
pub struct LookupSlot {
    pub slot: Slot,
    pub ts: u64,
    pub expires: u64,
    pub blob: Arc<[u8]>,
}

/// A lookup answer without the JSON built yet.
#[derive(Clone, Debug)]
pub struct LookupSnap {
    pub kind: Option<Kind>,
    pub slots: Vec<LookupSlot>,
}

/// Largest piece of lookup JSON held while it is written out. A full tag
/// is about 11 MiB on the wire; one request must not allocate that.
pub const LOOKUP_JSON_CHUNK: usize = 16 * 1024;

/// Same alphabet [`crate::proto::Blob`] serializes with.
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Writes the JSON `serde_json` would produce for [`LookupAnswer`], one
/// bounded chunk at a time. The blob bytes are base64-encoded straight
/// into the chunk; they are not copied into one string first.
pub struct LookupEncoder {
    slots: Vec<LookupSlot>,
    index: usize,
    phase: Phase,
    fixed: String,
    fixed_at: usize,
    raw_at: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Prologue,
    SlotHead,
    Blob,
    SlotTail,
    Comma,
    Tail,
    Done,
}

impl LookupEncoder {
    pub fn from_snap(snap: LookupSnap) -> LookupEncoder {
        LookupEncoder {
            slots: snap.slots,
            index: 0,
            phase: Phase::Prologue,
            fixed: prologue(snap.kind),
            fixed_at: 0,
            raw_at: 0,
        }
    }

    /// The next piece of the answer, or `None` when it is finished.
    /// Every piece is at most [`LOOKUP_JSON_CHUNK`] bytes.
    pub fn next_chunk(&mut self) -> Option<Vec<u8>> {
        if self.phase == Phase::Done {
            return None;
        }
        let mut buf = Vec::with_capacity(LOOKUP_JSON_CHUNK);
        loop {
            if self.phase == Phase::Done || buf.len() >= LOOKUP_JSON_CHUNK {
                break;
            }
            match self.phase {
                Phase::Blob => match self.write_blob(&mut buf) {
                    BlobWrite::NeedRoom => break,
                    BlobWrite::Wrote => {}
                    BlobWrite::Finished => {
                        // Close the blob string and the slot object.
                        self.phase = Phase::SlotTail;
                        self.fixed = "\"}".to_string();
                        self.fixed_at = 0;
                    }
                },
                Phase::Done => break,
                Phase::Prologue
                | Phase::SlotHead
                | Phase::SlotTail
                | Phase::Comma
                | Phase::Tail => {
                    if !self.copy_fixed(&mut buf) {
                        break;
                    }
                    self.advance_after_fixed();
                }
            }
        }
        if buf.is_empty() {
            self.phase = Phase::Done;
            None
        } else {
            Some(buf)
        }
    }

    fn copy_fixed(&mut self, buf: &mut Vec<u8>) -> bool {
        let bytes = self.fixed.as_bytes();
        let room = LOOKUP_JSON_CHUNK - buf.len();
        let left = bytes.len().saturating_sub(self.fixed_at);
        let n = room.min(left);
        buf.extend_from_slice(&bytes[self.fixed_at..self.fixed_at + n]);
        self.fixed_at += n;
        self.fixed_at >= bytes.len()
    }

    fn advance_after_fixed(&mut self) {
        match self.phase {
            Phase::Prologue => {
                if self.slots.is_empty() {
                    self.phase = Phase::Tail;
                    self.fixed = "]}".to_string();
                    self.fixed_at = 0;
                } else {
                    self.begin_slot();
                }
            }
            Phase::SlotHead => {
                self.phase = Phase::Blob;
                self.raw_at = 0;
            }
            Phase::SlotTail => {
                self.index += 1;
                if self.index < self.slots.len() {
                    self.phase = Phase::Comma;
                    self.fixed = ",".to_string();
                    self.fixed_at = 0;
                } else {
                    self.phase = Phase::Tail;
                    self.fixed = "]}".to_string();
                    self.fixed_at = 0;
                }
            }
            Phase::Comma => self.begin_slot(),
            Phase::Tail => self.phase = Phase::Done,
            Phase::Blob | Phase::Done => {}
        }
    }

    fn begin_slot(&mut self) {
        let s = &self.slots[self.index];
        self.fixed = format!(
            "{{\"slot\":\"{}\",\"ts\":{},\"expires\":{},\"blob\":\"",
            hex::encode(s.slot),
            s.ts,
            s.expires
        );
        self.fixed_at = 0;
        self.phase = Phase::SlotHead;
    }

    fn write_blob(&mut self, buf: &mut Vec<u8>) -> BlobWrite {
        let blob = &self.slots[self.index].blob;
        if self.raw_at >= blob.len() {
            return BlobWrite::Finished;
        }
        let left = blob.len() - self.raw_at;
        let room = LOOKUP_JSON_CHUNK - buf.len();
        let n = bytes_that_fit(left, room);
        if n == 0 {
            return BlobWrite::NeedRoom;
        }
        let start = buf.len();
        let out_len = b64_len(n);
        buf.resize(start + out_len, 0);
        let wrote = B64
            .encode_slice(&blob[self.raw_at..self.raw_at + n], &mut buf[start..])
            .expect("base64 output length");
        debug_assert_eq!(wrote, out_len);
        if wrote != out_len {
            buf.truncate(start + wrote);
        }
        self.raw_at += n;
        if self.raw_at == blob.len() {
            BlobWrite::Finished
        } else {
            BlobWrite::Wrote
        }
    }
}

enum BlobWrite {
    NeedRoom,
    Wrote,
    Finished,
}

fn prologue(kind: Option<Kind>) -> String {
    let k = match kind {
        None => "null",
        Some(Kind::Peer) => "\"peer\"",
        Some(Kind::Pair) => "\"pair\"",
    };
    format!("{{\"kind\":{k},\"slots\":[")
}

/// Base64url (no padding) length of `n` raw bytes.
fn b64_len(n: usize) -> usize {
    match n % 3 {
        0 => n / 3 * 4,
        1 => n / 3 * 4 + 2,
        _ => n / 3 * 4 + 3,
    }
}

/// How many raw bytes of a blob fit in `room` output bytes without
/// splitting a 3-byte group, unless that finishes the blob.
fn bytes_that_fit(left: usize, room: usize) -> usize {
    if left == 0 || room == 0 {
        return 0;
    }
    if b64_len(left) <= room {
        return left;
    }
    let groups = room / 4;
    (groups * 3).min(left - left % 3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{PAIR_SLOT, PAIR_TTL_MAX};
    use ed25519_dalek::SigningKey;

    const NOW: u64 = 1_800_000_000;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn put(kind: Kind, tag: u8, slot: u8, k: &SigningKey, ts: u64, ttl: u32) -> PutSlot {
        let s = if kind == Kind::Pair {
            PAIR_SLOT
        } else {
            [slot; 16]
        };
        PutSlot::sign(kind, [tag; 16], s, k, ts, ttl, vec![slot; 10])
    }

    fn reg() -> Registry {
        Registry::new(1000, 1 << 20)
    }

    #[test]
    fn first_writer_owns_the_slot_and_later_writes_must_be_newer() {
        let mut r = reg();
        let a = r
            .put(&put(Kind::Peer, 1, 1, &key(1), NOW, 100), NOW)
            .unwrap();
        assert!(a.created);
        assert_eq!(a.expires, NOW + 100);
        // Another key cannot take or overwrite it.
        assert_eq!(
            r.put(&put(Kind::Peer, 1, 1, &key(2), NOW + 1, 100), NOW + 1),
            Err(ErrorCode::NotOwner)
        );
        // The owner again, but not newer: a replay.
        assert_eq!(
            r.put(&put(Kind::Peer, 1, 1, &key(1), NOW, 100), NOW + 1),
            Err(ErrorCode::Stale)
        );
        let b = r
            .put(&put(Kind::Peer, 1, 1, &key(1), NOW + 2, 100), NOW + 2)
            .unwrap();
        assert!(!b.created);
        assert_eq!(
            r.owner(&[1; 16], &[1; 16], NOW + 2),
            Some(key(1).verifying_key().to_bytes())
        );
        assert_eq!(r.counts().slots, 1);
    }

    #[test]
    fn slots_expire_and_then_anyone_may_take_them() {
        let mut r = reg();
        r.put(&put(Kind::Peer, 1, 1, &key(1), NOW, 100), NOW)
            .unwrap();
        assert_eq!(r.lookup(&[1; 16], NOW + 99).slots.len(), 1);
        assert!(r.lookup(&[1; 16], NOW + 100).slots.is_empty());
        assert_eq!(r.owner(&[1; 16], &[1; 16], NOW + 100), None);
        let a = r
            .put(&put(Kind::Peer, 1, 1, &key(2), NOW + 101, 100), NOW + 101)
            .unwrap();
        assert!(a.created);
        assert_eq!(r.expire(NOW + 1000), 1);
        assert_eq!(r.counts(), Counts::default());
    }

    #[test]
    fn a_tag_is_bounded_and_keeps_its_kind() {
        let mut r = reg();
        for i in 0..crate::proto::MAX_SLOTS_PER_TAG as u8 {
            r.put(&put(Kind::Peer, 1, i, &key(i), NOW, 100), NOW)
                .unwrap();
        }
        assert_eq!(
            r.put(&put(Kind::Peer, 1, 200, &key(200), NOW, 100), NOW),
            Err(ErrorCode::TagFull)
        );
        // A pairing offer cannot land in a peer tag, and one pairing tag
        // holds one offer: a second code holder gets `tag_full`.
        assert_eq!(
            r.put(&put(Kind::Pair, 1, 0, &key(9), NOW, 60), NOW),
            Err(ErrorCode::TagFull)
        );
        r.put(&put(Kind::Pair, 2, 0, &key(9), NOW, PAIR_TTL_MAX), NOW)
            .unwrap();
        assert_eq!(
            r.put(&put(Kind::Pair, 2, 0, &key(10), NOW, 60), NOW),
            Err(ErrorCode::NotOwner)
        );
        assert_eq!(r.kind(&[2; 16], NOW), Some(Kind::Pair));
        assert_eq!(r.counts().pair_offers, 1);
    }

    #[test]
    fn memory_caps_refuse_new_slots() {
        let mut r = Registry::new(2, 1 << 20);
        r.put(&put(Kind::Peer, 1, 1, &key(1), NOW, 100), NOW)
            .unwrap();
        r.put(&put(Kind::Peer, 2, 1, &key(1), NOW, 100), NOW)
            .unwrap();
        assert_eq!(
            r.put(&put(Kind::Peer, 3, 1, &key(1), NOW, 100), NOW),
            Err(ErrorCode::Unavailable)
        );
        let mut small = Registry::new(100, 15);
        small
            .put(&put(Kind::Peer, 1, 1, &key(1), NOW, 100), NOW)
            .unwrap();
        assert_eq!(
            small.put(&put(Kind::Peer, 1, 2, &key(1), NOW, 100), NOW),
            Err(ErrorCode::Unavailable)
        );
    }

    #[test]
    fn only_the_owner_deletes() {
        let mut r = reg();
        r.put(&put(Kind::Pair, 3, 0, &key(1), NOW, 60), NOW)
            .unwrap();
        let wrong = DeleteSlot::sign([3; 16], PAIR_SLOT, &key(2), NOW + 1);
        assert_eq!(r.delete(&wrong, NOW + 1), Err(ErrorCode::NotOwner));
        let old = DeleteSlot::sign([3; 16], PAIR_SLOT, &key(1), NOW - 1);
        assert_eq!(r.delete(&old, NOW + 1), Err(ErrorCode::Stale));
        let ok = DeleteSlot::sign([3; 16], PAIR_SLOT, &key(1), NOW + 1);
        r.delete(&ok, NOW + 1).unwrap();
        assert_eq!(r.delete(&ok, NOW + 1), Err(ErrorCode::NotFound));
        assert_eq!(r.counts(), Counts::default());
    }

    #[test]
    fn forged_puts_never_reach_the_registry() {
        let mut r = reg();
        let mut p = put(Kind::Peer, 1, 1, &key(1), NOW, 100);
        p.blob.0[0] ^= 1;
        assert_eq!(r.put(&p, NOW), Err(ErrorCode::BadSignature));
        assert_eq!(r.counts().slots, 0);
    }

    #[test]
    fn a_lookup_answer_is_written_in_bounded_chunks() {
        let mut r = Registry::new(64, 64 * crate::proto::MAX_BLOB);
        let k = key(1);
        // Out of order, and lengths that hit every base64 group, including
        // one blob larger than a chunk (a full tag is the same writer).
        let specs: &[(u8, usize)] = &[
            (5, 0),
            (1, crate::proto::MAX_BLOB),
            (3, 1),
            (2, 2),
            (4, 4),
            (6, 5),
        ];
        for (slot, n) in specs {
            r.put(
                &PutSlot::sign(
                    Kind::Peer,
                    [9; 16],
                    [*slot; 16],
                    &k,
                    NOW + u64::from(*slot),
                    100,
                    vec![*slot; *n],
                ),
                NOW,
            )
            .unwrap();
        }
        let expect = serde_json::to_string(&r.lookup(&[9; 16], NOW)).unwrap();
        assert!(
            expect.len() > LOOKUP_JSON_CHUNK,
            "the fixture must span more than one chunk"
        );
        let mut enc = LookupEncoder::from_snap(r.lookup_snap(&[9; 16], NOW));
        let mut got = Vec::new();
        let mut chunks = 0usize;
        while let Some(c) = enc.next_chunk() {
            assert!(!c.is_empty());
            assert!(c.len() <= LOOKUP_JSON_CHUNK, "{}", c.len());
            got.extend_from_slice(&c);
            chunks += 1;
        }
        assert!(chunks > 1, "a max blob was not split");
        assert!(enc.next_chunk().is_none());
        assert_eq!(String::from_utf8(got).unwrap(), expect);

        // Unknown tag, and a pairing tag: same bytes as serde, one small chunk.
        let empty = Registry::new(4, 1000);
        let expect = serde_json::to_string(&empty.lookup(&[1; 16], NOW)).unwrap();
        let mut enc = LookupEncoder::from_snap(empty.lookup_snap(&[1; 16], NOW));
        let one = enc.next_chunk().unwrap();
        assert!(one.len() <= LOOKUP_JSON_CHUNK);
        assert!(enc.next_chunk().is_none());
        assert_eq!(String::from_utf8(one).unwrap(), expect);

        let mut pair = Registry::new(4, 1000);
        pair.put(&put(Kind::Pair, 2, 0, &key(9), NOW, 60), NOW)
            .unwrap();
        let expect = serde_json::to_string(&pair.lookup(&[2; 16], NOW)).unwrap();
        let mut enc = LookupEncoder::from_snap(pair.lookup_snap(&[2; 16], NOW));
        let mut got = Vec::new();
        while let Some(c) = enc.next_chunk() {
            assert!(c.len() <= LOOKUP_JSON_CHUNK);
            got.extend_from_slice(&c);
        }
        assert_eq!(String::from_utf8(got).unwrap(), expect);
    }
}
