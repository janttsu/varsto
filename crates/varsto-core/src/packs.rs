// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Packs: every block object is stored inside a pack (format 2).
//!
//! A push collects the encrypted objects of its blocks and writes them to
//! each storage as append-only packs:
//!
//! - `packs/<id[..2]>/<id>`: the objects' bytes one after another, nothing
//!   else; `<id>` is the BLAKE3 hash of the pack's bytes, so a pack is
//!   written with put-if-absent and checked like any object. Packs are cut
//!   at [`HOT_TARGET`] bytes (hot, local, pool and transferrer storages)
//!   or [`COLD_TARGET`] (cold storages).
//! - `packs/index/<device>/<seq>.enc`: per push and folder, the encrypted
//!   list of every block the device wrote (pack, offset, length, object
//!   name, chunk id), for `fsck`, recovery and devices that join later.
//! - `packs/tombstones/<device>/<seq>.enc`: per device and run, the
//!   encrypted list of pack members it deleted.
//!
//! A storage therefore sees pack sizes only, never the size of a block.
//! Where a block lives is in the ledger: a `chunk_stored` claim carries its
//! pack, offset and length ([`PackLoc`]), and the engine hands those to the
//! [`PackContext`] it shares with every storage it opens. The rest of the
//! engine reads and writes `chunks/<xx>/<object>` keys as before: a
//! [`PackStore`] answers them from the packs.
//!
//! Deleting a block records a tombstone. A pack whose members are all dead
//! is deleted; a hot pack more than half dead is rewritten by
//! [`PackStore::collect_garbage`] (the live members go into a new pack, the
//! old one goes); cold packs are never rewritten.

use crate::crypto::SecretKey;
use crate::record_shim::Records;
use crate::storage::Storage;
use anyhow::{anyhow, bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Where packs, pack indexes and tombstone lists are kept.
pub const PREFIX: &str = "packs/";
pub const INDEX_PREFIX: &str = "packs/index/";
pub const TOMBSTONE_PREFIX: &str = "packs/tombstones/";
/// Pack size on hot, local, pool and transferrer storages.
pub const HOT_TARGET: usize = 64 << 20;
/// Pack size on cold storages (fewer, larger objects: per-object fees and
/// minimum sizes).
pub const COLD_TARGET: usize = 256 << 20;
/// Largest block object: the largest chunk, its method byte, nonce and tag.
pub const MAX_OBJECT: u64 =
    crate::manifest::MAX_CHUNK_SIZE + 1 + crate::chunk_seal::OBJECT_OVERHEAD as u64;
/// A listing of a storage's packs is trusted this long before a miss
/// lists again.
const STALE: Duration = Duration::from_secs(30);
/// Record kinds of the envelope (`crate::record_shim`).
pub const KIND_INDEX: &str = "pack-index";
pub const KIND_TOMBSTONES: &str = "tombstones";
/// Version byte of the binary bodies of indexes and tombstone lists.
const BODY_FORMAT: u8 = 2;
/// Largest decompressed body of an index or tombstone list.
const MAX_BODY: usize = 64 << 20;

/// Where one block object is: `len` bytes from `offset` in pack `pack`,
/// which is `pack_len` bytes long.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackLoc {
    pub pack: String,
    pub offset: u64,
    pub len: u64,
    pub pack_len: u64,
}

impl PackLoc {
    /// Whether the numbers can describe a member at all (they come from
    /// other devices' ledger batches and from storages).
    pub fn valid(&self) -> bool {
        is_hash(&self.pack)
            && self.len > 0
            && self.len <= MAX_OBJECT
            && self.pack_len <= crate::storage::MAX_PACK
            && (cfg!(not(feature = "format3")) || is_class(self.pack_len))
            && self
                .offset
                .checked_add(self.len)
                .is_some_and(|end| end <= self.pack_len)
    }
}

/// The first two characters of a name, for the directory a name lives in;
/// never splits a character (a name from a storage is not trusted to be ASCII).
fn head2(s: &str) -> &str {
    s.get(..2).unwrap_or(s)
}

fn is_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The storage key of a pack.
pub fn pack_key(id: &str) -> String {
    format!("{PREFIX}{}/{id}", head2(id))
}

/// The pack id of a key `packs/<xx>/<id>`.
pub fn pack_of_key(key: &str) -> Option<&str> {
    let rest = key.strip_prefix(PREFIX)?;
    let (dir, id) = rest.split_once('/')?;
    (is_hash(id) && dir == &id[..2]).then_some(id)
}

/// The object name a block key `chunks/<xx>/<object>` stands for.
pub fn object_of(key: &str) -> Option<&str> {
    let rest = key.strip_prefix("chunks/")?;
    let (_, obj) = rest.split_once('/')?;
    (!obj.is_empty() && !obj.contains('/')).then_some(obj)
}

/// The block key of an object name.
pub fn chunk_key(object: &str) -> String {
    format!("chunks/{}/{object}", head2(object))
}

const KIB: usize = 1 << 10;
const MIB: usize = 1 << 20;
/// Size classes of a pack: its length is exactly one of them. Hot storages
/// stop at 64 MiB, cold ones (target above 64 MiB) go on to 256 MiB.
const CLASSES: [usize; 6] = [256 * KIB, MIB, 4 * MIB, 16 * MIB, 64 * MIB, 256 * MIB];

/// The smallest pack: the first size class.
pub const MIN_PACK: usize = 256 * KIB;

/// The largest size class on a storage with pack `target`.
pub fn top_class(target: usize) -> usize {
    if target > HOT_TARGET {
        COLD_TARGET
    } else {
        HOT_TARGET
    }
}

/// Whether `len` is a size class of some storage.
pub fn is_class(len: u64) -> bool {
    CLASSES.iter().any(|c| *c as u64 == len)
}

/// How many bytes of members fit in `room` bytes once packs are padded to
/// size classes: whole top-class packs and the largest class in the rest.
pub fn fill_capacity(room: u64) -> u64 {
    let top = HOT_TARGET as u64;
    let rest = room % top;
    let class = CLASSES
        .iter()
        .map(|c| *c as u64)
        .filter(|c| *c <= rest && *c < top)
        .max()
        .unwrap_or(0);
    room - rest + class
}

/// Split `items` into groups to write as one pack each: up to 15 MiB of
/// members, so that a group fills the 16 MiB class (a group of 64 small
/// blocks would be padded to a class of its own, many times its size).
pub fn byte_groups<T>(items: &[T], size: impl Fn(&T) -> u64) -> Vec<&[T]> {
    const GROUP_BYTES: u64 = 15 << 20;
    let mut out = Vec::new();
    let (mut start, mut bytes) = (0, 0u64);
    for (i, it) in items.iter().enumerate() {
        let n = size(it);
        if i > start && bytes + n > GROUP_BYTES {
            out.push(&items[start..i]);
            start = i;
            bytes = 0;
        }
        bytes += n;
    }
    if start < items.len() {
        out.push(&items[start..]);
    }
    out
}

/// The length of a pack of `len` bytes of members on a storage with pack
/// `target`: the smallest class that fits (256 KiB, 1, 4, 16, 64 MiB; 256
/// MiB too on cold storages). Members of a pack never pass the top class
/// (`PackStore` closes a pack before); the whole MiB above it is only a
/// fallback for a caller that does not.
pub fn padded_len(len: usize, target: usize) -> usize {
    let top = top_class(target);
    CLASSES
        .iter()
        .copied()
        .find(|&c| c <= top && len <= c)
        .unwrap_or_else(|| len.div_ceil(MIB) * MIB)
}

/// A pack as `build` makes it: its id, its bytes and the places of its
/// members.
pub type BuiltPack = (String, Vec<u8>, Vec<(String, PackLoc)>);

/// Build a pack from (object name, bytes): its id, bytes and members. The
/// members are followed by random padding up to the size class (see
/// `padded_len`); nothing addresses the padding, the id is the hash of all
/// the bytes and `pack_len` of every place is the padded length.
pub fn build(members: &[(String, &[u8])], target: usize) -> BuiltPack {
    let used: usize = members.iter().map(|(_, b)| b.len()).sum();
    let total = padded_len(used, target);
    let mut bytes = Vec::with_capacity(total);
    let mut spans = Vec::with_capacity(members.len());
    for (object, data) in members {
        spans.push((object.clone(), bytes.len() as u64, data.len() as u64));
        bytes.extend_from_slice(data);
    }
    bytes.resize(total, 0);
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes[used..]);
    let id = hex::encode(crate::crypto::hash(&bytes));
    let pack_len = bytes.len() as u64;
    let locs = spans
        .into_iter()
        .map(|(o, offset, len)| {
            (
                o,
                PackLoc {
                    pack: id.clone(),
                    offset,
                    len,
                    pack_len,
                },
            )
        })
        .collect();
    (id, bytes, locs)
}

/// Place members of the given sizes into bins of at most `limit` bytes,
/// first fit decreasing: the largest member first, each into the first bin
/// it fits. Returns the member indexes of every bin (a member larger than
/// `limit` gets a bin of its own). Used by `PackStore` and by the pack-level
/// moves of format 3 (`crate::storages3`), so full packs are nearly all
/// members.
pub fn first_fit_decreasing(sizes: &[usize], limit: usize) -> Vec<Vec<usize>> {
    let mut order: Vec<usize> = (0..sizes.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(sizes[i]));
    let mut bins: Vec<(Vec<usize>, usize)> = Vec::new();
    for i in order {
        let n = sizes[i];
        match bins.iter_mut().find(|(_, used)| *used + n <= limit) {
            Some((members, used)) => {
                members.push(i);
                *used += n;
            }
            None => bins.push((vec![i], n)),
        }
    }
    bins.into_iter().map(|(m, _)| m).collect()
}

/// A pack this process wrote, not yet listed in a pack index.
#[derive(Clone, Debug)]
pub struct NewPack {
    pub pack: String,
    pub members: Vec<(String, PackLoc)>,
}

/// One block of a pack index: where it is and which chunk it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub loc: PackLoc,
    pub object: String,
    pub chunk: String,
}

/// One deleted pack member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tombstone {
    pub loc: PackLoc,
    pub object: String,
}

fn hash_bytes(hex_str: &str) -> Result<[u8; 32]> {
    let v = hex::decode(hex_str)?;
    v.try_into().map_err(|_| anyhow!("a hash has 32 bytes"))
}

fn put_loc(out: &mut Vec<u8>, l: &PackLoc) -> Result<()> {
    out.extend_from_slice(&hash_bytes(&l.pack)?);
    out.extend_from_slice(&l.offset.to_le_bytes());
    out.extend_from_slice(&l.len.to_le_bytes());
    out.extend_from_slice(&l.pack_len.to_le_bytes());
    Ok(())
}

struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        if self.0.len() < n {
            bail!("record body is cut short");
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
    fn hash(&mut self) -> Result<String> {
        Ok(hex::encode(self.take(32)?))
    }
    fn loc(&mut self) -> Result<PackLoc> {
        let l = PackLoc {
            pack: self.hash()?,
            offset: self.u64()?,
            len: self.u64()?,
            pack_len: self.u64()?,
        };
        // Format 2 reads packs of any length (older builds wrote none
        // padded); a format 3 reader refuses the rest.
        #[cfg(feature = "format3")]
        if !is_class(l.pack_len) {
            bail!(
                "pack {} has length {}, not a size class",
                l.pack,
                l.pack_len
            );
        }
        if !l.valid() {
            bail!("record body names an impossible pack member");
        }
        Ok(l)
    }
}

fn seal_body(kind: u8, n: usize, fill: impl FnOnce(&mut Vec<u8>) -> Result<()>) -> Result<Vec<u8>> {
    let mut raw = vec![BODY_FORMAT, kind];
    raw.extend_from_slice(&(n as u32).to_le_bytes());
    fill(&mut raw)?;
    Ok(zstd::bulk::compress(&raw, crate::pack::ZSTD_LEVEL)?)
}

fn open_body(kind: u8, body: &[u8]) -> Result<(usize, Vec<u8>)> {
    let raw = zstd::bulk::decompress(body, MAX_BODY)?;
    if raw.len() < 6 || raw[0] != BODY_FORMAT || raw[1] != kind {
        bail!("not a format-2 record body of this kind");
    }
    let n = u32::from_le_bytes(raw[2..6].try_into().expect("4 bytes")) as usize;
    Ok((n, raw[6..].to_vec()))
}

/// The body of a pack index: fixed-width binary entries, zstd-compressed.
pub fn encode_index(entries: &[IndexEntry]) -> Result<Vec<u8>> {
    seal_body(1, entries.len(), |out| {
        for e in entries {
            put_loc(out, &e.loc)?;
            out.extend_from_slice(&hash_bytes(&e.object)?);
            out.extend_from_slice(&hash_bytes(&e.chunk)?);
        }
        Ok(())
    })
}

pub fn decode_index(body: &[u8]) -> Result<Vec<IndexEntry>> {
    let (n, raw) = open_body(1, body)?;
    let mut r = Reader(&raw);
    let mut out = Vec::with_capacity(n.min(raw.len() / 128 + 1));
    for _ in 0..n {
        out.push(IndexEntry {
            loc: r.loc()?,
            object: r.hash()?,
            chunk: r.hash()?,
        });
    }
    Ok(out)
}

pub fn encode_tombstones(entries: &[Tombstone]) -> Result<Vec<u8>> {
    seal_body(2, entries.len(), |out| {
        for e in entries {
            put_loc(out, &e.loc)?;
            out.extend_from_slice(&hash_bytes(&e.object)?);
        }
        Ok(())
    })
}

pub fn decode_tombstones(body: &[u8]) -> Result<Vec<Tombstone>> {
    let (n, raw) = open_body(2, body)?;
    let mut r = Reader(&raw);
    let mut out = Vec::with_capacity(n.min(raw.len() / 96 + 1));
    for _ in 0..n {
        out.push(Tombstone {
            loc: r.loc()?,
            object: r.hash()?,
        });
    }
    Ok(out)
}

/// `packs/<kind dir>/<device>/<seq 16 digits>.enc` and back.
pub fn record_key(prefix: &str, device: &str, seq: u64) -> String {
    format!("{prefix}{device}/{seq:016}.enc")
}

pub fn parse_record_key<'a>(prefix: &str, key: &'a str) -> Option<(&'a str, u64)> {
    let rest = key.strip_prefix(prefix)?;
    let (device, file) = rest.split_once('/')?;
    let seq = file.strip_suffix(".enc")?;
    if device.is_empty() || seq.len() != 16 || !seq.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((device, seq.parse().ok()?))
}

/// Where blocks are, as the ledger and this process's writes say.
#[derive(Default)]
struct Locator {
    /// From the ledger view (`PackContext::set_view_locations`).
    view: HashMap<String, Vec<PackLoc>>,
    /// Written or learned by this process.
    own: HashMap<String, Vec<PackLoc>>,
    /// (storage, pack, offset) of every place a live claim of the view
    /// names: a tombstone of another device never makes one of them dead.
    claimed: HashSet<(String, String, u64)>,
    generation: Option<u64>,
}

/// The folders this device holds the keys of, for folder-scoped tombstone
/// lists (format 2: under the folder's metadata key K10, so every device
/// of the folder, members of a shared folder too, reads them).
#[derive(Default)]
struct Folders {
    /// Folder id -> its metadata keys, the one written under first.
    keys: HashMap<String, Vec<SecretKey>>,
    /// Object name -> the folder whose block it is (from the view).
    of_object: HashMap<String, String>,
    /// Changes whenever `keys` does: lists no key opened are tried again.
    generation: u64,
}

impl Locator {
    fn candidates(&self, object: &str) -> Vec<PackLoc> {
        let mut out: Vec<PackLoc> = self.own.get(object).cloned().unwrap_or_default();
        for l in self.view.get(object).into_iter().flatten() {
            if !out.contains(l) {
                out.push(l.clone());
            }
        }
        out
    }
}

/// What this device knows of one storage's packs.
#[derive(Default)]
struct StoreState {
    /// Packs listed on the storage (and written since).
    packs: HashSet<String>,
    listed: Option<Instant>,
    /// Dead members by pack: offset -> (length, deleted by this device).
    dead: HashMap<String, BTreeMap<u64, (u64, bool)>>,
    /// Tombstone lists no key of this device opened, and the folder key
    /// generation they were tried with.
    unreadable: BTreeSet<String>,
    unreadable_generation: u64,
    tombstones_seen: BTreeSet<String>,
    /// This device's highest tombstone list sequence number seen.
    own_tombstone_seq: u64,
    /// Members deleted by this process, not yet written as a list.
    pending: Vec<Tombstone>,
    new_packs: Vec<NewPack>,
}

impl StoreState {
    fn is_dead(&self, l: &PackLoc) -> bool {
        self.dead
            .get(&l.pack)
            .is_some_and(|d| d.contains_key(&l.offset))
    }

    /// Dead members of `pack` that may go: deleted by this device, or by
    /// another device and not claimed live by the view on `storage`.
    fn gone(&self, ctx: &PackContext, storage: &str, pack: &str) -> BTreeMap<u64, u64> {
        self.dead
            .get(pack)
            .into_iter()
            .flatten()
            .filter(|(off, (_, own))| *own || !ctx.claims(storage, pack, **off))
            .map(|(off, (len, _))| (*off, *len))
            .collect()
    }

    fn gone_bytes(&self, ctx: &PackContext, storage: &str, pack: &str) -> u64 {
        self.gone(ctx, storage, pack).values().sum()
    }

    fn mark_dead(&mut self, storage: &str, t: &Tombstone, own: bool) {
        let e = self
            .dead
            .entry(t.loc.pack.clone())
            .or_default()
            .entry(t.loc.offset)
            .or_insert((t.loc.len, own));
        e.1 |= own;
        debug_registry::dead(storage, &t.loc);
    }
}

/// What every storage an engine opens shares: where blocks are, the state
/// of each storage's packs, and the keys of the tombstone lists.
#[derive(Default)]
pub struct PackContext {
    locator: RwLock<Locator>,
    stores: Mutex<HashMap<String, Arc<Mutex<StoreState>>>>,
    tombstones: RwLock<Option<(Records, SecretKey)>>,
    folders: RwLock<Folders>,
    /// Pack indexes read (storage, key), and the ones no folder key opened
    /// with the folder key generation they were tried at.
    indexes: Mutex<IndexesRead>,
    /// Format 3: the folder block map tables that give places of blocks.
    #[cfg(feature = "format3")]
    sources: RwLock<Vec<Arc<dyn PlaceSource>>>,
}

/// Format 3: where blocks are, as a folder's block map table says
/// (`crate::blockmap`). A `PackStore` reads a block from the first of its
/// places held on its storage; places come live ones first.
#[cfg(feature = "format3")]
pub trait PlaceSource: Send + Sync {
    fn places(&self, object: &str) -> Vec<PackLoc>;
    /// Whether a place of `object` is a live copy: it carries no dead or
    /// lost mark and its writer did not flag it dead (design section 5,
    /// "Liveness of a place"). Writes and existence checks use only live
    /// places; reads try them first.
    fn is_live(&self, _object: &str, _loc: &PackLoc) -> bool {
        true
    }
}

/// (storage, key) of pack indexes read, of those no folder key opened, and
/// the folder key generation the latter were tried at.
type IndexesRead = (HashSet<(String, String)>, HashSet<(String, String)>, u64);

/// One context per engine (the name is older than packs for everything).
pub type Caches = Arc<PackContext>;

impl PackContext {
    /// The device that writes tombstone lists, and their key (vault-wide:
    /// any full device deletes blocks and reads what the others deleted).
    pub fn set_tombstone_keys(&self, records: Records, key: SecretKey) {
        *self.tombstones.write().unwrap() = Some((records, key));
    }

    pub fn has_tombstone_keys(&self) -> bool {
        self.tombstones.read().unwrap().is_some()
    }

    /// The ledger generation the view locations were taken from.
    pub fn view_generation(&self) -> Option<u64> {
        self.locator.read().unwrap().generation
    }

    /// Replace what was taken from the ledger view: the locations of
    /// blocks, the places a live claim names (storage, pack, offset), and
    /// the folder of each block.
    pub fn set_view_locations(
        &self,
        generation: u64,
        view: HashMap<String, Vec<PackLoc>>,
        claimed: HashSet<(String, String, u64)>,
        of_object: HashMap<String, String>,
    ) {
        let mut l = self.locator.write().unwrap();
        // A place the view drops (a block just dropped from the ledger) is
        // kept: deleting the block after its drop is sealed still finds it.
        let old = std::mem::take(&mut l.view);
        for (object, locs) in old {
            let now = view.get(&object);
            for loc in locs {
                if now.is_some_and(|n| n.contains(&loc)) {
                    continue;
                }
                let e = l.own.entry(object.clone()).or_default();
                if !e.contains(&loc) {
                    e.push(loc);
                }
            }
        }
        l.view = view;
        l.claimed = claimed;
        l.generation = Some(generation);
        self.folders.write().unwrap().of_object = of_object;
    }

    /// The metadata keys (K10, the one to write under first) of the folders
    /// this device holds: tombstones of their blocks are listed per folder
    /// under them.
    pub fn set_folder_keys(&self, keys: HashMap<String, Vec<SecretKey>>) {
        let mut f = self.folders.write().unwrap();
        let same = f.keys.len() == keys.len()
            && keys.iter().all(|(id, ks)| {
                f.keys.get(id).is_some_and(|old| {
                    old.len() == ks.len() && old.iter().zip(ks).all(|(a, b)| a.0 == b.0)
                })
            });
        if !same {
            f.keys = keys;
            f.generation += 1;
        }
    }

    /// Whether pack index `key` on `storage` is still to be read: not read
    /// yet, and not refused by every folder key this device holds now.
    pub fn index_unread(&self, storage: &str, key: &str) -> bool {
        let generation = self.folders.read().unwrap().generation;
        let mut i = self.indexes.lock().unwrap();
        if i.2 != generation {
            i.1.clear();
            i.2 = generation;
        }
        let k = (storage.to_string(), key.to_string());
        !i.0.contains(&k) && !i.1.contains(&k)
    }

    /// Pack index `key` on `storage` was read (`opened`) or no key of this
    /// device opens it.
    pub fn index_done(&self, storage: &str, key: &str, opened: bool) {
        let k = (storage.to_string(), key.to_string());
        let mut i = self.indexes.lock().unwrap();
        if opened {
            i.0.insert(k);
        } else {
            i.1.insert(k);
        }
    }

    fn claims(&self, storage: &str, pack: &str, offset: u64) -> bool {
        self.locator.read().unwrap().claimed.contains(&(
            storage.to_string(),
            pack.to_string(),
            offset,
        ))
    }

    /// A location learned outside the view (a write, a pack index).
    pub fn learn(&self, object: &str, loc: PackLoc) {
        if !loc.valid() {
            return;
        }
        let mut l = self.locator.write().unwrap();
        let e = l.own.entry(object.to_string()).or_default();
        if !e.contains(&loc) {
            e.push(loc);
        }
    }

    fn candidates(&self, object: &str) -> Vec<PackLoc> {
        self.candidates_where(object, false)
    }

    /// Places of `object` that count as copies: the ones this process
    /// wrote or the ledger gave, and the live places of the block maps.
    fn live_candidates(&self, object: &str) -> Vec<PackLoc> {
        self.candidates_where(object, true)
    }

    fn candidates_where(&self, object: &str, live_only: bool) -> Vec<PackLoc> {
        #[allow(unused_mut)]
        let mut out = self.locator.read().unwrap().candidates(object);
        #[cfg(not(feature = "format3"))]
        let _ = live_only;
        #[cfg(feature = "format3")]
        for s in self.sources.read().unwrap().iter() {
            for l in s.places(object) {
                if l.valid() && !out.contains(&l) && (!live_only || s.is_live(object, &l)) {
                    out.push(l);
                }
            }
        }
        out
    }

    /// Format 3: read places of blocks from `source` too (a folder's block
    /// map table), after the ones this context knows itself.
    #[cfg(feature = "format3")]
    pub fn add_place_source(&self, source: Arc<dyn PlaceSource>) {
        self.sources.write().unwrap().push(source);
    }

    /// Format 3: forget every place source (folder keys changed).
    #[cfg(feature = "format3")]
    pub fn clear_place_sources(&self) {
        self.sources.write().unwrap().clear();
    }

    /// Every block with a known location (for listings).
    fn all_objects(&self) -> Vec<(String, Vec<PackLoc>)> {
        let l = self.locator.read().unwrap();
        let mut out: HashMap<String, Vec<PackLoc>> = HashMap::new();
        for (o, locs) in l.view.iter().chain(l.own.iter()) {
            let e = out.entry(o.clone()).or_default();
            for loc in locs {
                if !e.contains(loc) {
                    e.push(loc.clone());
                }
            }
        }
        out.into_iter().collect()
    }

    fn store(&self, name: &str) -> Arc<Mutex<StoreState>> {
        self.stores
            .lock()
            .unwrap()
            .entry(name.to_string())
            .or_default()
            .clone()
    }

    /// A pack written to storage `name` outside a `PackStore` (a pool disk
    /// being filled): its blocks are located, and it goes into the next
    /// pack index.
    pub fn record_pack(&self, name: &str, pack: NewPack) {
        for (o, l) in &pack.members {
            self.learn(o, l.clone());
        }
        debug_registry::written(&pack.members);
        let st = self.store(name);
        let mut st = st.lock().unwrap();
        st.packs.insert(pack.pack.clone());
        st.new_packs.push(pack);
    }

    /// Whether storage `name` has packs to index or tombstones to write.
    pub fn has_work(&self, name: &str) -> bool {
        let st = self.store(name);
        let st = st.lock().unwrap();
        !st.new_packs.is_empty() || !st.pending.is_empty()
    }

    /// Where `object` is on storage `name`, as far as this device knows
    /// (no request): a live member of a pack the storage holds.
    pub fn location_on(&self, name: &str, object: &str) -> Option<PackLoc> {
        let st = self.store(name);
        let st = st.lock().unwrap();
        self.candidates(object)
            .into_iter()
            .find(|l| st.packs.contains(&l.pack) && !st.is_dead(l))
    }
}

/// A storage whose block objects live in packs. `target`: the pack size
/// written here.
pub struct PackStore {
    inner: Box<dyn Storage>,
    ctx: Caches,
    state: Arc<Mutex<StoreState>>,
    target: usize,
    /// Whether tombstone lists are written here (not on disk pools, which
    /// hold blocks only).
    records: bool,
}

impl PackStore {
    pub fn new(inner: Box<dyn Storage>, ctx: &Caches, target: usize) -> PackStore {
        let state = ctx.store(inner.name());
        PackStore {
            inner,
            ctx: ctx.clone(),
            state,
            target: target.max(1),
            records: true,
        }
    }

    /// The largest whole pack read here: the top size class, plus the block by
    /// which a pack of an older build may pass it.
    fn pack_limit(&self) -> u64 {
        // A pack of an older build passes the top class by one block object.
        (top_class(self.target) as u64 + MAX_OBJECT).min(crate::storage::MAX_PACK)
    }

    /// A storage that holds blocks only (a disk pool): no tombstone lists.
    pub fn blocks_only(mut self) -> PackStore {
        self.records = false;
        self
    }

    /// List the storage's packs and read the tombstone lists not read yet.
    fn refresh(&self) -> Result<()> {
        let keys = self.inner.list(PREFIX)?;
        let mut packs = HashSet::new();
        let mut tomb_keys = Vec::new();
        for k in &keys {
            if let Some(id) = pack_of_key(k) {
                packs.insert(id.to_string());
            } else if k.starts_with(TOMBSTONE_PREFIX) {
                tomb_keys.push(k.clone());
            }
        }
        let keys_for = self.ctx.tombstones.read().unwrap().clone();
        let me = keys_for
            .as_ref()
            .map(|(r, _)| r.device().as_str().to_string());
        let (folder_keys, folder_gen) = {
            let f = self.ctx.folders.read().unwrap();
            (f.keys.clone(), f.generation)
        };
        let unseen: Vec<String> = {
            let mut st = self.state.lock().unwrap();
            if st.unreadable_generation != folder_gen {
                st.unreadable.clear();
                st.unreadable_generation = folder_gen;
            }
            tomb_keys
                .into_iter()
                .filter(|k| !st.tombstones_seen.contains(k) && !st.unreadable.contains(k))
                .collect()
        };
        let mut read: Vec<(String, Vec<Tombstone>)> = Vec::new();
        let mut unreadable: Vec<String> = Vec::new();
        let mut own_seq = 0;
        for k in unseen {
            let Some((device, seq)) = parse_record_key(TOMBSTONE_PREFIX, &k) else {
                read.push((k, Vec::new()));
                continue;
            };
            if me.as_deref() == Some(device) {
                own_seq = own_seq.max(seq);
            }
            let Some((records, key)) = &keys_for else {
                // Without the key nothing is recorded as read: a later
                // engine with the key reads it.
                continue;
            };
            let entries = (|| -> Result<Option<Vec<Tombstone>>> {
                let blob = self.inner.get(&k)?.ok_or_else(|| anyhow!("gone"))?;
                let writer = crate::ids::DeviceId::from_hex(device)?;
                // Vault-scoped (blocks of no folder this device knows), or
                // scoped to a folder whose metadata key this device holds.
                let body = records
                    .open(KIND_TOMBSTONES, "", &writer, seq, key, &blob)
                    .ok()
                    .or_else(|| {
                        folder_keys.iter().find_map(|(folder, keys)| {
                            keys.iter().find_map(|fk| {
                                records
                                    .open(KIND_TOMBSTONES, folder, &writer, seq, fk, &blob)
                                    .ok()
                            })
                        })
                    });
                body.map(|b| decode_tombstones(&b)).transpose()
            })();
            match entries {
                Ok(Some(e)) => read.push((k, e)),
                // Under a key this device does not hold (yet): read again
                // when its folder keys change.
                Ok(None) => unreadable.push(k),
                Err(e) => {
                    log::debug!(storage = self.inner.name(); "packs: tombstone list {k} skipped: {e:#}");
                    read.push((k, Vec::new()));
                }
            }
        }
        let mut st = self.state.lock().unwrap();
        // Packs this process wrote after the listing started stay known.
        let written: Vec<String> = st.new_packs.iter().map(|p| p.pack.clone()).collect();
        st.packs = packs;
        st.packs.extend(written);
        st.own_tombstone_seq = st.own_tombstone_seq.max(own_seq);
        let me_writer = me.unwrap_or_default();
        for (k, entries) in read {
            let own = parse_record_key(TOMBSTONE_PREFIX, &k).is_some_and(|(d, _)| d == me_writer);
            for t in &entries {
                st.mark_dead(self.inner.name(), t, own);
            }
            st.tombstones_seen.insert(k);
        }
        st.unreadable.extend(unreadable);
        st.listed = Some(Instant::now());
        Ok(())
    }

    fn ensure_listed(&self) -> Result<()> {
        if self.state.lock().unwrap().listed.is_none() {
            self.refresh()?;
        }
        Ok(())
    }

    /// The live location of `object` here; with `relist`, a miss lists
    /// the storage again when the last listing is old.
    fn locate(&self, object: &str, relist: bool) -> Result<Option<PackLoc>> {
        self.locate_where(object, relist, true)
    }

    /// `locate` over every place (`live_only` false: marked places too,
    /// after the live ones), for reads.
    fn locate_where(&self, object: &str, relist: bool, live_only: bool) -> Result<Option<PackLoc>> {
        self.ensure_listed()?;
        let candidates = || {
            if live_only {
                self.ctx.live_candidates(object)
            } else {
                self.ctx.candidates(object)
            }
        };
        let find = || {
            let st = self.state.lock().unwrap();
            candidates()
                .into_iter()
                .find(|l| l.valid() && st.packs.contains(&l.pack) && !st.is_dead(l))
        };
        if let Some(l) = find() {
            return Ok(Some(l));
        }
        let stale = self
            .state
            .lock()
            .unwrap()
            .listed
            .is_none_or(|t| t.elapsed() > STALE);
        if relist && stale && !candidates().is_empty() {
            self.refresh()?;
            return Ok(find());
        }
        Ok(None)
    }

    /// The pack is gone from the storage (another device deleted it).
    fn forget_pack(&self, pack: &str) {
        self.state.lock().unwrap().packs.remove(pack);
    }

    /// Every live place of `object`, also in packs the last listing of this
    /// storage did not show (written since by another device, or held
    /// elsewhere): a request tells. Listed packs are included, since another
    /// thread may have added one since `locate` looked.
    fn unlisted(&self, object: &str, live_only: bool) -> Vec<PackLoc> {
        let st = self.state.lock().unwrap();
        let candidates = if live_only {
            self.ctx.live_candidates(object)
        } else {
            self.ctx.candidates(object)
        };
        candidates
            .into_iter()
            .filter(|l| l.valid() && !st.is_dead(l))
            .collect()
    }

    /// A pack found by a request: listed from now on.
    fn found_pack(&self, pack: &str) {
        self.state.lock().unwrap().packs.insert(pack.to_string());
    }

    fn read_member(&self, object: &str) -> Result<Option<Vec<u8>>> {
        for _ in 0..4 {
            let Some(loc) = self.locate_where(object, false, false)? else {
                break;
            };
            match self
                .inner
                .get_range(&pack_key(&loc.pack), loc.offset, loc.len)?
            {
                Some(b) if b.len() as u64 == loc.len => return Ok(Some(b)),
                Some(_) => return Ok(None),
                None => self.forget_pack(&loc.pack),
            }
        }
        for loc in self.unlisted(object, false) {
            if let Some(b) = self
                .inner
                .get_range(&pack_key(&loc.pack), loc.offset, loc.len)?
            {
                if b.len() as u64 == loc.len {
                    self.found_pack(&loc.pack);
                    return Ok(Some(b));
                }
            }
        }
        Ok(None)
    }

    /// Whether a pack not in the listing holds `object` here (one HEAD per
    /// pack, remembered in `checked`).
    fn unlisted_here(&self, object: &str, checked: &mut HashMap<String, bool>) -> Result<bool> {
        for loc in self.unlisted(object, true) {
            let here = match checked.get(&loc.pack) {
                Some(v) => *v,
                None => {
                    let v = self.inner.exists(&pack_key(&loc.pack))?;
                    checked.insert(loc.pack.clone(), v);
                    v
                }
            };
            if here {
                self.found_pack(&loc.pack);
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Write tombstones recorded since the last call as one list.
    fn write_tombstones(&self) -> Result<()> {
        let pending = std::mem::take(&mut self.state.lock().unwrap().pending);
        if pending.is_empty() || !self.records {
            return Ok(());
        }
        let Some((records, key)) = self.ctx.tombstones.read().unwrap().clone() else {
            return Ok(());
        };
        // One list per folder whose key this device holds (under its
        // metadata key, readable by every device of the folder), one under
        // the vault key for the rest.
        let mut lists: BTreeMap<String, Vec<Tombstone>> = BTreeMap::new();
        let mut scoped: HashMap<String, SecretKey> = HashMap::new();
        {
            let f = self.ctx.folders.read().unwrap();
            for t in pending {
                let folder = f
                    .of_object
                    .get(&t.object)
                    .and_then(|id| Some((id, f.keys.get(id)?.first()?)));
                let scope = match folder {
                    Some((id, k)) => {
                        scoped.entry(id.clone()).or_insert_with(|| k.clone());
                        id.clone()
                    }
                    None => String::new(),
                };
                lists.entry(scope).or_default().push(t);
            }
        }
        let device = records.device().as_str().to_string();
        for (scope, list) in lists {
            let body = encode_tombstones(&list)?;
            let key = scoped.get(&scope).unwrap_or(&key);
            let mut seq = self.state.lock().unwrap().own_tombstone_seq + 1;
            loop {
                let k = record_key(TOMBSTONE_PREFIX, &device, seq);
                let blob = records.seal(KIND_TOMBSTONES, &scope, seq, key, &body)?;
                if self.inner.put_if_absent(&k, &blob)? {
                    let mut st = self.state.lock().unwrap();
                    st.own_tombstone_seq = seq;
                    st.tombstones_seen.insert(k);
                    break;
                }
                seq += 1;
            }
        }
        Ok(())
    }

    /// Write packs of the fresh members. Members are placed first-fit
    /// decreasing into packs of at most the top size class (or the target,
    /// when smaller), so that full packs are nearly all members; the pack
    /// of what is left takes the smallest class it fits.
    fn write_packs(&self, fresh: &[(String, &[u8])]) -> Result<()> {
        let limit = self.target.min(top_class(self.target));
        let sizes: Vec<usize> = fresh.iter().map(|(_, b)| b.len()).collect();
        let bins = first_fit_decreasing(&sizes, limit);
        for mut idx in bins {
            // The order of the push inside a pack (blocks of a file next
            // to each other).
            idx.sort_unstable();
            let group: Vec<(String, &[u8])> = idx.iter().map(|&i| fresh[i].clone()).collect();
            let (id, data, members) = build(&group, self.target);
            self.inner.put_if_absent(&pack_key(&id), &data)?;
            for (o, l) in &members {
                self.ctx.learn(o, l.clone());
            }
            debug_registry::written(&members);
            let mut st = self.state.lock().unwrap();
            st.packs.insert(id.clone());
            st.new_packs.push(NewPack { pack: id, members });
        }
        Ok(())
    }

    /// Whether `spans` (offset -> length) follow one another from the start
    /// of a pack of `pack_len` bytes and leave only the padding this store
    /// writes after the last one. A member this device does not know shows
    /// as a gap, except one past the last known member, which hides in the
    /// padding.
    fn accounted(&self, spans: &BTreeMap<u64, u64>, pack_len: u64) -> bool {
        let mut at = 0u64;
        for (off, len) in spans {
            if *off != at {
                return false;
            }
            at += len;
        }
        at == pack_len || padded_len(at as usize, self.target) as u64 == pack_len
    }

    /// Rewrite the hot packs here that are more than half dead and whose
    /// members this device knows completely and `keep` accepts (the engine
    /// keeps to folders whose key it holds): the live members go into new
    /// packs, then the old pack is deleted. Returns the new location of every moved
    /// member. Cold storages never call this.
    pub fn collect_garbage(&self, keep: &dyn Fn(&str) -> bool) -> Result<Vec<(String, PackLoc)>> {
        self.refresh()?;
        let candidates: Vec<(String, u64)> = {
            let st = self.state.lock().unwrap();
            // (pack length, end of the last known member): the padding is
            // not counted as live.
            let mut packs: HashMap<String, (u64, u64)> = HashMap::new();
            for (o, locs) in self.ctx.all_objects() {
                let _ = o;
                for l in locs {
                    if st.packs.contains(&l.pack) {
                        let e = packs.entry(l.pack.clone()).or_insert((l.pack_len, 0));
                        e.1 = e.1.max(l.offset + l.len);
                    }
                }
            }
            packs
                .into_iter()
                .filter(|(p, (_, end))| st.gone_bytes(&self.ctx, self.inner.name(), p) * 2 > *end)
                .map(|(p, (len, _))| (p, len))
                .collect()
        };
        let mut moved = Vec::new();
        for (pack, pack_len) in candidates {
            // Every byte of the pack must be accounted for: a member this
            // device does not know would be lost.
            let all = self.ctx.all_objects();
            let (live, dead): (Vec<(String, PackLoc)>, BTreeMap<u64, u64>) = {
                let gone = self
                    .state
                    .lock()
                    .unwrap()
                    .gone(&self.ctx, self.inner.name(), &pack);
                let live = all
                    .iter()
                    .flat_map(|(o, locs)| locs.iter().map(move |l| (o, l)))
                    .filter(|(_, l)| l.pack == pack && !gone.contains_key(&l.offset))
                    .map(|(o, l)| (o.clone(), l.clone()))
                    .collect();
                (live, gone)
            };
            let mut spans: BTreeMap<u64, u64> = dead;
            let mut live_unique: BTreeMap<u64, (String, PackLoc)> = BTreeMap::new();
            for (o, l) in live {
                live_unique.insert(l.offset, (o, l));
            }
            for (off, (_, l)) in &live_unique {
                spans.insert(*off, l.len);
            }
            if !self.accounted(&spans, pack_len) {
                continue;
            }
            if pack_len > self.pack_limit() {
                continue; // not a pack written with this target
            }
            let Some(bytes) = self
                .inner
                .get_bounded(&pack_key(&pack), self.pack_limit())?
            else {
                self.forget_pack(&pack);
                continue;
            };
            if hex::encode(crate::crypto::hash(&bytes)) != pack {
                continue; // damaged: repair, not garbage collection, handles it
            }
            if live_unique.values().any(|(o, _)| !keep(o)) {
                continue;
            }
            let keep_members: Vec<(String, &[u8])> = live_unique
                .values()
                .map(|(o, l)| {
                    let s = l.offset as usize;
                    (o.clone(), &bytes[s..s + l.len as usize])
                })
                .filter(|(o, b)| hex::encode(crate::crypto::hash(b)) == *o)
                .collect();
            if keep_members.len() != live_unique.len() {
                continue; // a damaged member: repair first
            }
            let before = self.state.lock().unwrap().new_packs.len();
            if !keep_members.is_empty() {
                self.write_packs(&keep_members)?;
            }
            let written: Vec<(String, PackLoc)> = self.state.lock().unwrap().new_packs[before..]
                .iter()
                .flat_map(|p| p.members.clone())
                .collect();
            self.inner.delete(&pack_key(&pack))?;
            {
                let mut st = self.state.lock().unwrap();
                st.packs.remove(&pack);
            }
            moved.extend(written);
        }
        Ok(moved)
    }
}

impl Storage for PackStore {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn conditional_writes(&self) -> Option<bool> {
        self.inner.conditional_writes()
    }

    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        match object_of(key) {
            Some(obj) => Ok(self.put_pack(&[(obj.to_string(), data)])?[0]),
            None => self.inner.put_if_absent(key, data),
        }
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match object_of(key) {
            Some(obj) => self.read_member(obj),
            None => self.inner.get(key),
        }
    }

    fn get_bounded(&self, key: &str, max: u64) -> Result<Option<Vec<u8>>> {
        match object_of(key) {
            // A member is a range of a validated length (`PackLoc::valid`).
            Some(obj) => match self.read_member(obj)? {
                Some(b) if b.len() as u64 > max => {
                    Err(crate::storage::too_large(key, b.len() as u64, max))
                }
                other => Ok(other),
            },
            None => self.inner.get_bounded(key, max),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        let Some(obj) = object_of(key) else {
            return self.inner.exists(key);
        };
        // The listing may be older than another device's deletion of the
        // pack: asked before a write is skipped or a copy counted.
        while let Some(loc) = self.locate(obj, false)? {
            if self.inner.exists(&pack_key(&loc.pack))? {
                return Ok(true);
            }
            self.forget_pack(&loc.pack);
        }
        self.unlisted_here(obj, &mut HashMap::new())
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.list_after(prefix, "")
    }

    fn list_after(&self, prefix: &str, start_after: &str) -> Result<Vec<String>> {
        if !("chunks/".starts_with(prefix) || prefix.starts_with("chunks/")) {
            return self.inner.list_after(prefix, start_after);
        }
        // A listing of blocks lists the packs anew: what other devices
        // wrote or deleted since shows.
        self.refresh()?;
        let mut out = if prefix.is_empty() {
            self.inner.list_after(prefix, start_after)?
        } else {
            Vec::new()
        };
        let st = self.state.lock().unwrap();
        for (obj, locs) in self.ctx.all_objects() {
            if !locs
                .iter()
                .any(|l| l.valid() && st.packs.contains(&l.pack) && !st.is_dead(l))
            {
                continue;
            }
            let k = chunk_key(&obj);
            if k.starts_with(prefix) && k.as_str() > start_after {
                out.push(k);
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    fn delete(&self, key: &str) -> Result<()> {
        let Some(obj) = object_of(key) else {
            return self.inner.delete(key);
        };
        if cfg!(feature = "format3") {
            // Format 3 removes blocks through dead marks and garbage
            // collection (`gc3`), never member by member.
            bail!("{key}: blocks are removed by garbage collection in storage format 3 (f3-switch: part B)");
        }
        // Tombstones of other devices first: a pack they emptied goes.
        self.ensure_listed()?;
        self.unlisted_here(obj, &mut HashMap::new())?;
        while let Some(loc) = self.locate(obj, false)? {
            let t = Tombstone {
                loc: loc.clone(),
                object: obj.to_string(),
            };
            let empty = {
                let mut st = self.state.lock().unwrap();
                st.mark_dead(self.inner.name(), &t, true);
                st.pending.push(t);
                let gone = st.gone(&self.ctx, self.inner.name(), &loc.pack);
                // No member this device knows is left, and the dead ones
                // are all there is (padding apart).
                let live = self.ctx.all_objects().iter().any(|(_, locs)| {
                    locs.iter()
                        .any(|l| l.pack == loc.pack && !gone.contains_key(&l.offset))
                });
                !live && self.accounted(&gone, loc.pack_len)
            };
            if empty {
                // The block is dead either way (its tombstone is recorded);
                // a pack that cannot go now is garbage `collect_garbage`
                // removes later.
                match self.inner.delete(&pack_key(&loc.pack)) {
                    Ok(()) => self.forget_pack(&loc.pack),
                    Err(e) => log::warn!(
                        storage = self.inner.name();
                        "packs: an emptied pack stays until garbage collection: {e:#}"
                    ),
                }
            }
        }
        Ok(())
    }

    fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Option<Vec<u8>>> {
        self.inner.get_range(key, offset, len)
    }

    fn put_pack(&self, members: &[(String, &[u8])]) -> Result<Vec<bool>> {
        self.ensure_listed()?;
        let mut written = vec![false; members.len()];
        let mut fresh: Vec<(String, &[u8])> = Vec::new();
        let mut taken: HashSet<&str> = HashSet::new();
        let mut checked: HashMap<String, bool> = HashMap::new();
        for (i, (o, b)) in members.iter().enumerate() {
            if !taken.insert(o.as_str()) {
                continue;
            }
            let here = match self.locate(o, false)? {
                Some(loc) => match checked.get(&loc.pack) {
                    Some(v) => *v,
                    None => {
                        let v = self.inner.exists(&pack_key(&loc.pack))?;
                        if !v {
                            self.forget_pack(&loc.pack);
                        }
                        checked.insert(loc.pack.clone(), v);
                        v
                    }
                },
                None => self.unlisted_here(o, &mut checked)?,
            };
            if !here {
                fresh.push((o.clone(), *b));
                written[i] = true;
            }
        }
        self.write_packs(&fresh)?;
        Ok(written)
    }

    fn put_built_pack(
        &self,
        id: &str,
        data: &[u8],
        members: &[(String, PackLoc)],
    ) -> Result<Option<Vec<bool>>> {
        // A pack of another storage's class, or one whose members do not
        // fit it, is not taken as it is.
        if !is_class(data.len() as u64)
            || data.len() > top_class(self.target)
            || members
                .iter()
                .any(|(_, l)| l.pack != id || l.pack_len != data.len() as u64 || !l.valid())
        {
            return Ok(None);
        }
        self.ensure_listed()?;
        let mut checked: HashMap<String, bool> = HashMap::new();
        for (o, _) in members {
            let here = match self.locate(o, false)? {
                Some(loc) => match checked.get(&loc.pack) {
                    Some(v) => *v,
                    None => {
                        let v = self.inner.exists(&pack_key(&loc.pack))?;
                        if !v {
                            self.forget_pack(&loc.pack);
                        }
                        checked.insert(loc.pack.clone(), v);
                        v
                    }
                },
                None => self.unlisted_here(o, &mut checked)?,
            };
            if here {
                // Writing the whole pack would put a second copy of a
                // block here: this storage builds its own pack instead.
                return Ok(None);
            }
        }
        self.inner.put_if_absent(&pack_key(id), data)?;
        for (o, l) in members {
            self.ctx.learn(o, l.clone());
        }
        debug_registry::written(members);
        let mut st = self.state.lock().unwrap();
        st.packs.insert(id.to_string());
        st.new_packs.push(NewPack {
            pack: id.to_string(),
            members: members.to_vec(),
        });
        Ok(Some(vec![true; members.len()]))
    }

    fn pack_target(&self) -> usize {
        self.target
    }

    fn pack_location(&self, object: &str) -> Option<PackLoc> {
        self.locate(object, false).ok().flatten()
    }

    fn take_new_packs(&self) -> Vec<NewPack> {
        std::mem::take(&mut self.state.lock().unwrap().new_packs)
    }

    fn flush_deletions(&self) -> Result<()> {
        self.write_tombstones()
    }

    fn collect_pack_garbage(&self, keep: &dyn Fn(&str) -> bool) -> Result<Vec<(String, PackLoc)>> {
        self.collect_garbage(keep)
    }
}

impl Drop for PackStore {
    fn drop(&mut self) {
        // Best effort: an engine writes them at the end of each operation.
        if let Err(e) = self.write_tombstones() {
            log::debug!(storage = self.inner.name(); "packs: tombstones not written: {e:#}");
        }
    }
}

/// One group of `group_by_pack`: the lane, and (item, object, place) of
/// each block in it.
pub type PackGroup<T> = (String, Vec<(T, String, Option<PackLoc>)>);

/// Items to read from storages, grouped so that the blocks of one pack on
/// one storage are read together: `(item, lane, object, location)` in,
/// groups out, in the order of each group's first item. Items without a
/// location stay alone.
pub fn group_by_pack<T>(
    items: impl IntoIterator<Item = (T, String, String, Option<PackLoc>)>,
) -> Vec<PackGroup<T>> {
    let mut groups: Vec<PackGroup<T>> = Vec::new();
    let mut at: HashMap<(String, String), usize> = HashMap::new();
    for (item, lane, object, loc) in items {
        match &loc {
            Some(l) => {
                let k = (lane.clone(), l.pack.clone());
                match at.get(&k) {
                    Some(&g) => groups[g].1.push((item, object, loc)),
                    None => {
                        at.insert(k, groups.len());
                        groups.push((lane, vec![(item, object, loc)]));
                    }
                }
            }
            None => groups.push((lane, vec![(item, object, loc)])),
        }
    }
    groups
}

/// Read a group of `group_by_pack`: the blocks of one pack with one ranged
/// read of the span they cover (verification reads a pack once and checks
/// every member), others one by one. `None` for a block that is not there.
pub fn read_members(
    backend: &dyn Storage,
    members: &[(String, Option<PackLoc>)],
) -> Result<Vec<Option<Vec<u8>>>> {
    let packed: Vec<&PackLoc> = members.iter().filter_map(|(_, l)| l.as_ref()).collect();
    // Places come from other devices' ledger batches: one span is read
    // only for valid places in one pack.
    if packed.len() == members.len()
        && !members.is_empty()
        && packed.iter().all(|l| l.valid() && l.pack == packed[0].pack)
    {
        let start = packed.iter().map(|l| l.offset).min().unwrap_or(0);
        let end = packed.iter().map(|l| l.offset + l.len).max().unwrap_or(0);
        let span = backend.get_range(&pack_key(&packed[0].pack), start, end - start)?;
        return Ok(packed
            .iter()
            .map(|l| {
                span.as_ref().and_then(|b| {
                    let s = (l.offset - start) as usize;
                    b.get(s..s + l.len as usize).map(<[u8]>::to_vec)
                })
            })
            .collect());
    }
    members
        .iter()
        .map(|(o, _)| backend.get(&chunk_key(o)))
        .collect()
}

/// Debug builds remember the members of every pack this process wrote and
/// the ones it deleted, so tests can find, damage and count block objects
/// in a storage directory without the ledger (`tests/common`). Release
/// builds keep nothing.
pub mod debug_registry {
    use super::PackLoc;
    #[cfg(debug_assertions)]
    use std::collections::{HashMap, HashSet};
    use std::path::Path;
    #[cfg(debug_assertions)]
    use std::path::PathBuf;
    #[cfg(debug_assertions)]
    use std::sync::Mutex;

    #[cfg(debug_assertions)]
    #[derive(Default)]
    struct Registry {
        members: HashMap<String, Vec<(String, PackLoc)>>,
        /// (storage, pack, offset): one pack id can be on several storages.
        dead: HashSet<(String, String, u64)>,
        /// Directory of a local storage -> its name.
        roots: HashMap<PathBuf, String>,
    }

    #[cfg(debug_assertions)]
    fn registry() -> &'static Mutex<Registry> {
        static R: std::sync::OnceLock<Mutex<Registry>> = std::sync::OnceLock::new();
        R.get_or_init(Default::default)
    }

    pub(super) fn written(_members: &[(String, PackLoc)]) {
        #[cfg(debug_assertions)]
        if let Some((_, l)) = _members.first() {
            registry()
                .lock()
                .unwrap()
                .members
                .insert(l.pack.clone(), _members.to_vec());
        }
    }

    pub(super) fn dead(_storage: &str, _loc: &PackLoc) {
        #[cfg(debug_assertions)]
        registry().lock().unwrap().dead.insert((
            _storage.to_string(),
            _loc.pack.clone(),
            _loc.offset,
        ));
    }

    /// The directory a local storage named `name` keeps (debug builds).
    pub fn root(_name: &str, _path: &Path) {
        #[cfg(debug_assertions)]
        registry()
            .lock()
            .unwrap()
            .roots
            .insert(_path.to_path_buf(), _name.to_string());
    }

    /// The live members of a pack this process wrote, as the storage kept
    /// in directory `root` sees them (debug builds; nothing in release
    /// builds).
    pub fn members_on(_root: &Path, _pack: &str) -> Vec<(String, PackLoc)> {
        #[cfg(debug_assertions)]
        {
            let r = registry().lock().unwrap();
            let name = r.roots.get(_root).cloned().or_else(|| {
                let canon = _root.canonicalize().ok()?;
                r.roots
                    .iter()
                    .find(|(p, _)| p.canonicalize().ok().as_ref() == Some(&canon))
                    .map(|(_, n)| n.clone())
            });
            r.members
                .get(_pack)
                .map(|m| {
                    m.iter()
                        .filter(|(_, l)| {
                            !r.dead.iter().any(|(s, p, o)| {
                                *p == l.pack
                                    && *o == l.offset
                                    && name.as_ref().is_none_or(|n| n == s)
                            })
                        })
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        }
        #[cfg(not(debug_assertions))]
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{DeviceId, VaultId};
    use crate::storage::LocalDirStorage;

    fn ctx(device: u8) -> Caches {
        let c: Caches = Default::default();
        c.set_tombstone_keys(
            Records::new(
                VaultId::from_bytes(&[1; 16]),
                DeviceId::from_bytes(&[device; 16]),
            ),
            SecretKey([9; 32]),
        );
        c
    }

    fn store(dir: &std::path::Path, ctx: &Caches, target: usize) -> PackStore {
        PackStore::new(
            Box::new(LocalDirStorage::new("box".into(), dir.to_path_buf()).unwrap()),
            ctx,
            target,
        )
    }

    fn objects(lens: &[usize]) -> Vec<(String, Vec<u8>)> {
        lens.iter()
            .enumerate()
            .map(|(i, n)| {
                let b: Vec<u8> = (0..*n).map(|j| (i * 7 + j) as u8).collect();
                (hex::encode(crate::crypto::hash(&b)), b)
            })
            .collect()
    }

    /// Another device learns the places from the ledger: here, from the
    /// writer's new packs.
    fn share(from: &PackStore, to: &Caches) -> Vec<NewPack> {
        let new = from.take_new_packs();
        for p in &new {
            for (o, l) in &p.members {
                to.learn(o, l.clone());
            }
        }
        new
    }

    fn member_refs(objs: &[(String, Vec<u8>)]) -> Vec<(String, &[u8])> {
        objs.iter()
            .map(|(o, b)| (o.clone(), b.as_slice()))
            .collect()
    }

    #[test]
    fn size_classes_hold_the_smallest_fit() {
        let (kib, mib) = (1usize << 10, 1usize << 20);
        for (len, hot, cold) in [
            (0, 256 * kib, 256 * kib),
            (1, 256 * kib, 256 * kib),
            (256 * kib, 256 * kib, 256 * kib),
            (256 * kib + 1, mib, mib),
            (mib + 1, 4 * mib, 4 * mib),
            (5 * mib, 16 * mib, 16 * mib),
            (16 * mib + 1, 64 * mib, 64 * mib),
            (64 * mib, 64 * mib, 64 * mib),
            (64 * mib + 1, 65 * mib, 256 * mib),
            (200 * mib, 200 * mib, 256 * mib),
            (256 * mib, 256 * mib, 256 * mib),
        ] {
            assert_eq!(padded_len(len, HOT_TARGET), hot, "hot {len}");
            assert_eq!(padded_len(len, COLD_TARGET), cold, "cold {len}");
        }
        for c in [256 * kib, mib, 4 * mib, 16 * mib, 64 * mib, 256 * mib] {
            assert!(is_class(c as u64));
        }
        assert!(!is_class(100) && !is_class(2 * mib as u64) && !is_class(65 * mib as u64));
        assert_eq!(crate::storage::MAX_PACK, 256 * mib as u64);
    }

    #[test]
    fn a_pack_is_padded_to_its_class_with_random_bytes() {
        let (kib, mib) = (1usize << 10, 1usize << 20);
        for (sizes, hot) in [
            (vec![1usize], 256 * kib),
            (vec![2 * mib, 3 * mib], 16 * mib),
        ] {
            let objs = objects(&sizes);
            let (id, bytes, locs) = build(&member_refs(&objs), HOT_TARGET);
            assert_eq!(bytes.len(), hot);
            assert_eq!(hex::encode(crate::crypto::hash(&bytes)), id);
            let used: usize = sizes.iter().sum();
            assert!(bytes[used..].iter().any(|b| *b != 0), "padding is random");
            for ((o, b), (lo, loc)) in objs.iter().zip(&locs) {
                assert_eq!(o, lo);
                assert_eq!(loc.pack_len, hot as u64);
                assert!(loc.valid());
                assert_eq!(&bytes[loc.offset as usize..][..loc.len as usize], &b[..]);
            }
        }
        // Two packs of the same members are not the same object.
        let small = objects(&[10]);
        assert_ne!(
            build(&member_refs(&small), HOT_TARGET).0,
            build(&member_refs(&small), HOT_TARGET).0
        );
    }

    #[test]
    fn a_push_over_the_top_class_closes_the_pack_and_starts_another() {
        let mib = 1usize << 20;
        let t = tempfile::tempdir().unwrap();
        let s = store(t.path(), &ctx(2), HOT_TARGET);
        // 7 blocks of 10 MiB: six fill one 64 MiB pack (first-fit), the
        // last one takes the smallest class it fits.
        let objs = objects(&[10 * mib; 7]);
        s.put_pack(&member_refs(&objs)).unwrap();
        let mut lens: Vec<u64> = common_pack_lens(t.path());
        lens.sort();
        assert_eq!(lens, vec![16 * mib as u64, 64 * mib as u64]);
        // On a cold storage all 70 MiB go into one pack of the 256 MiB class.
        let t = tempfile::tempdir().unwrap();
        let s = store(t.path(), &ctx(2), COLD_TARGET);
        s.put_pack(&member_refs(&objs)).unwrap();
        assert_eq!(common_pack_lens(t.path()), vec![256 * mib as u64]);
    }

    fn common_pack_lens(dir: &std::path::Path) -> Vec<u64> {
        let st = LocalDirStorage::new("x".into(), dir.to_path_buf()).unwrap();
        st.list(PREFIX)
            .unwrap()
            .iter()
            .filter(|k| pack_of_key(k).is_some())
            .map(|k| st.get(k).unwrap().unwrap().len() as u64)
            .collect()
    }

    #[test]
    fn padded_packs_are_read_back_member_by_member() {
        let t = tempfile::tempdir().unwrap();
        let c = ctx(2);
        let s = store(t.path(), &c, HOT_TARGET);
        let objs = objects(&[1]);
        s.put_pack(&member_refs(&objs)).unwrap();
        let keys = s.inner.list(PREFIX).unwrap();
        let pack = keys.iter().find(|k| pack_of_key(k).is_some()).unwrap();
        let bytes = s.inner.get(pack).unwrap().unwrap();
        assert_eq!(bytes.len(), 256 << 10);
        assert_eq!(
            hex::encode(crate::crypto::hash(&bytes)),
            pack_of_key(pack).unwrap()
        );
        assert_eq!(
            s.get(&chunk_key(&objs[0].0)).unwrap().as_deref(),
            Some(objs[0].1.as_slice())
        );
        assert_eq!(s.pack_location(&objs[0].0).unwrap().pack_len, 256 << 10);
    }

    #[test]
    #[ignore = "f3-switch: port in part B (pack rewrite and GC: gc3 dead marks replace tombstones)"]
    fn a_fully_deleted_padded_pack_goes() {
        let t = tempfile::tempdir().unwrap();
        let c = ctx(2);
        let s = store(t.path(), &c, HOT_TARGET);
        let objs = objects(&[100, 200]);
        s.put_pack(&member_refs(&objs)).unwrap();
        s.delete(&chunk_key(&objs[0].0)).unwrap();
        assert_eq!(
            s.inner
                .list(PREFIX)
                .unwrap()
                .iter()
                .filter(|k| pack_of_key(k).is_some())
                .count(),
            1
        );
        s.delete(&chunk_key(&objs[1].0)).unwrap();
        assert!(s
            .inner
            .list(PREFIX)
            .unwrap()
            .iter()
            .all(|k| pack_of_key(k).is_none()));
    }

    // A format 3 reader refuses unpadded packs by design.
    #[cfg(not(feature = "format3"))]
    #[test]
    fn a_pack_of_an_older_build_is_read_verified_and_collected() {
        let t = tempfile::tempdir().unwrap();
        let c = ctx(2);
        let s = store(t.path(), &c, HOT_TARGET);
        // A pack as earlier builds wrote it: members only, no padding.
        let objs = objects(&[1000, 1000, 500]);
        let mut bytes = Vec::new();
        let mut spans = Vec::new();
        for (o, b) in &objs {
            spans.push((o.clone(), bytes.len() as u64, b.len() as u64));
            bytes.extend_from_slice(b);
        }
        let id = hex::encode(crate::crypto::hash(&bytes));
        s.inner.put_if_absent(&pack_key(&id), &bytes).unwrap();
        for (o, offset, len) in spans {
            c.learn(
                &o,
                PackLoc {
                    pack: id.clone(),
                    offset,
                    len,
                    pack_len: bytes.len() as u64,
                },
            );
        }
        for (o, b) in &objs {
            assert_eq!(s.get(&chunk_key(o)).unwrap().as_deref(), Some(b.as_slice()));
        }
        let loc = s.pack_location(&objs[0].0).unwrap();
        assert!(loc.valid() && loc.pack_len == 2500);
        let whole = s.inner.get(&pack_key(&id)).unwrap().unwrap();
        assert_eq!(hex::encode(crate::crypto::hash(&whole)), id);
        // Two of three blocks die: more than half, so it is rewritten (padded).
        s.delete(&chunk_key(&objs[0].0)).unwrap();
        s.delete(&chunk_key(&objs[1].0)).unwrap();
        let moved = s.collect_garbage(&|_| true).unwrap();
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].1.pack_len, 256 << 10);
        assert!(!s.inner.exists(&pack_key(&id)).unwrap());
        assert_eq!(
            s.get(&chunk_key(&objs[2].0)).unwrap().as_deref(),
            Some(objs[2].1.as_slice())
        );
    }

    #[test]
    fn blocks_of_any_size_round_trip_through_packs() {
        let t = tempfile::tempdir().unwrap();
        let c = ctx(2);
        let s = store(t.path(), &c, HOT_TARGET);
        let objs = objects(&[1, 63, 64, 4095, 4096, 300_000, 16 << 20]);
        let refs: Vec<(String, &[u8])> = objs
            .iter()
            .map(|(o, b)| (o.clone(), b.as_slice()))
            .collect();
        assert_eq!(s.put_pack(&refs).unwrap(), vec![true; objs.len()]);
        // One pack, no block object of its own, named by its bytes.
        let keys = s.inner.list("").unwrap();
        assert!(keys.iter().all(|k| !k.starts_with("chunks/")), "{keys:?}");
        let packs: Vec<&String> = keys.iter().filter(|k| pack_of_key(k).is_some()).collect();
        assert_eq!(packs.len(), 1);
        let bytes = s.inner.get(packs[0]).unwrap().unwrap();
        assert_eq!(
            hex::encode(crate::crypto::hash(&bytes)),
            pack_of_key(packs[0]).unwrap()
        );
        // The members, then padding up to the size class (17 MiB: the next
        // MiB above the top class is not reached, the 64 MiB class is).
        let used = objs.iter().map(|(_, b)| b.len()).sum::<usize>();
        assert_eq!(bytes.len(), padded_len(used, HOT_TARGET));
        assert_eq!(bytes.len(), 64 << 20);
        // Another device that knows the places reads every block.
        let other_ctx = ctx(3);
        share(&s, &other_ctx);
        let other = store(t.path(), &other_ctx, HOT_TARGET);
        for (o, b) in &objs {
            assert_eq!(
                other.get(&chunk_key(o)).unwrap().as_deref(),
                Some(b.as_slice())
            );
            assert!(other.exists(&chunk_key(o)).unwrap());
        }
        assert_eq!(other.list("chunks/").unwrap().len(), objs.len());
        // Writing again writes nothing.
        assert_eq!(other.put_pack(&refs).unwrap(), vec![false; objs.len()]);
        // A device that does not know the places finds nothing.
        let stranger = store(t.path(), &ctx(4), HOT_TARGET);
        assert!(stranger.get(&chunk_key(&objs[0].0)).unwrap().is_none());
    }

    #[test]
    fn packs_are_cut_at_the_target_size() {
        let t = tempfile::tempdir().unwrap();
        let c = ctx(2);
        let s = store(t.path(), &c, 10_000);
        let objs = objects(&[4000; 7]);
        let refs: Vec<(String, &[u8])> = objs
            .iter()
            .map(|(o, b)| (o.clone(), b.as_slice()))
            .collect();
        s.put_pack(&refs).unwrap();
        let new = s.take_new_packs();
        // 4000 + 4000 fit 10 000, a third would not: 2 + 2 + 2 + 1.
        let sizes: Vec<usize> = new.iter().map(|p| p.members.len()).collect();
        assert_eq!(sizes, vec![2, 2, 2, 1]);
        for (o, b) in &objs {
            assert_eq!(s.get(&chunk_key(o)).unwrap().as_deref(), Some(b.as_slice()));
        }
    }

    #[test]
    #[ignore = "f3-switch: port in part B (pack rewrite and GC: gc3 dead marks replace tombstones)"]
    fn deletions_become_tombstones_and_an_empty_pack_goes() {
        let t = tempfile::tempdir().unwrap();
        let (ca, cb) = (ctx(2), ctx(3));
        let a = store(t.path(), &ca, HOT_TARGET);
        let objs = objects(&[100, 200, 300]);
        let refs: Vec<(String, &[u8])> = objs
            .iter()
            .map(|(o, b)| (o.clone(), b.as_slice()))
            .collect();
        a.put_pack(&refs).unwrap();
        share(&a, &cb);
        a.delete(&chunk_key(&objs[0].0)).unwrap();
        assert!(!a.exists(&chunk_key(&objs[0].0)).unwrap());
        assert!(a.get(&chunk_key(&objs[0].0)).unwrap().is_none());
        a.flush_deletions().unwrap();
        // The list is encrypted: no object name in it.
        let tomb = a
            .inner
            .list(TOMBSTONE_PREFIX)
            .unwrap()
            .into_iter()
            .next()
            .expect("a tombstone list");
        let raw = a.inner.get(&tomb).unwrap().unwrap();
        assert!(!raw.windows(8).any(|w| objs[0].0.as_bytes().starts_with(w)));
        // Another device reads it: the block is gone for it too.
        let b = store(t.path(), &cb, HOT_TARGET);
        assert!(!b.exists(&chunk_key(&objs[0].0)).unwrap());
        assert!(b.exists(&chunk_key(&objs[1].0)).unwrap());
        // The last two deleted (by the other device): the pack goes.
        for (o, _) in &objs[1..] {
            b.delete(&chunk_key(o)).unwrap();
        }
        assert!(b
            .inner
            .list(PREFIX)
            .unwrap()
            .iter()
            .all(|k| pack_of_key(k).is_none()));
        // Its own deletions go out as one list when it is done.
        let lists = b.inner.list(TOMBSTONE_PREFIX).unwrap();
        assert!(!lists.is_empty());
        drop(b);
        assert_eq!(b_lists_after_drop(t.path()), lists.len() + 1);
    }

    /// The view of a device: every block of `objs` in folder `f1`, and
    /// the places in `claimed` held by a live claim on storage `box`.
    fn view_of(c: &Caches, objs: &[(String, Vec<u8>)], claimed: &[PackLoc], generation: u64) {
        let of_object = objs
            .iter()
            .map(|(o, _)| (o.clone(), "f1".to_string()))
            .collect();
        let claimed = claimed
            .iter()
            .map(|l| ("box".to_string(), l.pack.clone(), l.offset))
            .collect();
        c.set_view_locations(generation, HashMap::new(), claimed, of_object);
    }

    #[test]
    #[ignore = "f3-switch: port in part B (pack rewrite and GC: gc3 dead marks replace tombstones)"]
    fn folder_tombstones_are_read_by_every_device_of_the_folder() {
        let t = tempfile::tempdir().unwrap();
        let folder_keys: HashMap<String, Vec<SecretKey>> =
            [("f1".to_string(), vec![SecretKey([5; 32])])].into();
        let (ca, cb) = (ctx(2), ctx(3));
        // A member of the folder: another vault key, the same folder key.
        let member: Caches = Default::default();
        member.set_tombstone_keys(
            Records::new(
                crate::ids::VaultId::from_bytes(&[1; 16]),
                crate::ids::DeviceId::from_bytes(&[4; 16]),
            ),
            SecretKey([8; 32]),
        );
        let objs = objects(&[100, 200, 300]);
        for c in [&ca, &cb, &member] {
            view_of(c, &objs, &[], 1);
        }
        ca.set_folder_keys(folder_keys.clone());
        member.set_folder_keys(folder_keys.clone());
        let a = store(t.path(), &ca, HOT_TARGET);
        let refs: Vec<(String, &[u8])> = objs
            .iter()
            .map(|(o, b)| (o.clone(), b.as_slice()))
            .collect();
        a.put_pack(&refs).unwrap();
        let new = a.take_new_packs();
        for c in [&cb, &member] {
            for p in &new {
                for (o, l) in &p.members {
                    c.learn(o, l.clone());
                }
            }
        }
        a.delete(&chunk_key(&objs[0].0)).unwrap();
        a.flush_deletions().unwrap();
        // Written under the folder's metadata key, scoped to the folder.
        let tomb = a.inner.list(TOMBSTONE_PREFIX).unwrap().remove(0);
        let (_, seq) = parse_record_key(TOMBSTONE_PREFIX, &tomb).unwrap();
        let blob = a.inner.get(&tomb).unwrap().unwrap();
        let (records, vault_key) = ca.tombstones.read().unwrap().clone().unwrap();
        let writer = records.device().clone();
        assert!(records
            .open(KIND_TOMBSTONES, "", &writer, seq, &vault_key, &blob)
            .is_err());
        assert!(records
            .open(
                KIND_TOMBSTONES,
                "f1",
                &writer,
                seq,
                &SecretKey([5; 32]),
                &blob
            )
            .is_ok());
        // A member reads it with the folder key alone.
        let m = store(t.path(), &member, HOT_TARGET);
        assert!(!m.exists(&chunk_key(&objs[0].0)).unwrap());
        assert!(m.exists(&chunk_key(&objs[1].0)).unwrap());
        // A device without the folder key does not, until it gets the key.
        let b = store(t.path(), &cb, HOT_TARGET);
        assert!(b.exists(&chunk_key(&objs[0].0)).unwrap());
        cb.set_folder_keys(folder_keys);
        b.refresh().unwrap();
        assert!(!b.exists(&chunk_key(&objs[0].0)).unwrap());
    }

    #[test]
    #[ignore = "f3-switch: port in part B (pack rewrite and GC: gc3 dead marks replace tombstones)"]
    fn a_tombstone_of_another_device_cannot_kill_a_claimed_block() {
        let t = tempfile::tempdir().unwrap();
        let (owner, hostile) = (ctx(2), ctx(3));
        let objs = objects(&[1000, 1000, 1000, 1000, 500]);
        let o = store(t.path(), &owner, HOT_TARGET);
        let refs: Vec<(String, &[u8])> = objs
            .iter()
            .map(|(o, b)| (o.clone(), b.as_slice()))
            .collect();
        o.put_pack(&refs).unwrap();
        let new = share(&o, &hostile);
        let pack = new[0].pack.clone();
        let places: Vec<PackLoc> = new[0].members.iter().map(|(_, l)| l.clone()).collect();
        // The owner's ledger holds a live claim of every block.
        view_of(&owner, &objs, &places, 1);
        // Another device marks four of five blocks dead.
        let h = store(t.path(), &hostile, HOT_TARGET);
        for (obj, _) in &objs[..4] {
            h.delete(&chunk_key(obj)).unwrap();
        }
        drop(h);
        // The owner deletes the last one: the pack stays, nothing is
        // rewritten away, and the claimed blocks are still in it.
        o.refresh().unwrap();
        o.delete(&chunk_key(&objs[4].0)).unwrap();
        assert!(o.inner.exists(&pack_key(&pack)).unwrap());
        assert!(o.collect_garbage(&|_| true).unwrap().is_empty());
        let bytes = o.inner.get(&pack_key(&pack)).unwrap().unwrap();
        for ((_, b), l) in objs.iter().zip(&places).take(4) {
            assert_eq!(
                &bytes[l.offset as usize..(l.offset + l.len) as usize],
                b.as_slice()
            );
        }
        // Once the ledger drops the claims, the dead pack goes.
        view_of(&owner, &objs, &[], 2);
        assert!(o.collect_garbage(&|_| true).unwrap().is_empty());
        assert!(!o.inner.exists(&pack_key(&pack)).unwrap());
    }

    #[test]
    fn places_outside_the_read_limits_are_refused() {
        let ok = PackLoc {
            pack: "ab".repeat(32),
            offset: crate::storage::MAX_PACK - 10,
            len: 10,
            pack_len: crate::storage::MAX_PACK,
        };
        assert!(ok.valid());
        for bad in [
            PackLoc {
                pack_len: crate::storage::MAX_PACK + 1,
                ..ok.clone()
            },
            PackLoc {
                len: MAX_OBJECT + 1,
                offset: 0,
                ..ok.clone()
            },
            PackLoc {
                offset: u64::MAX,
                ..ok.clone()
            },
            PackLoc {
                pack: "\u{e4}".repeat(32),
                ..ok.clone()
            },
        ] {
            assert!(!bad.valid(), "{bad:?}");
        }
        // A name that is not ASCII never panics a key.
        assert_eq!(pack_key("\u{e4}"), "packs/\u{e4}/\u{e4}");
        assert_eq!(chunk_key("\u{e4}x"), "chunks/\u{e4}/\u{e4}x");
    }

    fn b_lists_after_drop(dir: &std::path::Path) -> usize {
        LocalDirStorage::new("box".into(), dir.to_path_buf())
            .unwrap()
            .list(TOMBSTONE_PREFIX)
            .unwrap()
            .len()
    }

    #[test]
    #[ignore = "f3-switch: port in part B (pack rewrite and GC: gc3 dead marks replace tombstones)"]
    fn a_mostly_dead_pack_is_rewritten_with_its_live_blocks() {
        let t = tempfile::tempdir().unwrap();
        let c = ctx(2);
        let s = store(t.path(), &c, HOT_TARGET);
        let objs = objects(&[1000, 1000, 1000, 1000, 500]);
        let refs: Vec<(String, &[u8])> = objs
            .iter()
            .map(|(o, b)| (o.clone(), b.as_slice()))
            .collect();
        s.put_pack(&refs).unwrap();
        let old = s.take_new_packs().remove(0).pack;
        // Less than half dead: nothing to do.
        s.delete(&chunk_key(&objs[0].0)).unwrap();
        assert!(s.collect_garbage(&|_| true).unwrap().is_empty());
        // More than half: the two live blocks move, the old pack goes.
        s.delete(&chunk_key(&objs[1].0)).unwrap();
        s.delete(&chunk_key(&objs[2].0)).unwrap();
        // A device that may not rewrite one of the blocks leaves the pack.
        assert!(s.collect_garbage(&|o| o != objs[4].0).unwrap().is_empty());
        let moved = s.collect_garbage(&|_| true).unwrap();
        let names: BTreeSet<&str> = moved.iter().map(|(o, _)| o.as_str()).collect();
        assert_eq!(names, [objs[3].0.as_str(), objs[4].0.as_str()].into());
        assert!(!s.inner.exists(&pack_key(&old)).unwrap());
        for (o, b) in &objs[3..] {
            assert_eq!(s.get(&chunk_key(o)).unwrap().as_deref(), Some(b.as_slice()));
        }
        let new = &moved[0].1;
        // 1500 bytes of members in the smallest class.
        assert_eq!(new.pack_len, 256 << 10);
        let rewritten = s.inner.get(&pack_key(&new.pack)).unwrap().unwrap();
        assert_eq!(rewritten.len(), 256 << 10);
        assert_eq!(
            hex::encode(crate::crypto::hash(&rewritten)),
            new.pack,
            "the id is the hash of the padded bytes"
        );
        assert!(rewritten[1500..].iter().any(|b| *b != 0));
    }

    #[test]
    fn index_and_tombstone_bodies_round_trip_and_refuse_impossible_places() {
        let loc = PackLoc {
            pack: "ab".repeat(32),
            offset: 10,
            len: 41,
            pack_len: 1 << 20,
        };
        let entries = vec![IndexEntry {
            loc: loc.clone(),
            object: "cd".repeat(32),
            chunk: "ef".repeat(32),
        }];
        assert_eq!(
            decode_index(&encode_index(&entries).unwrap()).unwrap(),
            entries
        );
        let tombs = vec![Tombstone {
            loc: loc.clone(),
            object: "cd".repeat(32),
        }];
        assert_eq!(
            decode_tombstones(&encode_tombstones(&tombs).unwrap()).unwrap(),
            tombs
        );
        // A place whose pack is no size class is read in format 2 and
        // refused, with a reason, by a format 3 reader.
        let odd = vec![Tombstone {
            loc: PackLoc {
                pack_len: 100,
                ..loc.clone()
            },
            object: "cd".repeat(32),
        }];
        let read = decode_tombstones(&encode_tombstones(&odd).unwrap());
        if cfg!(feature = "format3") {
            let err = read.unwrap_err();
            assert!(
                format!("{err:#}").contains("has length 100, not a size class"),
                "{err:#}"
            );
        } else {
            assert_eq!(read.unwrap(), odd);
        }
        // A body of the other kind, or one naming a place past the pack.
        assert!(decode_tombstones(&encode_index(&entries).unwrap()).is_err());
        let bad = vec![Tombstone {
            loc: PackLoc {
                offset: (1 << 20) - 10,
                ..loc
            },
            object: "cd".repeat(32),
        }];
        assert!(decode_tombstones(&encode_tombstones(&bad).unwrap()).is_err());
        assert_eq!(
            parse_record_key(INDEX_PREFIX, &record_key(INDEX_PREFIX, "dev", 7)),
            Some(("dev", 7))
        );
    }

    #[test]
    fn members_of_one_pack_are_read_with_one_request() {
        let t = tempfile::tempdir().unwrap();
        let c = ctx(2);
        let s = store(t.path(), &c, HOT_TARGET);
        let objs = objects(&[300, 400, 500]);
        let refs: Vec<(String, &[u8])> = objs
            .iter()
            .map(|(o, b)| (o.clone(), b.as_slice()))
            .collect();
        s.put_pack(&refs).unwrap();
        let calls = std::sync::Arc::new(crate::storage::StorageCalls::default());
        let counted = crate::storage::CountingStorage::new(
            Box::new(store(t.path(), &c, HOT_TARGET)),
            calls.clone(),
        );
        let items = objs
            .iter()
            .enumerate()
            .map(|(i, (o, _))| (i, "box".to_string(), o.clone(), counted.pack_location(o)));
        let groups = group_by_pack(items);
        assert_eq!(groups.len(), 1);
        let wanted: Vec<(String, Option<PackLoc>)> = groups[0]
            .1
            .iter()
            .map(|(_, o, l)| (o.clone(), l.clone()))
            .collect();
        let before = calls.snapshot();
        let got = read_members(&counted, &wanted).unwrap();
        let after = calls.snapshot();
        let d = after - before;
        assert_eq!((d.gets, d.lists), (1, 0));
        for ((_, b), g) in objs.iter().zip(got) {
            assert_eq!(g.as_deref(), Some(b.as_slice()));
        }
    }
}
