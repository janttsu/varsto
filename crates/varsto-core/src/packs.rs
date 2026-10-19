// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Packs: every block object is stored inside a pack.
//!
//! A push collects the encrypted objects of its blocks and writes them to
//! each storage as append-only packs, `packs/<id[..2]>/<id>`: the objects'
//! bytes one after another, then random padding up to a size class
//! (`docs/spec/format-3-design.md` section 2); `<id>` is the BLAKE3 hash of
//! all the bytes, so a pack is written with put-if-absent and checked like
//! any object. Packs are cut at [`HOT_TARGET`] bytes (hot, local, pool and
//! transferrer storages) or [`COLD_TARGET`] (cold storages).
//!
//! A storage therefore sees pack sizes only, never the size of a block.
//! Where a block lives is in the folder's block map (`crate::blockmap`):
//! the engine hands the map tables to the [`PackContext`] it shares with
//! every storage it opens ([`PlaceSource`]). The rest of the engine reads
//! and writes `chunks/<xx>/<object>` keys as before: a [`PackStore`]
//! answers them from the packs.
//!
//! A block is never deleted by name: blocks go through garbage collection,
//! which drops or rewrites whole packs after dead marks in the block maps
//! have settled (`crate::gc3`).

use crate::storage::Storage;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Where packs are kept.
pub const PREFIX: &str = "packs/";
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
        .collect::<Vec<_>>();
    debug_registry::written(&locs);
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

/// A pack this process wrote, for the writer's block map delta
/// (`Storage::take_new_packs`).
#[derive(Clone, Debug)]
pub struct NewPack {
    pub pack: String,
    pub members: Vec<(String, PackLoc)>,
}

/// Where blocks are, as this process's writes say.
#[derive(Default)]
struct Locator {
    /// Written or learned by this process.
    own: HashMap<String, Vec<PackLoc>>,
}

/// What this device knows of one storage's packs.
#[derive(Default)]
struct StoreState {
    /// Packs listed on the storage (and written since).
    packs: HashSet<String>,
    listed: Option<Instant>,
    new_packs: Vec<NewPack>,
}

/// What every storage an engine opens shares: where blocks are and the
/// state of each storage's packs.
#[derive(Default)]
pub struct PackContext {
    locator: RwLock<Locator>,
    stores: Mutex<HashMap<String, Arc<Mutex<StoreState>>>>,
    /// The folder block map tables that give places of blocks.
    sources: RwLock<Vec<Arc<dyn PlaceSource>>>,
}

/// Where blocks are, as a folder's block map table says
/// (`crate::blockmap`). A `PackStore` reads a block from the first of its
/// places held on its storage; places come live ones first.
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

/// One context per engine (the name is older than packs for everything).
pub type Caches = Arc<PackContext>;

impl PackContext {
    /// A location learned outside the maps (a write).
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
    /// wrote, and the live places of the block maps.
    fn live_candidates(&self, object: &str) -> Vec<PackLoc> {
        self.candidates_where(object, true)
    }

    fn candidates_where(&self, object: &str, live_only: bool) -> Vec<PackLoc> {
        let mut out: Vec<PackLoc> = self
            .locator
            .read()
            .unwrap()
            .own
            .get(object)
            .cloned()
            .unwrap_or_default();
        for s in self.sources.read().unwrap().iter() {
            for l in s.places(object) {
                if l.valid() && !out.contains(&l) && (!live_only || s.is_live(object, &l)) {
                    out.push(l);
                }
            }
        }
        out
    }

    /// Read places of blocks from `source` too (a folder's block map
    /// table), after the ones this context knows itself.
    pub fn add_place_source(&self, source: Arc<dyn PlaceSource>) {
        self.sources.write().unwrap().push(source);
    }

    /// Forget every place source (folder keys changed).
    pub fn clear_place_sources(&self) {
        self.sources.write().unwrap().clear();
    }

    /// Every block with a known location written by this process (for
    /// listings).
    fn all_objects(&self) -> Vec<(String, Vec<PackLoc>)> {
        let l = self.locator.read().unwrap();
        l.own.iter().map(|(o, v)| (o.clone(), v.clone())).collect()
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
    /// being filled): its blocks are located, and it goes into the
    /// writer's next map delta.
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

    /// Whether storage `name` has packs written that no map delta took yet.
    pub fn has_work(&self, name: &str) -> bool {
        let st = self.store(name);
        let st = st.lock().unwrap();
        !st.new_packs.is_empty()
    }

    /// Where `object` is on storage `name`, as far as this device knows
    /// (no request): a member of a pack the storage holds.
    pub fn location_on(&self, name: &str, object: &str) -> Option<PackLoc> {
        let st = self.store(name);
        let st = st.lock().unwrap();
        self.candidates(object)
            .into_iter()
            .find(|l| st.packs.contains(&l.pack))
    }
}

/// A storage whose block objects live in packs. `target`: the pack size
/// written here.
pub struct PackStore {
    inner: Box<dyn Storage>,
    ctx: Caches,
    state: Arc<Mutex<StoreState>>,
    target: usize,
}

impl PackStore {
    pub fn new(inner: Box<dyn Storage>, ctx: &Caches, target: usize) -> PackStore {
        let state = ctx.store(inner.name());
        PackStore {
            inner,
            ctx: ctx.clone(),
            state,
            target: target.max(1),
        }
    }

    /// List the storage's packs.
    fn refresh(&self) -> Result<()> {
        let keys = self.inner.list(PREFIX)?;
        let packs: HashSet<String> = keys
            .iter()
            .filter_map(|k| pack_of_key(k).map(str::to_string))
            .collect();
        let mut st = self.state.lock().unwrap();
        // Packs this process wrote after the listing started stay known.
        let written: Vec<String> = st.new_packs.iter().map(|p| p.pack.clone()).collect();
        st.packs = packs;
        st.packs.extend(written);
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
                .find(|l| l.valid() && st.packs.contains(&l.pack))
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
        let candidates = if live_only {
            self.ctx.live_candidates(object)
        } else {
            self.ctx.candidates(object)
        };
        candidates.into_iter().filter(|l| l.valid()).collect()
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
            if !locs.iter().any(|l| l.valid() && st.packs.contains(&l.pack)) {
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
        // Blocks go through dead marks and garbage collection (`gc3`),
        // which drop or rewrite whole packs, never member by member.
        bail!("{key}: blocks are removed by garbage collection, never by name ({obj})")
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

/// Debug builds remember the members of every pack this process built, so
/// tests can find, damage and count block objects in a storage directory
/// without the block maps (`tests/common`). Release builds keep nothing.
pub mod debug_registry {
    use super::PackLoc;
    #[cfg(debug_assertions)]
    use std::collections::HashMap;
    use std::path::Path;
    #[cfg(debug_assertions)]
    use std::sync::Mutex;

    #[cfg(debug_assertions)]
    #[derive(Default)]
    struct Registry {
        members: HashMap<String, Vec<(String, PackLoc)>>,
    }

    #[cfg(debug_assertions)]
    fn registry() -> &'static Mutex<Registry> {
        static R: std::sync::OnceLock<Mutex<Registry>> = std::sync::OnceLock::new();
        R.get_or_init(Default::default)
    }

    pub(crate) fn written(_members: &[(String, PackLoc)]) {
        #[cfg(debug_assertions)]
        if let Some((_, l)) = _members.first() {
            registry()
                .lock()
                .unwrap()
                .members
                .insert(l.pack.clone(), _members.to_vec());
        }
    }

    /// The members of a pack this process built, in the storage kept in
    /// directory `root` (a pack is the same on every storage that holds
    /// it; debug builds; nothing in release builds).
    pub fn members_on(_root: &Path, _pack: &str) -> Vec<(String, PackLoc)> {
        #[cfg(debug_assertions)]
        {
            let r = registry().lock().unwrap();
            r.members.get(_pack).cloned().unwrap_or_default()
        }
        #[cfg(not(debug_assertions))]
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::LocalDirStorage;

    fn ctx(_device: u8) -> Caches {
        Default::default()
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

    /// Storage format 3 removes blocks only through garbage collection
    /// (dead marks in the block maps, `crate::gc3`): a block is never
    /// deleted by name, and its pack goes only whole.
    #[test]
    fn a_block_is_never_deleted_by_name() {
        let t = tempfile::tempdir().unwrap();
        let c = ctx(2);
        let s = store(t.path(), &c, HOT_TARGET);
        let objs = objects(&[100, 200]);
        s.put_pack(&member_refs(&objs)).unwrap();
        let pack = s.take_new_packs().remove(0).pack;
        let err = s.delete(&chunk_key(&objs[0].0)).unwrap_err();
        assert!(format!("{err:#}").contains("garbage collection"), "{err:#}");
        assert!(s.inner.exists(&pack_key(&pack)).unwrap());
        assert_eq!(
            s.get(&chunk_key(&objs[0].0)).unwrap().as_deref(),
            Some(objs[0].1.as_slice())
        );
        // No tombstone list or index is written anywhere.
        let all = s.inner.list("").unwrap();
        assert_eq!(all, vec![pack_key(&pack)], "{all:?}");
        // The whole pack goes by its own key.
        s.delete(&pack_key(&pack)).unwrap();
        assert!(!s.inner.exists(&pack_key(&pack)).unwrap());
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
            // A pack whose length is no size class.
            PackLoc {
                offset: 0,
                pack_len: 100,
                ..ok.clone()
            },
        ] {
            assert!(!bad.valid(), "{bad:?}");
        }
        // A name that is not ASCII never panics a key.
        assert_eq!(pack_key("\u{e4}"), "packs/\u{e4}/\u{e4}");
        assert_eq!(chunk_key("\u{e4}x"), "chunks/\u{e4}/\u{e4}x");
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
