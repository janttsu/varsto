// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Packs: many small block objects stored as one storage object.
//!
//! A folder of small files would otherwise be one object per file on every
//! storage: thousands of requests to upload, list and verify, and on some
//! storage classes a minimum billable size per object. A push collects the
//! encrypted objects of small blocks and writes them together:
//!
//! - `packs/<id[..2]>/<id>.pack`: the objects' bytes one after another;
//! - `packs/<id[..2]>/<id>.idx`: JSON listing each object's name, offset
//!   and length in the pack (written after the pack: it makes them visible);
//! - `packs/<id[..2]>/<id>.del.<object>`: one empty marker per object
//!   deleted from the pack; when every object of a pack is marked, the pack,
//!   its index and the markers go.
//!
//! `<id>` is the hash of the pack's bytes. Nothing in a pack is secret
//! beyond what single objects show: the objects are ciphertext named by
//! their hash, which every reader checks. The rest of the engine sees
//! nothing of this: [`PackAware`] answers `chunks/<xx>/<object>` for packed
//! objects as if they were single objects (a ranged read of the pack), and
//! the ledger records objects as before.

use crate::storage::Storage;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Objects up to this size go into packs.
pub const MAX_MEMBER: usize = 128 * 1024;
/// A pack is written when it holds this many bytes or objects.
pub const TARGET_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_MEMBERS: usize = 256;
/// How long a loaded pack index is trusted before a miss reloads it.
const STALE: Duration = Duration::from_secs(30);

const PREFIX: &str = "packs/";
const FORMAT: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    pub object: String,
    pub offset: u64,
    pub len: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackIndex {
    pub format: u32,
    pub pack: String,
    pub members: Vec<Member>,
}

fn dir(id: &str) -> String {
    format!("{PREFIX}{}/{id}", &id[..2.min(id.len())])
}
pub fn pack_key(id: &str) -> String {
    format!("{}.pack", dir(id))
}
pub fn index_key(id: &str) -> String {
    format!("{}.idx", dir(id))
}
fn tombstone_key(id: &str, object: &str) -> String {
    format!("{}.del.{object}", dir(id))
}

/// The object name a block key `chunks/<xx>/<object>` stands for.
pub fn object_of(key: &str) -> Option<&str> {
    let rest = key.strip_prefix("chunks/")?;
    let (_, obj) = rest.split_once('/')?;
    (!obj.is_empty() && !obj.contains('/')).then_some(obj)
}

fn chunk_key(object: &str) -> String {
    format!("chunks/{}/{object}", &object[..2.min(object.len())])
}

/// Build a pack from (object name, bytes): the pack's id, bytes and index.
pub fn build(members: &[(String, &[u8])]) -> (String, Vec<u8>, PackIndex) {
    let mut bytes = Vec::with_capacity(members.iter().map(|(_, b)| b.len()).sum());
    let mut index = Vec::with_capacity(members.len());
    for (object, data) in members {
        index.push(Member {
            object: object.clone(),
            offset: bytes.len() as u64,
            len: data.len() as u64,
        });
        bytes.extend_from_slice(data);
    }
    let id = hex::encode(crate::crypto::hash(&bytes));
    let idx = PackIndex {
        format: FORMAT,
        pack: id.clone(),
        members: index,
    };
    (id, bytes, idx)
}

#[derive(Clone, Debug)]
struct Loc {
    pack: String,
    offset: u64,
    len: u64,
}

/// What this device knows of one storage's packs.
#[derive(Default)]
pub struct Cache {
    loaded: Option<Instant>,
    /// Packed object -> where it is (deleted objects are left out).
    objects: HashMap<String, Loc>,
    /// Pack -> its objects and the ones marked deleted.
    packs: HashMap<String, (Vec<String>, BTreeSet<String>)>,
    seen_index: BTreeSet<String>,
}

impl Cache {
    fn add_index(&mut self, idx: &PackIndex) {
        let names: Vec<String> = idx.members.iter().map(|m| m.object.clone()).collect();
        let deleted = self
            .packs
            .get(&idx.pack)
            .map(|(_, d)| d.clone())
            .unwrap_or_default();
        for m in &idx.members {
            if !deleted.contains(&m.object) {
                self.objects.insert(
                    m.object.clone(),
                    Loc {
                        pack: idx.pack.clone(),
                        offset: m.offset,
                        len: m.len,
                    },
                );
            }
        }
        self.packs.insert(idx.pack.clone(), (names, deleted));
    }

    fn mark_deleted(&mut self, pack: &str, object: &str) {
        let entry = self.packs.entry(pack.to_string()).or_default();
        entry.1.insert(object.to_string());
        if self.objects.get(object).is_some_and(|l| l.pack == pack) {
            self.objects.remove(object);
        }
    }
}

/// One cache per storage, shared by every engine operation that opens it.
pub type Caches = Arc<Mutex<HashMap<String, Arc<Mutex<Cache>>>>>;

/// A storage that knows the packs in it. `packing`: whether new small
/// objects are written as packs here (hot buckets, rclone remotes and
/// directories; not cold storage, transferrers or disk pools).
pub struct PackAware {
    inner: Box<dyn Storage>,
    cache: Arc<Mutex<Cache>>,
    packing: bool,
}

impl PackAware {
    pub fn new(inner: Box<dyn Storage>, caches: &Caches, packing: bool) -> PackAware {
        let cache = caches
            .lock()
            .unwrap()
            .entry(inner.name().to_string())
            .or_default()
            .clone();
        PackAware {
            inner,
            cache,
            packing,
        }
    }

    /// Read the pack indexes and markers this device has not seen yet.
    fn refresh(&self) -> Result<()> {
        let keys = self.inner.list(PREFIX)?;
        let known: BTreeSet<String> = self.cache.lock().unwrap().seen_index.clone();
        let mut fresh = Vec::new();
        let mut tombs = Vec::new();
        for k in &keys {
            if k.ends_with(".idx") && !known.contains(k) {
                fresh.push(k.clone());
            } else if let Some((left, object)) = k.split_once(".del.") {
                let pack = left.rsplit('/').next().unwrap_or_default().to_string();
                tombs.push((pack, object.to_string()));
            }
        }
        let mut parsed = Vec::new();
        for k in fresh {
            if let Some(b) = self.inner.get(&k)? {
                if let Ok(idx) = serde_json::from_slice::<PackIndex>(&b) {
                    parsed.push((k, idx));
                }
            }
        }
        let mut c = self.cache.lock().unwrap();
        for (pack, object) in &tombs {
            c.mark_deleted(pack, object);
        }
        for (k, idx) in parsed {
            c.add_index(&idx);
            c.seen_index.insert(k);
        }
        c.loaded = Some(Instant::now());
        Ok(())
    }

    fn locate(&self, object: &str, reload_on_miss: bool) -> Result<Option<Loc>> {
        let (loc, stale) = {
            let c = self.cache.lock().unwrap();
            (
                c.objects.get(object).cloned(),
                c.loaded.is_none_or(|t| t.elapsed() > STALE),
            )
        };
        if loc.is_some() || !(stale && reload_on_miss) {
            return Ok(loc);
        }
        self.refresh()?;
        Ok(self.cache.lock().unwrap().objects.get(object).cloned())
    }

    fn ensure_loaded(&self) -> Result<()> {
        if self.cache.lock().unwrap().loaded.is_none() {
            self.refresh()?;
        }
        Ok(())
    }
}

impl Storage for PackAware {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        if let Some(obj) = object_of(key) {
            self.ensure_loaded()?;
            if self.locate(obj, false)?.is_some() {
                return Ok(false);
            }
        }
        self.inner.put_if_absent(key, data)
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let Some(obj) = object_of(key) else {
            return self.inner.get(key);
        };
        self.ensure_loaded()?;
        if let Some(loc) = self.locate(obj, false)? {
            if let Some(b) = self
                .inner
                .get_range(&pack_key(&loc.pack), loc.offset, loc.len)?
            {
                return Ok(Some(b));
            }
        }
        if let Some(b) = self.inner.get(key)? {
            return Ok(Some(b));
        }
        // Packed by another device since the index was read: a read is
        // asked for a block that should exist, so look again right away.
        self.refresh()?;
        let loc = self.cache.lock().unwrap().objects.get(obj).cloned();
        match loc {
            Some(loc) => self
                .inner
                .get_range(&pack_key(&loc.pack), loc.offset, loc.len),
            None => Ok(None),
        }
    }

    fn exists(&self, key: &str) -> Result<bool> {
        if let Some(obj) = object_of(key) {
            self.ensure_loaded()?;
            if self.locate(obj, false)?.is_some() {
                return Ok(true);
            }
        }
        self.inner.exists(key)
    }

    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.list_after(prefix, "")
    }

    fn list_after(&self, prefix: &str, start_after: &str) -> Result<Vec<String>> {
        let mut out = self.inner.list_after(prefix, start_after)?;
        if "chunks/".starts_with(prefix) || prefix.starts_with("chunks/") {
            self.ensure_loaded()?;
            let c = self.cache.lock().unwrap();
            for obj in c.objects.keys() {
                let k = chunk_key(obj);
                if k.starts_with(prefix) && k.as_str() > start_after {
                    out.push(k);
                }
            }
            out.sort();
            out.dedup();
        }
        Ok(out)
    }

    fn delete(&self, key: &str) -> Result<()> {
        if let Some(obj) = object_of(key) {
            self.ensure_loaded()?;
            if let Some(loc) = self.locate(obj, false)? {
                self.inner
                    .put_if_absent(&tombstone_key(&loc.pack, obj), b"")?;
                let gone = {
                    let mut c = self.cache.lock().unwrap();
                    c.mark_deleted(&loc.pack, obj);
                    c.packs
                        .get(&loc.pack)
                        .is_some_and(|(all, del)| all.iter().all(|o| del.contains(o)))
                };
                if gone {
                    // Every object of the pack is deleted: the pack goes.
                    let names = self
                        .cache
                        .lock()
                        .unwrap()
                        .packs
                        .get(&loc.pack)
                        .map(|(all, _)| all.clone())
                        .unwrap_or_default();
                    self.inner.delete(&index_key(&loc.pack))?;
                    self.inner.delete(&pack_key(&loc.pack))?;
                    for o in names {
                        let _ = self.inner.delete(&tombstone_key(&loc.pack, &o));
                    }
                    self.cache.lock().unwrap().packs.remove(&loc.pack);
                }
                // A single object of the same name (written before) goes too.
                return self.inner.delete(key);
            }
        }
        self.inner.delete(key)
    }

    fn get_range(&self, key: &str, offset: u64, len: u64) -> Result<Option<Vec<u8>>> {
        self.inner.get_range(key, offset, len)
    }

    fn put_pack(&self, members: &[(String, &[u8])]) -> Result<Vec<bool>> {
        if !self.packing || members.len() < 2 {
            return members
                .iter()
                .map(|(o, b)| self.put_if_absent(&chunk_key(o), b))
                .collect();
        }
        self.ensure_loaded()?;
        // Objects already here (single or packed) are not packed again.
        let mut written = vec![false; members.len()];
        let mut fresh: Vec<(String, &[u8])> = Vec::new();
        let mut positions = Vec::new();
        for (i, (o, b)) in members.iter().enumerate() {
            if self.locate(o, false)?.is_none() && !self.inner.exists(&chunk_key(o))? {
                fresh.push((o.clone(), *b));
                positions.push(i);
            }
        }
        if fresh.len() < 2 {
            for (i, (o, b)) in positions.iter().zip(fresh.iter()) {
                written[*i] = self.inner.put_if_absent(&chunk_key(o), b)?;
            }
            return Ok(written);
        }
        let (id, bytes, idx) = build(&fresh);
        self.inner.put_if_absent(&pack_key(&id), &bytes)?;
        let json = serde_json::to_vec(&idx).map_err(|e| anyhow!("pack index: {e}"))?;
        self.inner.put_if_absent(&index_key(&id), &json)?;
        {
            let mut c = self.cache.lock().unwrap();
            c.add_index(&idx);
            c.seen_index.insert(index_key(&id));
        }
        for i in positions {
            written[i] = true;
        }
        Ok(written)
    }

    fn packs_small_objects(&self) -> bool {
        self.packing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::LocalDirStorage;

    fn store(dir: &std::path::Path, caches: &Caches) -> PackAware {
        PackAware::new(
            Box::new(LocalDirStorage::new("box".into(), dir.to_path_buf()).unwrap()),
            caches,
            true,
        )
    }

    #[test]
    fn packed_objects_read_list_and_delete_like_single_ones() {
        let t = tempfile::tempdir().unwrap();
        let caches: Caches = Default::default();
        let s = store(t.path(), &caches);
        let objs: Vec<(String, Vec<u8>)> = (0..5u8)
            .map(|i| {
                (
                    hex::encode(crate::crypto::hash(&[i])),
                    vec![i; 100 + i as usize],
                )
            })
            .collect();
        let refs: Vec<(String, &[u8])> = objs
            .iter()
            .map(|(o, b)| (o.clone(), b.as_slice()))
            .collect();
        assert_eq!(s.put_pack(&refs).unwrap(), vec![true; 5]);
        // One pack object and its index, not five objects.
        let packs = s.inner.list("packs/").unwrap();
        assert_eq!(packs.iter().filter(|k| k.ends_with(".pack")).count(), 1);
        assert!(s.inner.list("chunks/").unwrap().is_empty());
        // Another engine (fresh cache) sees them.
        let other = store(t.path(), &Caches::default());
        for (o, b) in &objs {
            assert_eq!(
                other.get(&chunk_key(o)).unwrap().as_deref(),
                Some(b.as_slice())
            );
            assert!(other.exists(&chunk_key(o)).unwrap());
        }
        assert_eq!(other.list("chunks/").unwrap().len(), 5);
        // Writing again packs nothing new.
        assert_eq!(other.put_pack(&refs).unwrap(), vec![false; 5]);
        // Deleting four leaves the pack; the fifth removes it with its markers.
        for (o, _) in &objs[..4] {
            other.delete(&chunk_key(o)).unwrap();
        }
        assert_eq!(
            store(t.path(), &Caches::default())
                .list("chunks/")
                .unwrap()
                .len(),
            1
        );
        other.delete(&chunk_key(&objs[4].0)).unwrap();
        assert!(
            s.inner.list("packs/").unwrap().is_empty(),
            "{:?}",
            s.inner.list("packs/").unwrap()
        );
        assert!(store(t.path(), &Caches::default())
            .get(&chunk_key(&objs[0].0))
            .unwrap()
            .is_none());
    }

    #[test]
    fn a_reader_sees_packs_written_after_it_loaded_the_indexes() {
        let t = tempfile::tempdir().unwrap();
        let reader = store(t.path(), &Caches::default());
        let o = hex::encode(crate::crypto::hash(b"late"));
        assert!(reader.get(&chunk_key(&o)).unwrap().is_none());
        let writer = store(t.path(), &Caches::default());
        writer.put_pack(&[(o.clone(), b"late".as_slice())]).unwrap();
        assert_eq!(
            reader.get(&chunk_key(&o)).unwrap().as_deref(),
            Some(b"late".as_slice())
        );
    }
}
