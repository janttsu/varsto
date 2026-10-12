// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Block objects in a local-directory storage, whether stored one per file
//! (`chunks/<xx>/<object>`) or in packs (`packs/<xx>/<id>.pack`, see
//! `varsto_core::packs`): listing, reading, losing and damaging them.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::crypto;
use varsto_core::ids::ObjectName;
use varsto_core::packs::{self, PackAware, PackIndex};
use varsto_core::storage::{LocalDirStorage, Storage};

/// The storage directory as the engine reads it (packs included), with a
/// fresh view of its packs.
pub fn store(root: &Path) -> PackAware {
    let inner = LocalDirStorage::new("test".into(), root.to_path_buf()).unwrap();
    PackAware::new(Box::new(inner), &Default::default(), false)
}

fn chunk_key(object: &str) -> String {
    format!("chunks/{}/{object}", &object[..2])
}

/// Names of the block objects in a storage directory.
pub fn object_names(root: &Path) -> BTreeSet<String> {
    if !root.exists() {
        return BTreeSet::new();
    }
    store(root)
        .list("chunks/")
        .unwrap()
        .into_iter()
        .filter_map(|k| packs::object_of(&k).map(str::to_string))
        .filter(|n| !n.starts_with('.'))
        .collect()
}

pub fn object_count(root: &Path) -> usize {
    object_names(root).len()
}

/// The bytes of a block object, single or packed.
pub fn read_object(root: &Path, object: &str) -> Option<Vec<u8>> {
    store(root).get(&chunk_key(object)).unwrap()
}

/// Whether the object's bytes still hash to its name.
pub fn intact(root: &Path, object: &str) -> bool {
    read_object(root, object)
        .map(|b| ObjectName::from_bytes(&crypto::hash(&b)).as_str() == object)
        .unwrap_or(false)
}

/// Every pack index in a storage directory: (pack file, index file, index).
fn indexes(root: &Path) -> Vec<(PathBuf, PathBuf, PackIndex)> {
    let mut out = Vec::new();
    for e in walkdir::WalkDir::new(root.join("packs"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "idx") {
            let idx: PackIndex = serde_json::from_slice(&fs::read(p).unwrap()).unwrap();
            out.push((p.with_extension("pack"), p.to_path_buf(), idx));
        }
    }
    out
}

fn tombstoned(idx_path: &Path, object: &str) -> bool {
    let stem = idx_path.file_stem().unwrap().to_string_lossy();
    idx_path
        .with_file_name(format!("{stem}.del.{object}"))
        .exists()
}

/// The object is lost from the storage, as if its bytes were gone: a single
/// object's file is removed; a packed object's pack is written again
/// without it (under a new id) and the old pack goes.
pub fn lose_object(root: &Path, object: &str) {
    let single = root.join(chunk_key(object));
    if single.exists() {
        fs::remove_file(single).unwrap();
        return;
    }
    for (pack, idx_path, idx) in indexes(root) {
        if !idx.members.iter().any(|m| m.object == object) || tombstoned(&idx_path, object) {
            continue;
        }
        let bytes = fs::read(&pack).unwrap();
        let keep: Vec<(String, &[u8])> = idx
            .members
            .iter()
            .filter(|m| m.object != object && !tombstoned(&idx_path, &m.object))
            .map(|m| {
                let at = m.offset as usize;
                (m.object.clone(), &bytes[at..at + m.len as usize])
            })
            .collect();
        let stem = idx_path.file_stem().unwrap().to_string_lossy().to_string();
        for e in fs::read_dir(idx_path.parent().unwrap()).unwrap() {
            let p = e.unwrap().path();
            if p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with(&format!("{stem}."))
            {
                fs::remove_file(p).unwrap();
            }
        }
        if !keep.is_empty() {
            let (id, bytes, idx) = packs::build(&keep);
            let raw = LocalDirStorage::new("test".into(), root.to_path_buf()).unwrap();
            raw.put_if_absent(&packs::pack_key(&id), &bytes).unwrap();
            raw.put_if_absent(&packs::index_key(&id), &serde_json::to_vec(&idx).unwrap())
                .unwrap();
        }
        return;
    }
    panic!("no object {object} in {}", root.display());
}

/// Damage the object's stored bytes in place (single file or inside its pack).
pub fn corrupt_object(root: &Path, object: &str) {
    let single = root.join(chunk_key(object));
    let (path, at) = if single.exists() {
        (single, 0)
    } else {
        indexes(root)
            .into_iter()
            .find_map(|(pack, idx_path, idx)| {
                let m = idx.members.iter().find(|m| m.object == object)?;
                (!tombstoned(&idx_path, object)).then_some((pack, m.offset as usize))
            })
            .unwrap_or_else(|| panic!("no object {object} in {}", root.display()))
    };
    let mut bytes = fs::read(&path).unwrap();
    bytes[at] ^= 0xff;
    fs::write(&path, bytes).unwrap();
}

/// Every block object leaves the storage directory (single and packed).
pub fn lose_all_objects(root: &Path) {
    for d in ["chunks", "packs"] {
        let p = root.join(d);
        if p.exists() {
            fs::remove_dir_all(p).unwrap();
        }
    }
}
