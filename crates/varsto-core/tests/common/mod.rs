// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Block objects in a local-directory storage. Every block is in a pack
//! (`packs/<xx>/<id>`, see `varsto_core::packs`); which blocks a pack holds
//! is in the ledger and in encrypted pack indexes, so these helpers ask the
//! record of packs written in this test process
//! (`packs::debug_registry`): listing, reading, losing and damaging blocks.
#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::crypto;
use varsto_core::ids::ObjectName;
use varsto_core::packs::{self, PackLoc};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

/// Storage format 3: `device` asks for every folder `owner` holds and
/// `owner` approves it (comparing the six words, as a person would), then
/// `device` reads its grants. A device that joined with the vault words
/// alone opens no folder before this.
pub fn approve_all(owner: &mut Engine, device: &mut Engine) {
    let folders: Vec<String> = owner
        .folders()
        .into_iter()
        .filter(|(r, _)| !r.key_hex.is_empty())
        .map(|(r, _)| r.name.clone())
        .collect();
    let name = device.own_device_name().to_string();
    for f in folders {
        let req = device.f3_folder_request(&f, "editor").unwrap();
        owner
            .f3_approve(&f, &name, None, Some(&req.fingerprint))
            .unwrap();
    }
    device.refresh_devices().unwrap();
}

/// `Engine::join` and `approve_all` by `owner`.
pub fn join_approved(
    home: &Path,
    name: &str,
    pass: &str,
    key: &str,
    storage: StorageSpec,
    owner: &mut Engine,
) -> Engine {
    let mut e = Engine::join(home, name, pass, key, storage).unwrap();
    approve_all(owner, &mut e);
    e
}

/// Every pack file under a storage directory: (path, pack id).
pub fn pack_files(root: &Path) -> Vec<(PathBuf, String)> {
    let dir = root.join("packs");
    if !dir.exists() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for e in walkdir::WalkDir::new(&dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let rel = e
            .path()
            .strip_prefix(root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if let Some(id) = packs::pack_of_key(&rel) {
            out.push((e.path().to_path_buf(), id.to_string()));
        }
    }
    out.sort();
    out
}

/// The blocks in a storage directory with their pack file and place.
pub fn blocks(root: &Path) -> Vec<(String, PathBuf, PackLoc)> {
    let mut out = Vec::new();
    for (path, id) in pack_files(root) {
        for (object, loc) in packs::debug_registry::members_on(root, &id) {
            out.push((object, path.clone(), loc));
        }
    }
    out
}

/// Names of the block objects in a storage directory.
pub fn object_names(root: &Path) -> BTreeSet<String> {
    blocks(root).into_iter().map(|(o, _, _)| o).collect()
}

pub fn object_count(root: &Path) -> usize {
    object_names(root).len()
}

fn find(root: &Path, object: &str) -> Option<(PathBuf, PackLoc)> {
    blocks(root)
        .into_iter()
        .find(|(o, _, _)| o == object)
        .map(|(_, p, l)| (p, l))
}

/// The pack file that holds a block object.
pub fn pack_path(root: &Path, object: &str) -> Option<PathBuf> {
    find(root, object).map(|(p, _)| p)
}

/// The bytes of a block object.
pub fn read_object(root: &Path, object: &str) -> Option<Vec<u8>> {
    let (path, loc) = find(root, object)?;
    let bytes = fs::read(path).ok()?;
    bytes
        .get(loc.offset as usize..(loc.offset + loc.len) as usize)
        .map(<[u8]>::to_vec)
}

/// Whether the object's bytes still hash to its name.
pub fn intact(root: &Path, object: &str) -> bool {
    read_object(root, object)
        .map(|b| ObjectName::from_bytes(&crypto::hash(&b)).as_str() == object)
        .unwrap_or(false)
}

/// The object is lost from the storage: its pack goes, with every other
/// block in it (a lost pack is how a storage loses blocks now).
pub fn lose_object(root: &Path, object: &str) {
    let (path, _) =
        find(root, object).unwrap_or_else(|| panic!("no object {object} in {}", root.display()));
    fs::remove_file(path).unwrap();
}

/// The blocks that go with `object` when its pack is lost.
pub fn pack_mates(root: &Path, object: &str) -> BTreeSet<String> {
    let Some((path, _)) = find(root, object) else {
        return BTreeSet::new();
    };
    blocks(root)
        .into_iter()
        .filter(|(_, p, _)| *p == path)
        .map(|(o, _, _)| o)
        .collect()
}

/// Damage the object's stored bytes in place, inside its pack.
pub fn corrupt_object(root: &Path, object: &str) {
    let (path, loc) =
        find(root, object).unwrap_or_else(|| panic!("no object {object} in {}", root.display()));
    let mut bytes = fs::read(&path).unwrap();
    bytes[loc.offset as usize] ^= 0xff;
    fs::write(&path, bytes).unwrap();
}

/// Every block object leaves the storage directory.
pub fn lose_all_objects(root: &Path) {
    for d in ["chunks", "packs"] {
        let p = root.join(d);
        if p.exists() {
            fs::remove_dir_all(p).unwrap();
        }
    }
}
