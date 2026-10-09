// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Strongroom (S-012) beyond creation: converting an existing folder and
//! enrolling backup security keys, across two devices that share one storage.
//! The software key stands in for a FIDO2 authenticator.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::strongroom::{Method, SecurityKey, SoftwareKey};
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    storage: StorageSpec,
    a_home: PathBuf,
    b_home: PathBuf,
    a_dir: PathBuf,
    b_dir: PathBuf,
}

fn lab() -> Lab {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    Lab {
        storage: StorageSpec::LocalDir {
            name: "box".into(),
            path: root.join("storage"),
            cold: false,
            carrier: false,
            place: String::new(),
        },
        a_home: root.join("a-home"),
        b_home: root.join("b-home"),
        a_dir: root.join("a-docs"),
        b_dir: root.join("b-docs"),
        root,
        _tmp: tmp,
    }
}

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s & 0xff) as u8
        })
        .collect()
}

/// Every object key in the storage under `prefix`.
fn objects(storage: &Path, prefix: &str) -> BTreeSet<String> {
    let base = storage.join(prefix);
    walkdir::WalkDir::new(&base)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            e.path()
                .strip_prefix(storage)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect()
}

fn two_devices_with_docs(lab: &Lab) -> (Engine, Engine) {
    let (mut a, key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    fs::create_dir_all(lab.a_dir.join("sub")).unwrap();
    fs::write(lab.a_dir.join("hello.txt"), b"hello from a").unwrap();
    fs::write(lab.a_dir.join("sub/big.bin"), pseudo_random(150_000, 3)).unwrap();
    fs::write(lab.a_dir.join("gone.txt"), b"deleted before the conversion").unwrap();
    a.push("docs").unwrap();
    fs::remove_file(lab.a_dir.join("gone.txt")).unwrap();
    a.push("docs").unwrap();

    let mut b = Engine::join(&lab.b_home, "desk", PASS, &key, lab.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &lab.b_dir, false).unwrap();
    b.pull("docs").unwrap();
    fs::write(lab.b_dir.join("from-b.txt"), b"written on b").unwrap();
    b.push("docs").unwrap();
    a.pull("docs").unwrap();
    (a, b)
}

#[test]
fn converting_a_folder_re_encrypts_it_and_removes_the_old_copies() {
    let lab = lab();
    let (mut a, mut b) = two_devices_with_docs(&lab);
    let storage = lab.root.join("storage");
    let old_id = a.folders()[0].0.folder_id.clone();
    let old_chunks = objects(&storage, "chunks");
    assert!(!old_chunks.is_empty());
    assert!(!objects(&storage, &format!("manifests/{old_id}")).is_empty());

    let sk = SoftwareKey {
        path: lab.a_home.join("software-security-key"),
    };
    let r = a
        .convert_to_strongroom("docs", Method::Software, &sk, 15)
        .unwrap();
    assert_eq!(r.files, 3, "{r:?}");
    assert!(r.cleanup.failures.is_empty(), "{:?}", r.cleanup);
    assert!(r.cleanup.objects_deleted >= old_chunks.len() as u64);
    assert_ne!(r.folder_id, old_id.to_string());
    assert!(
        a.strongroom_conversions().is_empty(),
        "nothing left to clean"
    );

    // The old copies are gone from the storage: chunks, manifests, the
    // folder record that held the old key under the vault key.
    let now = objects(&storage, "chunks");
    assert!(now.is_disjoint(&old_chunks), "old chunks remain");
    assert!(!now.is_empty());
    assert!(objects(&storage, &format!("manifests/{old_id}")).is_empty());
    let records = objects(&storage, "vault/folders");
    assert!(
        records.iter().all(|k| !k.contains(old_id.as_str())),
        "{records:?}"
    );

    // On A: a Strongroom, unlocked, files intact, no key at rest.
    let (rec, _) = a.folders().into_iter().next().unwrap();
    assert!(rec.is_strongroom());
    assert!(rec.key_hex.is_empty());
    assert_eq!(
        fs::read(lab.a_dir.join("hello.txt")).unwrap(),
        b"hello from a"
    );
    fs::write(lab.a_dir.join("new.txt"), b"after the conversion").unwrap();
    a.push("docs").unwrap();
    assert_eq!(a.list_files("docs").unwrap().len(), 4);

    // B learns it on its next sync: the plain copies become placeholders,
    // the old key is forgotten, nothing opens without the security key.
    b.sync(None).unwrap();
    let folders = b.folders();
    assert_eq!(folders.len(), 1);
    assert!(folders[0].0.is_strongroom());
    assert!(folders[0].0.key_hex.is_empty());
    assert_ne!(folders[0].0.folder_id, old_id);
    assert!(b.strongroom_conversions().is_empty());
    for f in ["hello.txt", "sub/big.bin", "from-b.txt"] {
        assert!(!lab.b_dir.join(f).exists(), "{f} still in plain text on B");
        assert!(lab.b_dir.join(format!("{f}.varsto-placeholder")).exists());
    }
    assert!(b.pull("docs").is_err(), "locked on B");
    assert!(b.read_file("docs", "new.txt").is_err());
    assert!(b.read_file("docs", "hello.txt").is_err());

    // With a copy of the security key B opens it, and every file is intact.
    let wrong = SoftwareKey {
        path: lab.b_home.join("wrong-key"),
    };
    wrong.make_credential().unwrap();
    assert!(b.unlock_strongroom("docs", &wrong, 5).is_err());
    fs::copy(
        lab.a_home.join("software-security-key"),
        lab.b_home.join("software-security-key"),
    )
    .unwrap();
    b.unlock_strongroom_enrolled("docs", 5).unwrap();
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.conflicts, 0, "{pull:?}");
    for (f, want) in [
        ("hello.txt", b"hello from a".to_vec()),
        ("sub/big.bin", pseudo_random(150_000, 3)),
        ("from-b.txt", b"written on b".to_vec()),
        ("new.txt", b"after the conversion".to_vec()),
    ] {
        b.fetch_file("docs", f).unwrap();
        assert_eq!(fs::read(lab.b_dir.join(f)).unwrap(), want, "{f}");
    }
    assert!(!lab.b_dir.join("gone.txt").exists());
    b.push("docs").unwrap();
    // Converting again is refused politely: it is a Strongroom already.
    let again = a
        .convert_to_strongroom("docs", Method::Software, &sk, 15)
        .unwrap();
    assert_eq!(again.files, 0);
}

#[test]
fn an_interrupted_conversion_deletes_nothing_and_resumes_with_the_same_key() {
    let lab = lab();
    let (mut a, mut b) = two_devices_with_docs(&lab);
    let storage = lab.root.join("storage");
    let old_id = a.folders()[0].0.folder_id.clone();
    // A keeps only a placeholder of one file, and its blocks are away.
    a.free_file("docs", "sub/big.bin").unwrap();
    let old_chunks = objects(&storage, "chunks");
    let away = lab.root.join("away");
    fs::create_dir_all(&away).unwrap();
    for k in &old_chunks {
        let from = storage.join(k);
        if fs::metadata(&from).unwrap().len() > 1000 {
            fs::rename(&from, away.join(k.replace('/', "_"))).unwrap();
        }
    }
    let sk = SoftwareKey {
        path: lab.a_home.join("software-security-key"),
    };
    let err = a
        .convert_to_strongroom("docs", Method::Software, &sk, 15)
        .unwrap_err();
    assert!(format!("{err:#}").contains("sub/big.bin"), "{err:#}");
    // Nothing old was removed and the folder still works as before.
    let (rec, _) = a
        .folders()
        .into_iter()
        .find(|(r, _)| r.folder_id == old_id)
        .unwrap();
    assert!(!rec.is_strongroom());
    assert_eq!(
        a.strongroom_conversions(),
        vec![("docs".to_string(), false)]
    );
    for k in &old_chunks {
        let moved = away.join(k.replace('/', "_"));
        assert!(storage.join(k).exists() || moved.exists());
    }
    b.sync(None).unwrap();
    assert!(!b.folders()[0].0.is_strongroom(), "B was not told anything");
    assert!(lab.b_dir.join("hello.txt").exists());

    // The blocks come back; the same command resumes under the same key.
    for k in &old_chunks {
        let moved = away.join(k.replace('/', "_"));
        if moved.exists() {
            fs::rename(&moved, storage.join(k)).unwrap();
        }
    }
    let (pending_id, _) = a.strongroom_conversion("docs").unwrap();
    let r = a
        .convert_to_strongroom("docs", Method::Software, &sk, 15)
        .unwrap();
    assert_eq!(r.folder_id, pending_id.to_string());
    assert_eq!(r.files_fetched, 1);
    assert!(r.cleanup.failures.is_empty());
    assert!(objects(&storage, "chunks").is_disjoint(&old_chunks));
    assert!(a.strongroom_conversions().is_empty());
    // The placeholder stays a placeholder; its content is in the new folder.
    assert!(!lab.a_dir.join("sub/big.bin").exists());
    a.fetch_file("docs", "sub/big.bin").unwrap();
    assert_eq!(
        fs::read(lab.a_dir.join("sub/big.bin")).unwrap(),
        pseudo_random(150_000, 3)
    );
    b.sync(None).unwrap();
    assert!(b.folders()[0].0.is_strongroom());
    assert!(!lab.b_dir.join("hello.txt").exists());
}

#[test]
fn backup_key_opens_the_strongroom_and_the_last_key_stays() {
    let lab = lab();
    let (mut a, key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    let first = SoftwareKey {
        path: lab.a_home.join("software-security-key"),
    };
    a.create_strongroom("vault", &lab.a_dir, Method::Software, &first, 15)
        .unwrap();
    fs::write(lab.a_dir.join("deed.pdf"), b"title deed").unwrap();
    a.push("vault").unwrap();

    let spare = varsto_core::strongroom::new_software_key(&lab.a_home);
    assert_eq!(
        a.add_strongroom_key("vault", Method::Software, &spare, "safe")
            .unwrap(),
        2
    );
    assert!(
        a.add_strongroom_key("vault", Method::Software, &spare, "again")
            .is_err(),
        "the same key twice"
    );
    let keys = a.strongroom_keys("vault").unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[1].label, "safe");
    a.lock_strongroom("vault").unwrap();
    assert!(
        a.add_strongroom_key(
            "vault",
            Method::Software,
            &varsto_core::strongroom::new_software_key(&lab.a_home),
            ""
        )
        .is_err(),
        "enrolling needs an unlocked Strongroom"
    );

    // Another device: only the spare key's file is there, and it opens.
    let mut b = Engine::join(&lab.b_home, "desk", PASS, &key, lab.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("vault", &lab.b_dir, true).unwrap();
    assert_eq!(b.strongroom_keys("vault").unwrap().len(), 2);
    let spare_name = spare.path.file_name().unwrap();
    fs::copy(&spare.path, lab.b_home.join(spare_name)).unwrap();
    b.unlock_strongroom_enrolled("vault", 5).unwrap();
    b.pull("vault").unwrap();
    b.fetch_file("vault", "deed.pdf").unwrap();
    assert_eq!(fs::read(lab.b_dir.join("deed.pdf")).unwrap(), b"title deed");
    b.lock_strongroom("vault").unwrap();
    // Either key opens it.
    a.unlock_strongroom("vault", &spare, 5).unwrap();
    a.lock_strongroom("vault").unwrap();
    a.unlock_strongroom("vault", &first, 5).unwrap();

    // Removing the first key; the last one can never go.
    let gone = a.remove_strongroom_key("vault", "1").unwrap();
    assert_eq!(gone.credential, keys[0].credential);
    assert!(a.remove_strongroom_key("vault", "safe").is_err());
    assert_eq!(a.strongroom_keys("vault").unwrap().len(), 1);
    a.lock_strongroom("vault").unwrap();
    assert!(a.unlock_strongroom("vault", &first, 5).is_err());
    a.unlock_strongroom("vault", &spare, 5).unwrap();

    // B learns the new list on its next sync; a new device reads it from
    // the rewritten folder record.
    b.sync(None).unwrap();
    assert_eq!(b.strongroom_keys("vault").unwrap().len(), 1);
    fs::copy(
        lab.a_home.join("software-security-key"),
        lab.b_home.join("software-security-key"),
    )
    .unwrap();
    let only_first = SoftwareKey {
        path: lab.b_home.join("software-security-key"),
    };
    assert!(b.unlock_strongroom("vault", &only_first, 5).is_err());
    let c_home = lab.root.join("c-home");
    let c = Engine::join(&c_home, "tablet", PASS, &key, lab.storage.clone()).unwrap();
    let ck = c.strongroom_keys("vault").unwrap();
    assert_eq!(ck.len(), 1);
    assert_eq!(ck[0].label, "safe");
}

#[test]
fn rekeying_a_strongroom_re_encrypts_it_under_a_new_key_for_every_enrolled_key() {
    let lab = lab();
    let (mut a, key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    let first = SoftwareKey {
        path: lab.a_home.join("software-security-key"),
    };
    a.create_strongroom("vault", &lab.a_dir, Method::Software, &first, 15)
        .unwrap();
    fs::write(lab.a_dir.join("deed.pdf"), b"title deed").unwrap();
    fs::write(lab.a_dir.join("big.bin"), pseudo_random(120_000, 7)).unwrap();
    a.push("vault").unwrap();
    let spare = varsto_core::strongroom::new_software_key(&lab.a_home);
    a.add_strongroom_key("vault", Method::Software, &spare, "safe")
        .unwrap();

    let mut b = Engine::join(&lab.b_home, "desk", PASS, &key, lab.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("vault", &lab.b_dir, true).unwrap();
    let spare_name = spare.path.file_name().unwrap().to_owned();
    fs::copy(&spare.path, lab.b_home.join(&spare_name)).unwrap();
    b.unlock_strongroom_enrolled("vault", 5).unwrap();
    b.pull("vault").unwrap();
    b.fetch_file("vault", "deed.pdf").unwrap();
    b.lock_strongroom("vault").unwrap();

    let storage = lab.root.join("storage");
    let old_id = a.folders()[0].0.folder_id.clone();
    let old_chunks = objects(&storage, "chunks");
    let old_wraps = objects(&storage, &format!("vault/strongroom-keys/{old_id}"));
    assert!(!old_wraps.is_empty());

    // Re-key with the software keys in A's directory (both enrolled keys).
    let r = a.rekey_strongroom("vault", 15).unwrap();
    assert_eq!(r.files, 2, "{r:?}");
    assert!(r.cleanup.failures.is_empty(), "{:?}", r.cleanup);
    assert_ne!(r.folder_id, old_id.to_string());
    let (rec, _) = a.folders().into_iter().next().unwrap();
    assert!(rec.is_strongroom() && rec.key_hex.is_empty());
    assert_eq!(rec.name, "vault");
    let keys = a.strongroom_keys("vault").unwrap();
    assert_eq!(keys.len(), 2, "both keys still open it");
    assert_eq!(keys[1].label, "safe");
    // Old ciphertext and old key wraps are gone from the storage.
    assert!(objects(&storage, "chunks").is_disjoint(&old_chunks));
    assert!(objects(&storage, &format!("manifests/{old_id}")).is_empty());
    assert!(objects(&storage, &format!("vault/strongroom-keys/{old_id}")).is_empty());
    // A keeps working under the new key.
    assert_eq!(fs::read(lab.a_dir.join("deed.pdf")).unwrap(), b"title deed");
    fs::write(lab.a_dir.join("after.txt"), b"after the re-key").unwrap();
    a.push("vault").unwrap();
    a.lock_strongroom("vault").unwrap();
    a.unlock_strongroom("vault", &first, 5).unwrap();
    a.lock_strongroom("vault").unwrap();
    a.unlock_strongroom("vault", &spare, 5).unwrap();

    // B adopts the new folder on its next sync (locked), and its copy of
    // the spare key opens it.
    b.sync(None).unwrap();
    let folders = b.folders();
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0].0.folder_id.to_string(), r.folder_id);
    assert!(b.strongroom_conversions().is_empty());
    assert!(!lab.b_dir.join("deed.pdf").exists(), "plain copy left on B");
    assert!(b.pull("vault").is_err(), "locked on B");
    b.unlock_strongroom_enrolled("vault", 5).unwrap();
    b.pull("vault").unwrap();
    for (f, want) in [
        ("deed.pdf", b"title deed".to_vec()),
        ("big.bin", pseudo_random(120_000, 7)),
        ("after.txt", b"after the re-key".to_vec()),
    ] {
        b.fetch_file("vault", f).unwrap();
        assert_eq!(fs::read(lab.b_dir.join(f)).unwrap(), want, "{f}");
    }
    // Re-keying a folder that is not a Strongroom is refused.
    a.add_folder("plain", &lab.root.join("plain")).unwrap();
    assert!(a.rekey_strongroom("plain", 5).is_err());
}
