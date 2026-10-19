// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The switch to storage format 3 end to end (`docs/spec/format-3-design.md`,
//! the minimal path of work package 12): a vault made by `init`, a folder
//! added (folder record, grant to itself, escrow), a push (packs per target
//! set, a map delta, a manifest delta, one batch), a second device that
//! joins with the vault words and sees names but no content until an owner
//! approves its request, then pulls every file byte-identical; trash and
//! version history across the two devices; `fsck` clean; status from
//! `held`; refusals of a format-2 vault both ways.

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for e in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if e.file_type().is_file() {
            let rel = e
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel.starts_with(".varsto") {
                continue;
            }
            out.insert(rel, fs::read(e.path()).unwrap());
        }
    }
    out
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

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    storage: StorageSpec,
}

impl Lab {
    fn new() -> Lab {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        Lab {
            storage: StorageSpec::LocalDir {
                name: "box".into(),
                path: root.join("storage"),
                cold: false,
                carrier: false,
                place: String::new(),
                min_free: None,
            },
            root,
            _tmp: tmp,
        }
    }
    fn p(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

fn open(home: &Path) -> Engine {
    let mut e = Engine::open(home, PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e
}

/// Every object name under a storage directory, relative.
fn names(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for e in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        out.push(
            e.path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/"),
        );
    }
    out.sort();
    out
}

/// A: init, storage, folder "docs" with three files (one duplicate), push.
fn first_device(lab: &Lab) -> (Engine, String) {
    let (mut a, key) = Engine::init(&lab.p("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    // The kit names both word sets; the recovery key is this session's.
    let kit = a.recovery_kit_text().unwrap();
    assert!(kit.to_lowercase().contains("recovery"), "{kit}");
    a.add_storage(lab.storage.clone()).unwrap();
    let docs = lab.p("a-docs");
    a.add_folder("docs", &docs).unwrap();
    fs::create_dir_all(docs.join("sub")).unwrap();
    fs::write(docs.join("hello.txt"), b"hello from a").unwrap();
    fs::write(docs.join("sub/big.bin"), pseudo_random(150_000, 3)).unwrap();
    fs::write(docs.join("copy.bin"), pseudo_random(150_000, 3)).unwrap();
    let push = a.push("docs").unwrap();
    assert_eq!(push.files_changed, 3);
    assert!(push.chunks_uploaded > 1, "{push:?}");
    assert_eq!(push.manifest_seq, Some(1));
    assert!(push.batch_seq.is_some());
    (a, key)
}

/// B joins with the vault words, asks for "docs" and A approves.
fn second_device(lab: &Lab, a: &mut Engine, key: &str) -> Engine {
    let mut b = Engine::join(&lab.p("b-home"), "phone", PASS, key, lab.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    let req = b.f3_folder_request("docs", "editor").unwrap();
    let pending = a.f3_requests(None).unwrap();
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert_eq!(pending[0].device, "phone");
    assert_eq!(pending[0].fingerprint, req.fingerprint);
    a.f3_approve("docs", "phone", None, Some(&req.fingerprint))
        .unwrap();
    b.sync(None).unwrap();
    b.attach_folder("docs", &lab.p("b-docs"), false).unwrap();
    b
}

#[test]
fn a_second_device_reads_every_file_after_approval() {
    let lab = Lab::new();
    let (mut a, key) = first_device(&lab);

    // What the storage holds is format 3: packs of size classes, signed
    // records; no block objects, pack indexes or tombstone lists.
    let store = lab.p("storage");
    let meta: serde_json::Value =
        serde_json::from_slice(&fs::read(store.join("vault/meta.json")).unwrap()).unwrap();
    assert_eq!(meta["format_version"], 3);
    let objects = names(&store);
    assert!(
        objects.iter().any(|n| n.starts_with("packs/")),
        "{objects:?}"
    );
    assert!(
        objects.iter().any(|n| n.starts_with("maps/")),
        "{objects:?}"
    );
    assert!(objects
        .iter()
        .any(|n| n.starts_with("manifests/") && n.ends_with(".rec")));
    assert!(objects
        .iter()
        .any(|n| n.starts_with("ledger/") && n.ends_with(".rec")));
    assert!(objects.iter().any(|n| n.starts_with("vault/devices/")));
    assert!(objects.iter().any(|n| n.starts_with("vault/folders/")));
    assert!(objects.iter().any(|n| n.starts_with("vault/grants/")));
    assert!(objects.iter().any(|n| n.starts_with("vault/escrow/")));
    assert!(
        !objects.iter().any(|n| n.starts_with("chunks/")),
        "{objects:?}"
    );
    assert!(!objects.iter().any(|n| n.starts_with("packs/index/")));
    assert!(!objects.iter().any(|n| n.starts_with("packs/tombstones/")));
    for (path, _) in common::pack_files(&store) {
        let len = fs::metadata(path).unwrap().len();
        assert!(varsto_core::packs::is_class(len), "a pack of {len} bytes");
    }
    // Every folder epoch has its recovery copy: no warning.
    assert!(a.f3_missing_escrows().unwrap().is_empty());
    // A goes offline; it is opened again with its passphrase later.
    drop(a);
    let mut a = open(&lab.p("a-home"));

    // B joins with the vault words: it sees the folder and the laptop, and
    // opens nothing until an owner approves it.
    let mut b = Engine::join(&lab.p("b-home"), "phone", PASS, &key, lab.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    assert_eq!(b.folders().len(), 1);
    let names: Vec<String> = b.status().unwrap().devices.into_values().collect();
    assert!(names.contains(&"laptop".to_string()), "{names:?}");
    let refused = b
        .attach_folder("docs", &lab.p("b-docs"), false)
        .unwrap_err()
        .to_string();
    assert!(refused.contains("folder request"), "{refused}");
    let req = b.f3_folder_request("docs", "editor").unwrap();
    // A sees the request with the same six words, and approves.
    let pending = a.f3_requests(None).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].fingerprint, req.fingerprint);
    a.f3_approve("docs", "phone", None, Some(&req.fingerprint))
        .unwrap();
    b.sync(None).unwrap();
    b.attach_folder("docs", &lab.p("b-docs"), false).unwrap();
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.files_updated, 3, "{pull:?}");
    assert!(pull.files_unavailable.is_empty(), "{pull:?}");
    assert_eq!(tree(&lab.p("a-docs")), tree(&lab.p("b-docs")));

    // B changes, deletes and adds; A takes it.
    fs::write(lab.p("b-docs/hello.txt"), b"hello from b").unwrap();
    fs::remove_file(lab.p("b-docs/copy.bin")).unwrap();
    fs::write(lab.p("b-docs/new.txt"), b"new on b").unwrap();
    let push = b.push("docs").unwrap();
    assert_eq!(push.files_changed, 3);
    let pull = a.pull("docs").unwrap();
    assert_eq!(pull.files_updated + pull.files_deleted, 3, "{pull:?}");
    assert_eq!(tree(&lab.p("a-docs")), tree(&lab.p("b-docs")));

    // Status: every block of the folder has a copy on the storage, and
    // the other device's copy counts through its `held` flags.
    let st = a.status().unwrap();
    let docs = &st.folders[0];
    assert_eq!(docs.files, 3);
    assert_eq!(docs.chunks_without_storage_copy, 0, "{docs:?}");
    assert_eq!(docs.protection.state, "disks", "{:?}", docs.protection);
    assert_eq!(docs.protection.devices.pct, 100.0);

    // fsck finds nothing wrong on either device.
    let f = a.fsck(true).unwrap();
    let f3 = f.format3.as_ref().unwrap();
    assert!(f3.is_clean(), "{}", f3.describe());
    assert!(f3.copies_verified_now > 0);
    let f = b.fsck(false).unwrap();
    assert!(f.format3.as_ref().unwrap().is_clean());
}

#[test]
fn trash_and_version_history_work_across_devices() {
    let lab = Lab::new();
    let (mut a, key) = first_device(&lab);
    let mut b = second_device(&lab, &mut a, &key);
    // A file whose content is nowhere else in the folder (a deletion of a
    // file that has a copy is a rename).
    let report = pseudo_random(120_000, 9);
    fs::write(lab.p("a-docs/sub/report.bin"), &report).unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert_eq!(fs::read(lab.p("b-docs/sub/report.bin")).unwrap(), report);

    // Deleted on A: the entry is in B's trash, B applies the deletion and
    // restores the file from the blocks on the storage.
    fs::remove_file(lab.p("a-docs/sub/report.bin")).unwrap();
    a.sync(None).unwrap();
    let list = b.trash_list(None).unwrap();
    assert_eq!(list.len(), 1, "{list:?}");
    assert_eq!(list[0].path, "sub/report.bin");
    assert_eq!(list[0].deleted_by, "laptop");
    assert!(list[0].storages.contains(&"box".to_string()), "{list:?}");
    b.sync(None).unwrap();
    assert!(!lab.p("b-docs/sub/report.bin").exists());
    fs::remove_dir_all(lab.p("b-home").join("trash")).unwrap();
    let r = b
        .trash_restore("docs", &["sub/report.bin".to_string()], None, false)
        .unwrap();
    assert_eq!(r.restored.len(), 1, "{r:?}");
    assert_eq!(r.from_storages, 1);
    assert_eq!(fs::read(lab.p("b-docs/sub/report.bin")).unwrap(), report);
    assert!(b.trash_list(None).unwrap().is_empty());
    a.sync(None).unwrap();
    assert_eq!(fs::read(lab.p("a-docs/sub/report.bin")).unwrap(), report);
    assert!(a.trash_list(None).unwrap().is_empty());

    // Versions: A writes hello.txt twice; B lists the replaced version
    // and brings it back.
    fs::write(lab.p("a-docs/hello.txt"), b"second version").unwrap();
    a.sync(None).unwrap();
    fs::write(lab.p("a-docs/hello.txt"), b"third version").unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        fs::read(lab.p("b-docs/hello.txt")).unwrap(),
        b"third version"
    );
    let h = b.history_list("docs", "hello.txt").unwrap();
    assert!(h.versions.len() >= 2, "{h:?}");
    let oldest = h.versions.last().unwrap().id.clone();
    let r = b
        .history_restore(
            "docs",
            "hello.txt",
            &oldest,
            &varsto_core::engine::HistoryTarget {
                to: None,
                as_name: Some("hello-v1.txt".into()),
            },
            false,
        )
        .unwrap();
    assert_eq!(r.to, "hello-v1.txt", "{r:?}");
    assert_eq!(
        fs::read(lab.p("b-docs/hello-v1.txt")).unwrap(),
        b"hello from a"
    );
    // The restored version reaches A as a new file.
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    assert_eq!(
        fs::read(lab.p("a-docs/hello-v1.txt")).unwrap(),
        b"hello from a"
    );
}

#[test]
fn a_format_2_vault_is_refused_both_ways() {
    let lab = Lab::new();
    // A storage that holds a format-2 vault: this build does not mix them.
    let store = lab.p("storage");
    fs::create_dir_all(store.join("vault")).unwrap();
    fs::write(
        store.join("vault/meta.json"),
        br#"{"format_version": 2, "vault_id": "00112233445566778899aabbccddeeff", "created_utc": 1}"#,
    )
    .unwrap();
    let (mut a, _) = Engine::init(&lab.p("a-home"), "laptop", PASS).unwrap();
    let e = a.add_storage(lab.storage.clone()).unwrap_err().to_string();
    assert!(e.contains("holds a vault of format 2"), "{e}");
    // Joining a format-2 vault: the words are not even tried.
    let e = Engine::join(
        &lab.p("b-home"),
        "phone",
        PASS,
        &"00".repeat(32),
        lab.storage.clone(),
    )
    .err()
    .unwrap()
    .to_string();
    assert!(e.contains("storage format 2"), "{e}");
    assert!(e.contains("varsto reset --yes"), "{e}");
    // A device directory of format 2: refused when opened.
    let home = lab.p("old-home");
    fs::create_dir_all(&home).unwrap();
    let mut vault: serde_json::Value =
        serde_json::from_slice(&fs::read(lab.p("a-home").join("vault.json")).unwrap()).unwrap();
    vault["format_version"] = 2.into();
    fs::write(home.join("vault.json"), serde_json::to_vec(&vault).unwrap()).unwrap();
    let e = Engine::open(&home, PASS).err().unwrap().to_string();
    assert!(e.contains("storage format 2"), "{e}");
    // And the message an older build gives for a format-3 vault.
    let newer = varsto_core::format_mismatch(4);
    assert!(newer.contains("newer than this version"), "{newer}");
}

#[test]
fn the_vault_words_alone_restore_no_folder_and_the_recovery_words_restore_every_one() {
    let lab = Lab::new();
    let (a, key) = first_device(&lab);
    let words = a.recovery_kit_text().unwrap();
    drop(a);
    // Every device is lost. The vault words give the names, no content.
    let mut c = Engine::join(
        &lab.p("c-home"),
        "new laptop",
        PASS,
        &key,
        lab.storage.clone(),
    )
    .unwrap();
    c.chunker = ChunkerParams::SMALL;
    assert!(c.attach_folder("docs", &lab.p("c-docs"), false).is_err());
    // With the recovery words every folder opens again.
    let k1 = recovery_key_of(&words);
    let got = c.recover_folders(&k1).unwrap();
    assert_eq!(got, vec!["docs".to_string()]);
    c.attach_folder("docs", &lab.p("c-docs"), false).unwrap();
    let pull = c.pull("docs").unwrap();
    assert_eq!(pull.files_updated, 3, "{pull:?}");
    assert_eq!(tree(&lab.p("a-docs")), tree(&lab.p("c-docs")));
}

/// A device that recovered the folders through the escrow becomes their
/// owner once the lost devices are removed: it is the only holder left,
/// and it can then share the folder with a new device of its own.
#[test]
fn a_recovered_device_owns_the_folders_once_the_lost_ones_are_removed() {
    let lab = Lab::new();
    let (a, key) = first_device(&lab);
    let words = a.recovery_kit_text().unwrap();
    drop(a);
    let mut c = Engine::join(
        &lab.p("c-home"),
        "new laptop",
        PASS,
        &key,
        lab.storage.clone(),
    )
    .unwrap();
    c.chunker = ChunkerParams::SMALL;
    c.recover_folders(&recovery_key_of(&words)).unwrap();
    // While the lost device is still in the vault, C only reads.
    assert_eq!(
        c.f3_members("docs").unwrap().your_role.as_deref(),
        None,
        "not a participant yet"
    );
    let r = c.revoke_device("laptop", false).unwrap();
    assert_eq!(r.key_epoch, 1);
    assert_eq!(r.folders_rekeyed, vec!["docs".to_string()]);
    assert_eq!(
        c.f3_members("docs").unwrap().your_role.as_deref(),
        Some("owner")
    );
    // As owner it approves another device of its own, which reads and writes.
    let new_key = c.export_vault_key().unwrap();
    let mut d = common::join_approved(
        &lab.p("d-home"),
        "desk",
        PASS,
        &new_key,
        lab.storage.clone(),
        &mut c,
    );
    d.chunker = ChunkerParams::SMALL;
    d.attach_folder("docs", &lab.p("d-docs"), false).unwrap();
    d.sync(None).unwrap();
    assert_eq!(tree(&lab.p("a-docs")), tree(&lab.p("d-docs")));
    fs::write(lab.p("d-docs").join("after.txt"), b"after the recovery").unwrap();
    d.sync(None).unwrap();
    c.attach_folder("docs", &lab.p("c-docs"), false).unwrap();
    c.sync(None).unwrap();
    assert_eq!(
        fs::read(lab.p("c-docs").join("after.txt")).unwrap(),
        b"after the recovery"
    );
}

/// Recovering after the lost owner was removed: a device that joins with
/// the new vault words and recovers with the (unchanged) recovery words
/// reads what the removed owner wrote before its cut-off (its manifest and
/// block map), so every file arrives.
#[test]
fn recovering_after_the_lost_owner_was_removed_reads_its_records() {
    let lab = Lab::new();
    let (a, key) = first_device(&lab);
    let words = a.recovery_kit_text().unwrap();
    drop(a);
    let mut c = Engine::join(
        &lab.p("c-home"),
        "new laptop",
        PASS,
        &key,
        lab.storage.clone(),
    )
    .unwrap();
    c.chunker = ChunkerParams::SMALL;
    c.recover_folders(&recovery_key_of(&words)).unwrap();
    c.revoke_device("laptop", false).unwrap();
    let new_key = c.export_vault_key().unwrap();
    drop(c);
    // A later device: the new vault words and the recovery words.
    let mut e = Engine::join(
        &lab.p("e-home"),
        "spare",
        PASS,
        &new_key,
        lab.storage.clone(),
    )
    .unwrap();
    e.chunker = ChunkerParams::SMALL;
    let got = e.recover_folders(&recovery_key_of(&words)).unwrap();
    assert_eq!(got, vec!["docs".to_string()]);
    e.attach_folder("docs", &lab.p("e-docs"), false).unwrap();
    let pull = e.pull("docs").unwrap();
    assert_eq!(pull.files_updated, 3, "{pull:?}");
    assert_eq!(tree(&lab.p("a-docs")), tree(&lab.p("e-docs")));
}

/// The recovery key from the kit text: the 24 words after its heading.
fn recovery_key_of(kit: &str) -> varsto_core::membership3::RecoveryKey {
    let lines: Vec<&str> = kit.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.to_lowercase().contains("recovery words"))
        .unwrap_or_else(|| panic!("no recovery words in {kit}"));
    let words: Vec<&str> = lines[at + 1..]
        .iter()
        .flat_map(|l| l.split_whitespace())
        .filter(|w| w.chars().all(|c| c.is_ascii_lowercase()))
        .take(24)
        .collect();
    varsto_core::membership3::RecoveryKey::from_words(&words.join(" ")).unwrap()
}
