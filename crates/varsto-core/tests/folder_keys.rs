// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Storage format 2, section 4: folder keys reach a device only as grants.
//! A device that joins with the vault words sees every folder's name and
//! size but no content until an owner approves its request by hand; one
//! owner device is enough; a denied request gives nothing; a revoked device
//! gets no new key; a device of the vault cannot hand out a key of its own.

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

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
    fn home(&self, who: &str) -> PathBuf {
        self.root.join(format!("{who}-home"))
    }
    fn dir(&self, who: &str) -> PathBuf {
        self.root.join(format!("{who}-docs"))
    }
}

fn small(mut e: Engine) -> Engine {
    e.chunker = ChunkerParams::SMALL;
    e
}

fn read(dir: &Path, name: &str) -> Option<Vec<u8>> {
    fs::read(dir.join(name)).ok()
}

/// A with folder "docs" holding a file, and the vault key.
fn owner(lab: &Lab) -> (Engine, String) {
    let (a, key) = Engine::init(&lab.home("a"), "laptop", PASS).unwrap();
    let mut a = small(a);
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.dir("a")).unwrap();
    fs::write(lab.dir("a").join("plan.txt"), b"the secret plan").unwrap();
    a.sync(None).unwrap();
    (a, key)
}

fn join(lab: &Lab, who: &str, key: &str) -> Engine {
    let mut e = small(Engine::join(&lab.home(who), who, PASS, key, lab.storage.clone()).unwrap());
    e.sync(None).unwrap();
    e
}

#[test]
fn the_vault_words_give_names_and_sizes_but_no_content() {
    let lab = Lab::new();
    let (mut a, key) = owner(&lab);
    let mut b = join(&lab, "b", &key);
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    // B knows the folder by name and size.
    let st = b.status().unwrap();
    assert_eq!(st.folders_without_key, vec!["docs".to_string()]);
    let docs = st.folders.iter().find(|f| f.name == "docs").unwrap();
    assert!(docs.bytes > 0, "{docs:?}");
    // No key: nothing to attach, read or decrypt.
    let err = b.attach_folder("docs", &lab.dir("b"), false).unwrap_err();
    assert!(err.to_string().contains("varsto folder request"), "{err}");
    assert!(b.read_file("docs", "plan.txt").is_err());
    let rec = b
        .folders()
        .into_iter()
        .find(|(r, _)| r.name == "docs")
        .unwrap()
        .0;
    assert!(rec.key_hex.is_empty());
    assert!(!rec.key_check.is_empty());
    // The published folder record carries no key either.
    for e in walkdir::WalkDir::new(lab.root.join("storage/vault/folders"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let blob = fs::read(e.path()).unwrap();
        let env = varsto_core::record::SignedRecord::parse(&blob).unwrap();
        assert_eq!(env.kind.as_str(), "folder");
    }
}

#[test]
fn a_request_approved_on_one_owner_device_gives_the_content() {
    let lab = Lab::new();
    let (mut a, key) = owner(&lab);
    let mut b = join(&lab, "b", &key);
    b.folder_request("docs").unwrap();
    // The background service would only show it: the request waits.
    a.sync(None).unwrap();
    let reqs = a.folder_requests().unwrap();
    assert_eq!(reqs.len(), 1, "{reqs:?}");
    assert_eq!(reqs[0].folder, "docs");
    assert_eq!(reqs[0].device_id, b.device_id().to_string());
    assert_eq!(a.status().unwrap().folder_requests.len(), 1);
    b.sync(None).unwrap();
    assert!(b.attach_folder("docs", &lab.dir("b"), false).is_err());
    // Approved by hand on A: B reads the folder.
    let r = a
        .folder_approve("docs", b.device_id().as_str(), false)
        .unwrap();
    assert!(!r.read_only);
    assert!(a.folder_requests().unwrap().is_empty());
    b.sync(None).unwrap();
    b.attach_folder("docs", &lab.dir("b"), false).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("b"), "plan.txt").as_deref(),
        Some(&b"the secret plan"[..])
    );
    // And writes it: A takes B's change.
    fs::write(lab.dir("b").join("from-b.txt"), b"hello").unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("a"), "from-b.txt").as_deref(),
        Some(&b"hello"[..])
    );
    // B, an owner now, can grant C in turn.
    let mut c = join(&lab, "c", &key);
    c.folder_request("docs").unwrap();
    b.sync(None).unwrap();
    assert_eq!(b.folder_requests().unwrap().len(), 1);
    b.folder_approve("docs", "c", false).unwrap();
    c.sync(None).unwrap();
    c.attach_folder("docs", &lab.dir("c"), false).unwrap();
    c.sync(None).unwrap();
    assert!(read(&lab.dir("c"), "plan.txt").is_some());
}

#[test]
fn a_denied_request_gives_nothing() {
    let lab = Lab::new();
    let (mut a, key) = owner(&lab);
    let mut b = join(&lab, "b", &key);
    b.folder_request("docs").unwrap();
    a.sync(None).unwrap();
    assert_eq!(a.folder_requests().unwrap().len(), 1);
    a.folder_deny("docs", b.device_id().as_str()).unwrap();
    assert!(a.folder_requests().unwrap().is_empty());
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(b.attach_folder("docs", &lab.dir("b"), false).is_err());
    assert_eq!(
        b.status().unwrap().folders_without_key,
        vec!["docs".to_string()]
    );
}

#[test]
fn a_read_only_approval_takes_nothing_from_the_device() {
    let lab = Lab::new();
    let (mut a, key) = owner(&lab);
    let mut b = join(&lab, "b", &key);
    b.folder_request("docs").unwrap();
    a.sync(None).unwrap();
    let r = a.folder_approve("docs", "b", true).unwrap();
    assert!(r.read_only);
    b.sync(None).unwrap();
    b.attach_folder("docs", &lab.dir("b"), false).unwrap();
    b.sync(None).unwrap();
    assert!(read(&lab.dir("b"), "plan.txt").is_some());
    // B's own client keeps its changes aside; a modified client that
    // publishes anyway is refused by A.
    // (Pulled files arrive without write permission.)
    assert!(fs::write(lab.dir("b").join("plan.txt"), b"overwritten by b").is_err());
    b.disable_read_only_guard();
    fs::write(lab.dir("b").join("from-viewer.txt"), b"a viewer's file").unwrap();
    b.sync(None).unwrap();
    let r = a.sync(None).unwrap();
    assert!(read(&lab.dir("a"), "from-viewer.txt").is_none());
    assert!(r.iter().any(|(p, _)| !p.writes_refused.is_empty()), "{r:?}");
    // A viewer cannot grant the folder on.
    let mut c = join(&lab, "c", &key);
    c.folder_request("docs").unwrap();
    b.sync(None).unwrap();
    assert!(b.folder_approve("docs", "c", false).is_err());
}

#[test]
fn a_grant_of_a_key_that_is_not_the_folders_is_refused() {
    // A device holding the vault key but not the folder (B) "grants" C a
    // key of its own making for the folder: C refuses it, since it does not
    // match the key check the folder's creator signed.
    let lab = Lab::new();
    let (mut a, key) = owner(&lab);
    let mut b = join(&lab, "b", &key);
    let mut c = join(&lab, "c", &key);
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    let fid = b
        .folders()
        .into_iter()
        .find(|(r, _)| r.name == "docs")
        .unwrap()
        .0
        .folder_id
        .clone();
    b.forge_folder_grant_for_tests(&fid, c.device_id()).unwrap();
    c.sync(None).unwrap();
    assert_eq!(
        c.status().unwrap().folders_without_key,
        vec!["docs".to_string()]
    );
    assert!(c.attach_folder("docs", &lab.dir("c"), false).is_err());
}

#[test]
fn a_revoked_device_gets_no_new_key() {
    let lab = Lab::new();
    let (mut a, key) = owner(&lab);
    let mut b = join(&lab, "b", &key);
    let mut c = join(&lab, "c", &key);
    Engine::grant_all_for_tests(&mut a, &mut b).unwrap();
    Engine::grant_all_for_tests(&mut a, &mut c).unwrap();
    b.attach_folder("docs", &lab.dir("b"), false).unwrap();
    c.attach_folder("docs", &lab.dir("c"), false).unwrap();
    b.sync(None).unwrap();
    c.sync(None).unwrap();
    a.sync(None).unwrap();
    // A removes C: the folder C held gets a new key, granted to B only.
    let r = a.revoke_device("c", false).unwrap();
    assert!(r.folders_rekeyed.contains(&"docs".to_string()), "{r:?}");
    fs::write(lab.dir("a").join("after.txt"), b"after c left").unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("b"), "after.txt").as_deref(),
        Some(&b"after c left"[..])
    );
    let grants = lab.root.join("storage/vault/grants");
    let to_c: Vec<_> = walkdir::WalkDir::new(&grants)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            e.path()
                .parent()
                .and_then(|p| p.file_name())
                .is_some_and(|n| n == c.device_id().as_str())
        })
        .map(|e| {
            e.path()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .parse::<u32>()
                .unwrap()
        })
        .collect();
    assert!(!to_c.is_empty());
    assert!(to_c.iter().all(|e| *e == 0), "{to_c:?}");
    // A request C makes now is not shown to anyone.
    let _ = c.folder_request("docs");
    a.sync(None).unwrap();
    assert!(a.folder_requests().unwrap().is_empty());
}

#[test]
fn a_device_without_the_folder_cannot_start_an_epoch_of_it() {
    // B holds the vault key but not "docs"; C holds "docs". B starts an
    // epoch of "docs" with a key of its own and grants it to C: C refuses
    // it, as B cannot prove it holds the folder.
    let lab = Lab::new();
    let (mut a, key) = owner(&lab);
    let mut b = join(&lab, "b", &key);
    let mut c = join(&lab, "c", &key);
    Engine::grant_all_for_tests(&mut a, &mut c).unwrap();
    b.sync(None).unwrap();
    let fid = b
        .folders()
        .into_iter()
        .find(|(r, _)| r.name == "docs")
        .unwrap()
        .0
        .folder_id
        .clone();
    b.forge_folder_epoch_for_tests(&fid, c.device_id()).unwrap();
    c.sync(None).unwrap();
    let rec = c
        .folders()
        .into_iter()
        .find(|(r, _)| r.name == "docs")
        .unwrap()
        .0;
    assert!(rec.epoch_keys.is_empty(), "C adopted a forged epoch");
}

#[test]
fn pairing_gives_only_the_folders_chosen_on_the_offering_device() {
    let lab = Lab::new();
    let (mut a, _key) = owner(&lab);
    a.add_folder("photos", &lab.root.join("a-photos")).unwrap();
    fs::write(lab.root.join("a-photos/cat.jpg"), b"not really a cat").unwrap();
    a.sync(None).unwrap();
    // A offers; the person there chooses "docs" only.
    let offer = varsto_core::pair::Offer::start(a.pairing_bundle().unwrap()).unwrap();
    let code = offer.status().code;
    let addr = format!("127.0.0.1:{}", offer.status().port);
    let received = varsto_core::pair::receive(&code, "phone", Some(&addr)).unwrap();
    let mut joiner = None;
    for _ in 0..50 {
        let st = offer.status();
        if !st.open {
            joiner = st.joiner;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let joiner = joiner.expect("the joining device identified itself");
    let (b, _) = Engine::join_paired(&lab.home("b"), "phone", PASS, received).unwrap();
    let mut b = small(b);
    assert_eq!(b.device_id().to_string(), joiner.device_id);
    let given = a
        .grant_paired(&joiner, &["docs".to_string()], false)
        .unwrap();
    assert_eq!(given, vec!["docs".to_string()]);
    b.sync(None).unwrap();
    assert_eq!(
        b.status().unwrap().folders_without_key,
        vec!["photos".to_string()]
    );
    b.attach_folder("docs", &lab.dir("b"), false).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("b"), "plan.txt").as_deref(),
        Some(&b"the secret plan"[..])
    );
    assert!(b
        .attach_folder("photos", &lab.root.join("b-photos"), false)
        .is_err());
}

#[test]
fn an_organization_approval_can_carry_folders() {
    let lab = Lab::new();
    let (mut a, _key) = owner(&lab);
    a.org_create("Acme", "alice").unwrap();
    a.sync(None).unwrap();
    let code = varsto_core::org::OrgRequest::code_for(&lab.home("d"), Some("d")).unwrap();
    let approved = a
        .org_approve_folders(&code, "dana", None, &["docs".to_string()])
        .unwrap();
    assert_eq!(approved.folders, vec!["docs".to_string()]);
    let (d, _, _) = Engine::org_join(&lab.home("d"), "d", PASS, &approved.token).unwrap();
    let mut d = small(d);
    d.sync(None).unwrap();
    d.attach_folder("docs", &lab.dir("d"), false).unwrap();
    d.sync(None).unwrap();
    assert!(read(&lab.dir("d"), "plan.txt").is_some());
}

#[test]
fn vault_and_recovery_words_restore_every_folder_and_vault_words_alone_none() {
    let lab = Lab::new();
    let (a, key, recovery) = Engine::init_with_recovery(&lab.home("a"), "laptop", PASS).unwrap();
    let mut a = small(a);
    a.add_storage(lab.storage.clone()).unwrap();
    // Added while the recovery key is in this session: escrowed at once.
    a.add_folder("docs", &lab.dir("a")).unwrap();
    fs::write(lab.dir("a").join("plan.txt"), b"the secret plan").unwrap();
    a.add_folder("photos", &lab.root.join("a-photos")).unwrap();
    fs::write(lab.root.join("a-photos/cat.jpg"), b"a cat").unwrap();
    a.sync(None).unwrap();
    assert!(a.status().unwrap().folders_without_escrow.is_empty());
    // A second device, then removed: "docs" gets a new key epoch, escrowed
    // too (the recovery key is still in A's session).
    let mut b = join(&lab, "b", &key);
    Engine::grant_all_for_tests(&mut a, &mut b).unwrap();
    let r = a.revoke_device("b", false).unwrap();
    assert!(r.folders_rekeyed.contains(&"docs".to_string()), "{r:?}");
    fs::write(lab.dir("a").join("after.txt"), b"under the new folder key").unwrap();
    a.sync(None).unwrap();
    assert!(a.status().unwrap().folders_without_escrow.is_empty());
    let current = a.export_vault_key().unwrap();
    // Every device is lost.
    drop(a);
    drop(b);
    fs::remove_dir_all(lab.home("a")).unwrap();
    fs::remove_dir_all(lab.home("b")).unwrap();
    // The vault words alone: names, no content.
    let mut c = join(&lab, "c", &current);
    let mut missing = c.status().unwrap().folders_without_key;
    missing.sort();
    assert_eq!(missing, vec!["docs".to_string(), "photos".to_string()]);
    assert!(c.attach_folder("docs", &lab.dir("c"), false).is_err());
    // Wrong recovery words are refused.
    assert!(c
        .recover_folders(&varsto_core::crypto::SecretKey::random().to_hex())
        .is_err());
    // The vault words and the recovery words: everything.
    let mut d = join(&lab, "d", &current);
    let rep = d.recover_folders(&recovery).unwrap();
    assert!(rep.missing.is_empty(), "{rep:?}");
    d.attach_folder("docs", &lab.dir("d"), false).unwrap();
    d.attach_folder("photos", &lab.root.join("d-photos"), false)
        .unwrap();
    d.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("d"), "plan.txt").as_deref(),
        Some(&b"the secret plan"[..])
    );
    assert_eq!(
        read(&lab.dir("d"), "after.txt").as_deref(),
        Some(&b"under the new folder key"[..])
    );
    assert_eq!(
        read(&lab.root.join("d-photos"), "cat.jpg").as_deref(),
        Some(&b"a cat"[..])
    );
}

#[test]
fn a_folder_without_a_recovery_copy_is_reported_until_one_is_written() {
    let lab = Lab::new();
    let (mut a, _key) = owner(&lab);
    a.sync(None).unwrap();
    // Made without the recovery key in the session: no copy yet.
    assert_eq!(
        a.status().unwrap().folders_without_escrow,
        vec!["docs".to_string()]
    );
    let rk = varsto_core::crypto::SecretKey::random().to_hex();
    a.set_recovery_key(&rk).unwrap();
    assert_eq!(a.write_escrows().unwrap(), 1);
    assert!(a.status().unwrap().folders_without_escrow.is_empty());
    // Another set of words is not this vault's any more.
    let mut again = Engine::open(&lab.home("a"), PASS).unwrap();
    assert!(again
        .set_recovery_key(&varsto_core::crypto::SecretKey::random().to_hex())
        .is_err());
    again.set_recovery_key(&rk).unwrap();
}
