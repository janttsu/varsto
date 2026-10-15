// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Storage format 2, section 3: every record a device publishes is a signed
//! envelope, and a record that changes what another device sees counts only
//! when its writer signed it, may write it, and (manifests, trash records)
//! announced it in its own signed ledger. A storage that rewrites, replays
//! or relabels objects, and anyone who holds a folder key without being
//! its writer, changes nothing.

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::crypto::SigningKey;
use varsto_core::ids::FolderId;
use varsto_core::manifest::Manifest;
use varsto_core::record::SignedRecord;
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
    fn store(&self) -> PathBuf {
        self.root.join("storage")
    }
}

fn small(mut e: Engine) -> Engine {
    e.chunker = ChunkerParams::SMALL;
    e
}

/// A with folder "docs" holding one file, and a second device of the same
/// vault that holds the folder too.
fn two(lab: &Lab) -> (Engine, Engine, FolderId) {
    let (a, key) = Engine::init(&lab.home("a"), "a", PASS).unwrap();
    let mut a = small(a);
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.dir("a")).unwrap();
    fs::write(lab.dir("a").join("plan.txt"), b"the plan").unwrap();
    a.sync(None).unwrap();
    let b = Engine::join(&lab.home("b"), "b", PASS, &key, lab.storage.clone()).unwrap();
    let mut b = small(b);
    common::grant_folder(&mut a, &mut b, "docs");
    b.attach_folder("docs", &lab.dir("b"), false).unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("b"), "plan.txt").as_deref(),
        Some(&b"the plan"[..])
    );
    let fid = a.folders()[0].0.folder_id.clone();
    (a, b, fid)
}

mod common {
    use varsto_core::Engine;
    /// Give `to` the folder key the way the vault does it: a request from
    /// `to`, approved by hand on `from`.
    pub fn grant_folder(from: &mut Engine, to: &mut Engine, folder: &str) {
        to.sync(None).unwrap();
        from.sync(None).unwrap();
        to.sync(None).unwrap();
        to.folder_request(folder).unwrap();
        from.folder_approve(folder, to.device_id().as_str(), false)
            .unwrap();
        to.sync(None).unwrap();
    }
}

fn read(dir: &Path, name: &str) -> Option<Vec<u8>> {
    fs::read(dir.join(name)).ok()
}

fn manifest_dir(lab: &Lab, folder: &FolderId, device: &str) -> PathBuf {
    lab.store()
        .join("manifests")
        .join(folder.as_str())
        .join(device)
}

fn newest(dir: &Path) -> (u64, PathBuf) {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let n = e
                .path()
                .file_stem()?
                .to_string_lossy()
                .parse::<u64>()
                .ok()?;
            Some((n, e.path()))
        })
        .max()
        .unwrap()
}

/// Rewrite a stored record's JSON in place.
fn edit(path: &Path, f: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let orig = fs::read(path).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&orig).unwrap();
    f(&mut v);
    fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
    orig
}

#[test]
fn a_manifest_signed_by_anyone_else_is_refused() {
    let lab = Lab::new();
    let (mut a, mut b, fid) = two(&lab);
    // A publishes a new manifest; before B reads it, the storage (or anyone
    // holding the folder key) puts its own manifest under A's name and
    // number: same folder key, same header, another signer.
    fs::write(lab.dir("a").join("plan.txt"), b"the real change").unwrap();
    a.sync(None).unwrap();
    let (seq, path) = newest(&manifest_dir(&lab, &fid, a.device_id().as_str()));
    let genuine = fs::read(&path).unwrap();
    let env = SignedRecord::parse(&genuine).unwrap();
    assert_eq!(env.kind.as_str(), "manifest");
    let rec = b.folders()[0].0.clone();
    let fk = varsto_core::vault::FolderKeys::from_folder_key(
        &rec.folder_id,
        varsto_core::crypto::SecretKey::from_hex(&rec.key_hex).unwrap(),
    )
    .unwrap();
    let meta_for = |e: u32| fk.meta_key_for(e);
    let (mut m, _) = Manifest::open(
        &genuine,
        a.vault_id(),
        &fid,
        a.device_id(),
        seq,
        &a.device_public_key(),
        &meta_for,
    )
    .unwrap();
    m.files.get_mut("plan.txt").unwrap().deleted = true;
    m.files.get_mut("plan.txt").unwrap().chunks.clear();
    m.files.get_mut("plan.txt").unwrap().size = 0;
    m.files.get_mut("plan.txt").unwrap().content_hash.clear();
    let forger = SigningKey::generate();
    let forged = m
        .seal(a.vault_id(), 0, &fk.meta_key_for(0).unwrap(), &forger)
        .unwrap();
    fs::write(&path, forged.to_bytes()).unwrap();
    let r = b.sync(None).unwrap();
    assert!(r.iter().any(|(p, _)| !p.writes_refused.is_empty()), "{r:?}");
    assert_eq!(
        read(&lab.dir("b"), "plan.txt").as_deref(),
        Some(&b"the plan"[..])
    );
    // The genuine copy comes back: B takes it.
    fs::write(&path, &genuine).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("b"), "plan.txt").as_deref(),
        Some(&b"the real change"[..])
    );
}

#[test]
fn a_replayed_or_relabelled_manifest_is_refused() {
    let lab = Lab::new();
    let (mut a, mut b, fid) = two(&lab);
    let dir = manifest_dir(&lab, &fid, a.device_id().as_str());
    let (old_seq, old_path) = newest(&dir);
    let old = fs::read(&old_path).unwrap();
    fs::write(lab.dir("a").join("plan.txt"), b"second").unwrap();
    a.sync(None).unwrap();
    let (seq, path) = newest(&dir);
    assert!(seq > old_seq);
    // Replay: the older genuine manifest under the newer number.
    let genuine = fs::read(&path).unwrap();
    fs::write(&path, &old).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("b"), "plan.txt").as_deref(),
        Some(&b"the plan"[..])
    );
    // Relabelled: the genuine manifest with another key id or number.
    fs::write(&path, &genuine).unwrap();
    edit(&path, |v| v["key_id"] = "meta@1".into());
    b.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("b"), "plan.txt").as_deref(),
        Some(&b"the plan"[..])
    );
    fs::write(&path, &genuine).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("b"), "plan.txt").as_deref(),
        Some(&b"second"[..])
    );
}

#[test]
fn a_manifest_without_its_ledger_announcement_waits() {
    let lab = Lab::new();
    let (mut a, mut b, _fid) = two(&lab);
    fs::write(lab.dir("a").join("plan.txt"), b"announced later").unwrap();
    a.sync(None).unwrap();
    // The storage withholds A's newest batch (the one that announces the
    // manifest), everywhere.
    let ledger = lab.store().join("ledger").join(a.device_id().as_str());
    let (_, batch) = newest(&ledger);
    let held = fs::read(&batch).unwrap();
    fs::remove_file(&batch).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("b"), "plan.txt").as_deref(),
        Some(&b"the plan"[..])
    );
    // Even when the listing finds it: the manifest waits for its batch.
    let mut b = small(Engine::open(&lab.home("b"), PASS).unwrap());
    b.set_manifest_policy(varsto_core::engine::ManifestPolicy {
        sweep_secs: 0,
        prune: true,
    });
    let r = b.sync(None).unwrap();
    assert!(r.iter().any(|(p, _)| p.records_waiting > 0), "{r:?}");
    assert_eq!(
        read(&lab.dir("b"), "plan.txt").as_deref(),
        Some(&b"the plan"[..])
    );
    // Once the batch is there, the manifest counts.
    fs::write(&batch, held).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("b"), "plan.txt").as_deref(),
        Some(&b"announced later"[..])
    );
}

#[test]
fn a_relabelled_ledger_batch_is_refused() {
    let lab = Lab::new();
    let (mut a, mut b, _fid) = two(&lab);
    fs::write(lab.dir("a").join("plan.txt"), b"in a relabelled batch").unwrap();
    a.sync(None).unwrap();
    let ledger = lab.store().join("ledger").join(a.device_id().as_str());
    let (_, batch) = newest(&ledger);
    // The key id is signed (format 2): a storage that relabels a batch (to
    // make it unreadable, or to give it another scope) breaks it.
    let orig = edit(&batch, |v| v["key_id"] = "replica".into());
    b.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("b"), "plan.txt").as_deref(),
        Some(&b"the plan"[..])
    );
    assert!(b.ledger_health().batches_malformed > 0);
    fs::write(&batch, orig).unwrap();
    b.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("b"), "plan.txt").as_deref(),
        Some(&b"in a relabelled batch"[..])
    );
}

#[test]
fn a_trash_record_replayed_under_a_newer_name_is_refused() {
    let lab = Lab::new();
    let (mut a, mut b, fid) = two(&lab);
    fs::remove_file(lab.dir("a").join("plan.txt")).unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert_eq!(b.trash_list(Some("docs")).unwrap().len(), 1);
    // A's record, copied under a later time: the signed header names the
    // time it was written, so the copy is not A's record of that time.
    let tdir = lab
        .store()
        .join("vault/trash")
        .join(fid.as_str())
        .join(a.device_id().as_str());
    let (t, path) = newest(&tdir);
    let blob = fs::read(&path).unwrap();
    fs::write(tdir.join(format!("{:020}.enc", t + 1000)), &blob).unwrap();
    fs::remove_file(&path).unwrap();
    let env = SignedRecord::parse(&blob).unwrap();
    assert_eq!(env.kind.as_str(), "trash");
    assert_eq!(env.seq, t);
    // B already holds A's record; a fresh device reads only what verifies.
    let key = a.export_vault_key().unwrap();
    let mut c = small(Engine::join(&lab.home("c"), "c", PASS, &key, lab.storage.clone()).unwrap());
    common::grant_folder(&mut a, &mut c, "docs");
    c.sync(None).unwrap();
    assert!(c.trash_list(Some("docs")).unwrap().is_empty());
    // Put back under its own name: it counts.
    fs::write(&path, &blob).unwrap();
    let _ = fs::remove_file(tdir.join(format!("{:020}.enc", t + 1000)));
    let mut c = small(Engine::open(&lab.home("c"), PASS).unwrap());
    c.trash_reread().unwrap();
    assert_eq!(c.trash_list(Some("docs")).unwrap().len(), 1);
}

#[test]
fn a_peer_record_signed_by_another_key_is_ignored() {
    let lab = Lab::new();
    let (a, b, _fid) = two(&lab);
    let rec = a.peer_record_template(17893);
    a.publish_peer_record(&rec).unwrap();
    assert_eq!(b.peer_record_list().unwrap().len(), 1);
    // Someone with the registry key writes A's record with its own key
    // (pointing A's id at its own address and certificate).
    let path = lab
        .store()
        .join("vault/peers")
        .join(format!("{}.enc", a.device_id()));
    let genuine = fs::read(&path).unwrap();
    let env = SignedRecord::parse(&genuine).unwrap();
    assert_eq!(env.kind.as_str(), "peer");
    let forger = SigningKey::generate();
    let forged = env.header().sign_body(env.body_bytes().unwrap(), &forger);
    fs::write(&path, forged.to_bytes()).unwrap();
    assert!(b.peer_record_list().unwrap().is_empty());
    fs::write(&path, &genuine).unwrap();
    assert_eq!(b.peer_record_list().unwrap().len(), 1);
}

#[test]
fn a_relabelled_revocation_is_refused() {
    let lab = Lab::new();
    let (mut a, mut b, _fid) = two(&lab);
    let key = a.export_vault_key().unwrap();
    let mut c = small(Engine::join(&lab.home("c"), "c", PASS, &key, lab.storage.clone()).unwrap());
    c.sync(None).unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    // A removes C. The storage moves A's signed revocation to name B as
    // the removed device instead: the scope is signed, so nobody removes B.
    a.revoke_device("c", false).unwrap();
    let rdir = lab.store().join("vault/revocations");
    let from = rdir
        .join(c.device_id().as_str())
        .join(format!("{}.json", a.device_id()));
    let blob = fs::read(&from).unwrap();
    let to_dir = rdir.join(b.device_id().as_str());
    fs::create_dir_all(&to_dir).unwrap();
    let to = to_dir.join(format!("{}.json", a.device_id()));
    fs::write(&to, &blob).unwrap();
    edit(&to, |v| v["scope"] = b.device_id().to_string().into());
    b.sync(None).unwrap();
    assert!(b.removal().is_none());
    assert!(b.status().is_ok());
}
