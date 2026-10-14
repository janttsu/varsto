// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Device revocation, key rotation and remote wipe with three devices of one
//! vault (`docs/spec/alpha-0-format.md` section 20): A removes C, A and B keep
//! syncing under a new vault key, C's later batches are ignored, what is
//! written afterwards does not open with C's keys, a wipe order empties C,
//! and a wipe order not signed by a device of the vault is ignored.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::crypto::{self, SecretKey, SigningKey};
use varsto_core::engine::{DeviceRemoved, Revocation, SignedRevocation};
use varsto_core::ids::ChunkId;
use varsto_core::ledger::{self, SignedBatch};
use varsto_core::manifest::Manifest;
use varsto_core::storage::StorageSpec;
use varsto_core::vault::FolderKeys;
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

/// A creates the vault with one file; B and C join and sync it. Returns the
/// three engines and the original vault key.
fn three_devices(lab: &Lab) -> (Engine, Engine, Engine, String) {
    let (a, key) = Engine::init(&lab.home("a"), "a", PASS).unwrap();
    let mut a = small(a);
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.dir("a")).unwrap();
    fs::write(
        lab.dir("a").join("one.txt"),
        b"written before the revocation",
    )
    .unwrap();
    a.push("docs").unwrap();
    let mut others = Vec::new();
    for who in ["b", "c"] {
        let mut e =
            small(Engine::join(&lab.home(who), who, PASS, &key, lab.storage.clone()).unwrap());
        e.attach_folder("docs", &lab.dir(who), false).unwrap();
        e.sync(None).unwrap();
        assert!(lab.dir(who).join("one.txt").exists());
        others.push(e);
    }
    a.sync(None).unwrap();
    let c = others.pop().unwrap();
    let b = others.pop().unwrap();
    (a, b, c, key)
}

fn removed(e: &anyhow::Error) -> Option<&DeviceRemoved> {
    e.downcast_ref::<DeviceRemoved>()
}

/// The bytes of every block object on the storage (single or packed).
fn chunk_objects(store: &Path) -> Vec<Vec<u8>> {
    let objs: Vec<Vec<u8>> = common::object_names(store)
        .iter()
        .map(|n| common::read_object(store, n).unwrap())
        .collect();
    assert!(!objs.is_empty());
    objs
}

#[test]
fn revoked_device_is_cut_off_and_new_data_needs_new_keys() {
    let lab = Lab::new();
    let (mut a, mut b, mut c, old_key) = three_devices(&lab);
    assert_eq!(a.devices_list().len(), 3);

    // Guard rails.
    assert!(
        a.revoke_device("a", false).is_err(),
        "a device cannot remove itself"
    );
    assert!(a.revoke_device("nobody", false).is_err());

    let c_id = c.device_id().clone();
    let report = a.revoke_device("c", false).unwrap();
    assert_eq!(report.key_epoch, 1);
    assert_eq!(report.keys_sent_to, vec!["b".to_string()]);
    assert!(report.keys_pending_for.is_empty());
    assert_eq!(report.folders_rekeyed, vec!["docs".to_string()]);
    assert!(a.revoke_device("c", false).is_err(), "already removed");
    let listed = a.devices_list();
    assert!(listed.iter().any(|d| d.name == "c" && d.revoked));

    // C has not heard of it yet and keeps writing: its new batch and
    // manifest must not count anywhere.
    fs::write(
        lab.dir("c").join("from-c.txt"),
        b"written by the removed device",
    )
    .unwrap();
    c.push("docs").unwrap();

    // A and B keep syncing under the new vault key.
    let a_secret = b"written after the revocation by a";
    fs::write(lab.dir("a").join("after-a.txt"), a_secret).unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert_eq!(b.key_epoch(), 1, "B picked up the new vault key");
    assert_eq!(
        fs::read(lab.dir("b").join("after-a.txt")).unwrap(),
        a_secret
    );
    assert!(
        !lab.dir("b").join("from-c.txt").exists(),
        "C's later manifest is ignored"
    );
    let b_secret = b"written after the revocation by b";
    fs::write(lab.dir("b").join("after-b.txt"), b_secret).unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    assert_eq!(
        fs::read(lab.dir("a").join("after-b.txt")).unwrap(),
        b_secret
    );
    assert!(!lab.dir("a").join("from-c.txt").exists());
    let names: Vec<String> = b.status().unwrap().devices.into_values().collect();
    assert!(!names.contains(&"c".to_string()), "{names:?}");
    assert!(b.status().unwrap().revoked.contains_key(c_id.as_str()));

    // C's batches after the cut-off were never taken in.
    for e in [&a, &b] {
        let max_c = e
            .ledger_entries()
            .unwrap()
            .iter()
            .filter(|x| x.device == c_id.as_str())
            .map(|x| x.seq)
            .max()
            .unwrap_or(0);
        assert!(
            max_c <= report.cutoff_seq,
            "batch {max_c} of C was accepted"
        );
    }
    assert!(c
        .ledger_entries()
        .unwrap()
        .iter()
        .any(|x| x.device == c_id.as_str() && x.seq > report.cutoff_seq));

    // Everything C holds opens nothing written after the revocation.
    let vault = a.vault_id().clone();
    let (rec, _) = c.folders().into_iter().next().unwrap();
    let fk0 =
        FolderKeys::from_folder_key(&rec.folder_id, SecretKey::from_hex(&rec.key_hex).unwrap())
            .unwrap();
    for secret in [&a_secret[..], &b_secret[..]] {
        let id = ChunkId::from_bytes(&crypto::keyed_hash(&fk0.hash, secret));
        for ct in chunk_objects(&lab.store()) {
            assert!(
                varsto_core::chunk_seal::open_chunk(&fk0, &vault, &id, 0, secret.len() as u64, &ct)
                    .is_err(),
                "new chunk opens with an old key"
            );
        }
    }
    let prefix = lab
        .store()
        .join("manifests")
        .join(rec.folder_id.as_str())
        .join(a.device_id().as_str());
    let newest = fs::read_dir(&prefix)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .max()
        .unwrap();
    let seq: u64 = newest
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .parse()
        .unwrap();
    let blob = fs::read(&newest).unwrap();
    // Only the old epoch's metadata key, as C holds it.
    let meta_for = |e: u32| (e == 0).then(|| fk0.meta.clone());
    let a_key = a.device_public_key();
    assert!(Manifest::open(
        &blob,
        &vault,
        &rec.folder_id,
        a.device_id(),
        seq,
        &a_key,
        &meta_for
    )
    .is_err());
    let old_ledger = SecretKey::from_hex(&old_key).unwrap().derive("ledger", &[]);
    let batches = lab.store().join("ledger").join(a.device_id().as_str());
    let newest = fs::read_dir(&batches)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .max()
        .unwrap();
    let signed: SignedBatch = serde_json::from_slice(&fs::read(newest).unwrap()).unwrap();
    assert_eq!(signed.key_id, "ledger@1");
    assert!(signed.open(&old_ledger).is_err());

    // C learns it was removed and stops; its files stay (no wipe ordered).
    let err = c.sync(None).unwrap_err();
    let gone = removed(&err).expect("a DeviceRemoved error");
    assert!(!gone.wiped);
    assert!(c.push("docs").is_err());
    assert!(c.removal().is_some());
    assert!(lab.dir("c").join("one.txt").exists());
    drop(c);
    let c = Engine::open(&lab.home("c"), PASS).unwrap();
    assert!(c.removal().is_some(), "the removal survives a restart");

    // A device joining with the old key is refused; the current key opens everything.
    assert!(Engine::join(&lab.home("d-old"), "d", PASS, &old_key, lab.storage.clone()).is_err());
    let new_key = a.export_vault_key().unwrap();
    assert_ne!(new_key, old_key);
    let mut d =
        small(Engine::join(&lab.home("d"), "d", PASS, &new_key, lab.storage.clone()).unwrap());
    assert_eq!(d.key_epoch(), 1);
    d.attach_folder("docs", &lab.dir("d"), false).unwrap();
    d.sync(None).unwrap();
    assert!(lab.dir("d").join("one.txt").exists());
    assert_eq!(
        fs::read(lab.dir("d").join("after-a.txt")).unwrap(),
        a_secret
    );
    assert_eq!(
        fs::read(lab.dir("d").join("after-b.txt")).unwrap(),
        b_secret
    );
    assert!(!lab.dir("d").join("from-c.txt").exists());
    // A trusts the device that joined with the current key.
    a.sync(None).unwrap();
    assert!(a.devices_list().iter().any(|x| x.name == "d" && !x.revoked));
    // The cached views (rebuilt on the new epoch and the cut-off) equal a
    // replay of every batch, also after a restart.
    for e in [&a, &d] {
        assert_eq!(e.view().unwrap(), e.view_replayed().unwrap());
    }
    drop(a);
    let a = Engine::open(&lab.home("a"), PASS).unwrap();
    assert_eq!(a.view().unwrap(), a.view_replayed().unwrap());
}

#[test]
fn wipe_order_removes_keys_state_and_folder_contents() {
    let lab = Lab::new();
    let (mut a, mut b, mut c, _) = three_devices(&lab);
    // An unsynced file on the lost device is wiped too.
    fs::write(lab.dir("c").join("never-synced.txt"), b"local only").unwrap();
    let report = a.revoke_device("c", true).unwrap();
    assert!(report.wipe);

    let err = c.sync(None).unwrap_err();
    assert!(removed(&err).expect("a DeviceRemoved error").wiped);
    drop(c);
    let home = lab.home("c");
    for f in [
        "keys.enc",
        "vault.json",
        "keyring.enc",
        "vault-keys.enc",
        "config.json",
        "devices.json",
    ] {
        assert!(!home.join(f).exists(), "{f} survived the wipe");
    }
    for d in ["state", "ledger", "trash"] {
        assert!(!home.join(d).exists(), "{d}/ survived the wipe");
    }
    let notice = varsto_core::engine::removal_notice(&home).expect("a wipe notice");
    assert!(notice.wipe);
    assert_eq!(notice.by_name, "a");
    assert!(lab.dir("c").is_dir(), "the folder root itself stays");
    assert_eq!(
        fs::read_dir(lab.dir("c")).unwrap().count(),
        0,
        "the folder is empty"
    );
    assert!(Engine::open(&home, PASS).is_err());

    // Nothing else was touched: the other devices and the storage keep working.
    assert!(lab.dir("a").join("one.txt").exists());
    fs::write(lab.dir("b").join("still.txt"), b"still syncing").unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    assert!(lab.dir("a").join("still.txt").exists());
}

#[test]
fn forged_wipe_order_is_ignored() {
    let lab = Lab::new();
    let (mut a, mut b, mut c, old_key) = three_devices(&lab);
    let vault = a.vault_id().clone();
    let c_id = c.device_id().clone();
    let store = lab.storage.open().unwrap();
    // Someone with the vault key (an old recovery kit, say) but no device key
    // of the vault: signs with a key the registry does not know...
    let registry = SecretKey::from_hex(&old_key)
        .unwrap()
        .derive("device-registry", &[]);
    let forger = SigningKey::generate();
    let forger_id = ledger::device_id_for(&forger.public());
    let mut order = Revocation {
        device: c_id.clone(),
        device_name: "c".into(),
        issuer: forger_id.clone(),
        issued_utc: 1,
        cutoff_seq: 0,
        wipe: true,
        new_epoch: 1,
    };
    let forged = SignedRevocation::seal(&order, &vault, 0, &registry, &forger).unwrap();
    store
        .put_if_absent(
            &SignedRevocation::storage_key(&c_id, &forger_id),
            &serde_json::to_vec(&forged).unwrap(),
        )
        .unwrap();
    // ...or claims to be A while signing with its own key...
    order.issuer = a.device_id().clone();
    let impostor = SignedRevocation::seal(&order, &vault, 0, &registry, &forger).unwrap();
    store
        .put_if_absent(
            &SignedRevocation::storage_key(&c_id, a.device_id()),
            &serde_json::to_vec(&impostor).unwrap(),
        )
        .unwrap();
    // ...and the storage itself plants garbage in B's name.
    store
        .put_if_absent(
            &SignedRevocation::storage_key(&c_id, b.device_id()),
            b"{\"not\": \"a revocation\"}",
        )
        .unwrap();

    fs::write(lab.dir("c").join("c-file.txt"), b"still here").unwrap();
    c.sync(None).unwrap();
    assert!(c.removal().is_none());
    assert!(lab.home("c").join("keys.enc").exists());
    assert!(lab.dir("c").join("one.txt").exists());
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(
        lab.dir("b").join("c-file.txt").exists(),
        "C is still a device of the vault"
    );
    assert!(a.devices_list().iter().all(|d| !d.revoked));
    assert_eq!(a.key_epoch(), 0);
}

/// Junk under a device's own ledger name (anyone with the storage's
/// credentials can write it) does not fence the device: only an object its
/// own key signed does. It is reported, and `ledger clean-junk` deletes it
/// and nothing else (`docs/spec/alpha-0-format.md` section 58).
#[test]
fn junk_under_a_devices_ledger_name_does_not_fence_it() {
    let lab = Lab::new();
    let (mut a, mut b, _c, _) = three_devices(&lab);
    let own = lab.store().join("ledger").join(a.device_id().as_str());
    fs::write(own.join("9999999999999999.json"), b"junk").unwrap();
    fs::write(
        own.join("checkpoint-9999999999999998.json"),
        b"{\"not\": \"a checkpoint\"}",
    )
    .unwrap();
    // A copy of a real batch of another device, under A's name.
    let theirs = fs::read_dir(lab.store().join("ledger").join(b.device_id().as_str()))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "json"))
        .unwrap();
    fs::copy(theirs, own.join("9999999999999997.json")).unwrap();

    fs::write(lab.dir("a").join("two.txt"), b"after the junk").unwrap();
    a.sync(None).expect("junk does not fence the device");
    let h = a.ledger_health();
    assert_eq!(h.state, "ok", "{h:?}");
    assert_eq!(h.junk_objects, 3, "{h:?}");
    assert!(h.describe().contains("clean-junk"));
    assert_eq!(a.ledger_check_storages().unwrap().state, "ok");
    b.sync(None).unwrap();
    assert!(lab.dir("b").join("two.txt").exists());

    let dry = a.ledger_clean_junk(true).unwrap();
    assert_eq!(dry.junk.len(), 3, "{dry:?}");
    assert_eq!(dry.deleted, 0);
    let names = |p: &Path| fs::read_dir(p).unwrap().count();
    let before = names(&own);
    let done = a.ledger_clean_junk(false).unwrap();
    assert_eq!(done.deleted, 3);
    assert_eq!(names(&own), before - 3);
    assert!(done.genuine > 0);
    assert_eq!(a.ledger_health().junk_objects, 0);
    fs::write(lab.dir("a").join("three.txt"), b"still fine").unwrap();
    a.sync(None).unwrap();
}

/// Junk under the next key epoch number does not stop a removal, with or
/// without an organization: a number taken by anything but a signed epoch
/// record of a trusted device is skipped.
#[test]
fn junk_epoch_record_does_not_block_revocation() {
    let lab = Lab::new();
    let (mut a, mut b, _c, _) = three_devices(&lab);
    let epochs = lab.store().join("vault/epochs");
    fs::create_dir_all(&epochs).unwrap();
    fs::write(epochs.join("00000001.enc"), b"junk").unwrap();
    let r = a
        .revoke_device("c", false)
        .expect("junk does not block the removal");
    assert_eq!(r.key_epoch, 2);
    b.sync(None).unwrap();
    assert_eq!(b.key_epoch(), 2);
    assert!(b.devices_list().iter().any(|d| d.name == "c" && d.revoked));
}

/// Revocations apply in the order of the key epochs they started, not of
/// their timestamps, which the issuer chooses: after A removed C in epoch
/// 1, C (a stolen device running a modified client) removes A in epoch 2
/// with a revocation dated 2000-01-01. Every other device keeps A and
/// ignores C (`docs/spec/alpha-0-format.md` section 58).
#[test]
fn a_backdated_revocation_does_not_win() {
    let lab = Lab::new();
    let (mut a, mut b, mut c, _) = three_devices(&lab);
    let r = a.revoke_device("c", false).unwrap();
    assert_eq!(r.key_epoch, 1);
    // C has not pulled since; it removes A without looking.
    let forged = c.revoke_unchecked("a", 946_684_800).unwrap();
    assert_eq!(forged.key_epoch, 2);

    b.sync(None).unwrap();
    let list = b.devices_list();
    let a_entry = list.iter().find(|d| d.name == "a").unwrap();
    let c_entry = list.iter().find(|d| d.name == "c").unwrap();
    assert!(
        !a_entry.revoked,
        "A was removed by the backdated revocation"
    );
    assert!(c_entry.revoked);
    assert_eq!(b.key_epoch(), 1, "C's epoch is not adopted");
    a.sync(None).unwrap();
    assert!(a.removal().is_none());
    fs::write(lab.dir("a").join("after.txt"), b"A still writes").unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(lab.dir("b").join("after.txt").exists());
}

/// Two devices that each remove the other at the same moment, through
/// different first storages, write two key epochs under one number. Every
/// device that sees both records it, signs nothing until the user keeps
/// one, and then follows the kept one only.
#[test]
fn two_epochs_under_one_number_wait_for_a_choice() {
    let lab = Lab::new();
    let (mut a, mut b, c0, _) = three_devices(&lab);
    drop(c0);
    let second_dir = lab.root.join("second");
    let second = StorageSpec::LocalDir {
        name: "second".into(),
        path: second_dir.clone(),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    };
    a.add_storage(second.clone()).unwrap();
    a.sync(None).unwrap();
    b.add_storage(second.clone()).unwrap();
    b.sync(None).unwrap();
    // C2 works through the second storage only.
    let key = a.export_vault_key().unwrap();
    let mut c = small(Engine::join(&lab.home("c2"), "c2", PASS, &key, second).unwrap());
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    c.sync(None).unwrap();
    // A removes C2; at the same moment C2 removes A, and on the second
    // storage C2's record took the number first.
    let r = a.revoke_device("c2", false).unwrap();
    assert_eq!(r.key_epoch, 1);
    fs::remove_file(second_dir.join("vault/epochs/00000001.enc")).unwrap();
    assert_eq!(c.revoke_unchecked("a", 946_684_800).unwrap().key_epoch, 1);

    fs::write(lab.dir("b").join("b-file.txt"), b"wants to be signed").unwrap();
    let err = b.sync(None).unwrap_err();
    assert!(format!("{err:#}").contains("resolve-epoch"), "{err:#}");
    let h = b.ledger_health();
    assert_eq!(h.state, "epoch_fork", "{h:?}");
    assert_eq!(b.epoch_forks().unresolved(), vec![1]);
    assert!(b.resolve_epoch_fork(1, "nobody").is_err());
    b.resolve_epoch_fork(1, "a").unwrap();
    b.sync(None).unwrap();
    assert_eq!(b.ledger_health().state, "ok");
    let list = b.devices_list();
    assert!(!list.iter().find(|d| d.name == "a").unwrap().revoked);
    assert!(list.iter().find(|d| d.name == "c2").unwrap().revoked);
    assert_eq!(b.key_epoch(), 1);
    // A saw both as well, and was not removed by C2's record.
    let _ = a.sync(None);
    assert!(a.removal().is_none());
    a.resolve_epoch_fork(1, "a").unwrap();
    a.sync(None).unwrap();
    assert!(lab.dir("a").join("b-file.txt").exists());
}
