// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Tests of work package 8a (format 3 design, section 12, tests 2, 10, 11
//! as far as they concern the data model).

use super::store::Writer;
use super::*;
use crate::crypto::{SecretKey, SigningKey};
use crate::kem::DecapsKey;
use crate::record::envelope::decode_body;
use crate::record::{
    Acceptor, DeviceSigner, Junk, KeyId, Kind, RecordBody, RecordMeta, RecordTrust, RecordWriter,
    Refusal, StreamRef,
};
use crate::storage::Storage;
use anyhow::Result;
use rand::{Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Mutex;

const VAULT: Id16 = [0x5a; 16];

#[derive(Default)]
struct Mem(Mutex<BTreeMap<String, Vec<u8>>>);

impl Storage for Mem {
    fn name(&self) -> &str {
        "mem"
    }
    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        let mut m = self.0.lock().unwrap();
        if m.contains_key(key) {
            return Ok(false);
        }
        m.insert(key.to_string(), data.to_vec());
        Ok(true)
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }
    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.0.lock().unwrap().contains_key(key))
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
}

/// A device's own keys: K6 and K8.
struct Dev {
    sign: SigningKey,
    kem: DecapsKey,
}

impl Dev {
    fn new() -> Dev {
        Dev {
            sign: SigningKey::generate(),
            kem: DecapsKey::generate(),
        }
    }
}

/// Open and enrol a device with the vault keys given.
fn device<'a>(
    st: &'a [&'a dyn Storage],
    d: &'a Dev,
    keys: &VaultKeys,
    name: &str,
) -> Membership<'a> {
    let mut m = Membership::open(VAULT, st, &d.sign, &d.kem, keys.clone()).unwrap();
    m.enrol(name).unwrap();
    m
}

/// A record of folder content (a `notes` record stands in for manifests,
/// maps and trash: the same `meta:` key opens them).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Note {
    text: String,
}
impl RecordBody for Note {}

fn seal_note(
    m: &Membership,
    d: &Dev,
    folder: Id16,
    epoch: u32,
    seq: u64,
    text: &str,
) -> Vec<(String, Vec<u8>)> {
    let signer = DeviceSigner {
        device: m.me,
        key: &d.sign,
    };
    let keys = m.record_keys();
    RecordWriter {
        vault: VAULT,
        signer: &signer,
        keys: &keys,
    }
    .seal(
        &StreamRef::new(Kind::Notes, folder, m.me),
        seq,
        seq,
        &KeyId::Meta { folder, epoch },
        &Note { text: text.into() },
    )
    .unwrap()
    .parts
}

fn open_note(m: &Membership, parts: &[(String, Vec<u8>)]) -> Result<Note, Refusal> {
    let keys = m.record_keys();
    let trust = m.record_trust();
    Acceptor {
        vault: VAULT,
        keys: &keys,
        trust: &trust,
    }
    .open::<Note>(parts)
    .map(|r| r.body)
    .map_err(|r| r.reason)
}

fn meta(folder: Id16, epoch: u32) -> KeyId {
    KeyId::Meta { folder, epoch }
}

#[test]
fn device_id_is_the_hash_of_k6() {
    let s = Mem::default();
    let st: Vec<&dyn Storage> = vec![&s];
    let keys = VaultKeys::genesis(SecretKey::random());
    let a = Dev::new();
    let m = device(&st, &a, &keys, "laptop");
    let raw = a.sign.public().to_bytes();
    assert_eq!(m.me[..], crate::crypto::hash(&raw)[..16]);
    assert_eq!(m.devices.get(&m.me).unwrap().name, "laptop");

    // A device record for an id that is not the hash of its key: refused.
    let fake: Id16 = [0x77; 16];
    let body = DeviceRecord {
        device: fake,
        name: "impostor".into(),
        sign_pub: raw,
        kem_pub: a.kem.public().to_bytes(),
        stamp: Stamp {
            lamport: 9,
            device: fake,
        },
    };
    Writer {
        vault: VAULT,
        storages: &st,
        device: fake,
        key: &a.sign,
    }
    .write(
        &KeyRing::vault_only(fake, &keys),
        &DeviceRecord::stream(fake),
        None,
        &KeyId::Registry(0),
        &body,
    )
    .unwrap();
    let mut m2 = Membership::open(VAULT, &st, &a.sign, &a.kem, keys.clone()).unwrap();
    m2.refresh().unwrap();
    assert!(m2.devices.get(&fake).is_none());
    assert_eq!(m2.refused.get(Kind::Device), 1);
}

#[test]
fn a_device_with_the_vault_words_sees_names_and_no_content() {
    let s = Mem::default();
    let st: Vec<&dyn Storage> = vec![&s];
    let keys = VaultKeys::genesis(SecretKey::random());
    let (a, b) = (Dev::new(), Dev::new());
    let mut ma = device(&st, &a, &keys, "laptop");
    let f = ma.create_folder("Photos", BTreeMap::new(), None).unwrap();
    let note = seal_note(&ma, &a, f, 0, 1, "holiday.jpg");
    assert_eq!(open_note(&ma, &note).unwrap().text, "holiday.jpg");

    let mb = device(&st, &b, &keys, "phone");
    let folder = mb.registry.get(&f).expect("folder record readable with K3");
    assert_eq!(folder.name, "Photos");
    assert_eq!(folder.owners(), vec![ma.me]);
    // Sizes: the envelope of a content record is readable, its body is not.
    let env = crate::record::SignedRecord::decode(&note[0].1).unwrap();
    assert!(!env.body.is_empty());
    // No grant, so no meta key and no content.
    assert!(mb.read_my_grants().get(&f).is_none());
    assert!(crate::record::RecordKeys::symmetric(&mb.record_keys(), &meta(f, 0)).is_none());
    assert_eq!(open_note(&mb, &note), Err(Refusal::Junk(Junk::KeyNotHeld)));
}

#[test]
fn approval_on_one_owner_device_suffices() {
    let s = Mem::default();
    let st: Vec<&dyn Storage> = vec![&s];
    let keys = VaultKeys::genesis(SecretKey::random());
    let (a, a2, b) = (Dev::new(), Dev::new(), Dev::new());
    let mut ma = device(&st, &a, &keys, "laptop");
    let mut ma2 = device(&st, &a2, &keys, "desktop");
    let mut mb = device(&st, &b, &keys, "phone");
    ma.refresh().unwrap();
    let f = ma.create_folder("Docs", BTreeMap::new(), None).unwrap();
    ma.approve(&f, &ma2.me.clone(), Role::Owner).unwrap();
    ma2.refresh().unwrap();
    assert!(ma2.read_my_grants().holds(&f, 0));
    assert_eq!(ma2.role(&ma2.me, &f, 0), Some(Role::Owner));

    mb.request_folder(&f, Role::Editor).unwrap();
    // The request shows on both owner devices, with the same fingerprint.
    let fp = fingerprint(&b.sign.public().to_bytes(), &b.kem.public().to_bytes());
    for m in [&mut ma, &mut ma2] {
        m.refresh().unwrap();
        let reqs = m.list_requests(&f).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].device, mb.me);
        assert_eq!(reqs[0].name, "phone");
        assert_eq!(reqs[0].role_wanted, Role::Editor);
        assert_eq!(reqs[0].fingerprint, fp);
    }
    // One approval is enough: the grant opens on the requester.
    ma.approve(&f, &mb.me.clone(), Role::Editor).unwrap();
    mb.refresh().unwrap();
    assert!(mb.read_my_grants().holds(&f, 0));
    assert_eq!(mb.role(&mb.me, &f, 0), Some(Role::Editor));
    let note = seal_note(&ma, &a, f, 0, 1, "plan.txt");
    assert_eq!(open_note(&mb, &note).unwrap().text, "plan.txt");
    ma2.refresh().unwrap();
    assert!(ma2.list_requests(&f).unwrap().is_empty());
    // A second owner's grant is redundant: the same keys.
    let before = mb.read_my_grants().get(&f).unwrap().clone();
    ma2.issue_grant(&f, 0, &mb.me.clone(), Role::Editor)
        .unwrap();
    mb.refresh().unwrap();
    let after = mb.read_my_grants().get(&f).unwrap();
    assert_eq!(after.epochs.len(), 1);
    assert_eq!(after.epochs[&0].0, before.epochs[&0].0);
    assert_eq!(after.k11.0, before.k11.0);
}

#[test]
fn grants_and_folder_records_from_non_owners_are_refused() {
    let s = Mem::default();
    let st: Vec<&dyn Storage> = vec![&s];
    let keys = VaultKeys::genesis(SecretKey::random());
    let (a, b, c) = (Dev::new(), Dev::new(), Dev::new());
    let mut ma = device(&st, &a, &keys, "laptop");
    let mut mb = device(&st, &b, &keys, "phone");
    let mut mc = device(&st, &c, &keys, "tablet");
    ma.refresh().unwrap();
    let f = ma.create_folder("Docs", BTreeMap::new(), None).unwrap();
    ma.approve(&f, &mc.me.clone(), Role::Editor).unwrap();
    mc.refresh().unwrap();
    assert!(mc.read_my_grants().holds(&f, 0));
    // The API refuses a non-owner...
    assert!(mc.issue_grant(&f, 0, &mb.me.clone(), Role::Editor).is_err());
    // ... and so does every reader when the editor writes one anyway: with
    // the real key, and with a key of its own making.
    for k9 in [mc.read_my_grants().get(&f).unwrap().epochs[&0].0, [9u8; 32]] {
        let body = grants::GrantRecord {
            folder: f,
            epoch: 0,
            recipient: mb.me,
            issuer: mc.me,
            role: Role::Owner,
            k9,
            k11: grants::k11_of(&f, &SecretKey(k9)).0,
            older: Vec::new(),
        };
        Writer {
            vault: VAULT,
            storages: &st,
            device: mc.me,
            key: &c.sign,
        }
        .write(
            &mc.record_keys(),
            &body.stream(),
            None,
            &KeyId::Kem(mb.me),
            &body,
        )
        .unwrap();
    }
    mb.refresh().unwrap();
    assert!(mb.read_my_grants().get(&f).is_none());
    // A folder record by a non-owner that makes itself owner: ignored.
    let body = FolderRecord {
        id: f,
        name: "Mine now".into(),
        settings: BTreeMap::new(),
        stamp: Stamp {
            lamport: 1000,
            device: mc.me,
        },
        creation: None,
        participants: vec![Participant {
            device: mc.me,
            role: Role::Owner,
            stamp: Stamp {
                lamport: 1000,
                device: mc.me,
            },
        }],
        denied: vec![Denied {
            device: ma.me,
            stamp: Stamp {
                lamport: 1000,
                device: mc.me,
            },
        }],
        members: Vec::new(),
    };
    Writer {
        vault: VAULT,
        storages: &st,
        device: mc.me,
        key: &c.sign,
    }
    .write(
        &mc.record_keys(),
        &FolderRegistry::stream(f, mc.me),
        None,
        &KeyId::Registry(0),
        &body,
    )
    .unwrap();
    mb.refresh().unwrap();
    let folder = mb.registry.get(&f).unwrap();
    assert_eq!(folder.name, "Docs");
    assert_eq!(folder.role(&mc.me), Some(Role::Editor));
    assert_eq!(folder.role(&ma.me), Some(Role::Owner));
    assert!(folder.entries_refused >= 3);
}

#[test]
fn a_folder_epoch_removes_a_member() {
    let s = Mem::default();
    let st: Vec<&dyn Storage> = vec![&s];
    let keys = VaultKeys::genesis(SecretKey::random());
    let (a, a2, b) = (Dev::new(), Dev::new(), Dev::new());
    let k1 = RecoveryKey::generate();
    let mut ma = device(&st, &a, &keys, "laptop");
    let mut ma2 = device(&st, &a2, &keys, "desktop");
    let mut mb = device(&st, &b, &keys, "phone");
    ma.refresh().unwrap();
    let f = ma
        .create_folder("Docs", BTreeMap::new(), Some(&k1))
        .unwrap();
    ma.approve(&f, &ma2.me.clone(), Role::Owner).unwrap();
    ma.approve(&f, &mb.me.clone(), Role::Editor).unwrap();
    let old = seal_note(&ma, &a, f, 0, 1, "old");
    let start = ma
        .start_folder_epoch(
            &f,
            &[Removed {
                device: mb.me,
                cutoff: 7,
            }],
            Some(&k1),
        )
        .unwrap();
    assert_eq!(start.epoch, 1);
    assert!(start.escrowed);
    assert!(start.granted_to.contains(&ma2.me) && !start.granted_to.contains(&mb.me));
    assert_eq!(ma.folder_epochs(&f).current(), 1);
    let new = seal_note(&ma, &a, f, 1, 2, "new");

    mb.refresh().unwrap();
    assert_eq!(open_note(&mb, &old).unwrap().text, "old");
    assert_eq!(open_note(&mb, &new), Err(Refusal::Junk(Junk::KeyNotHeld)));
    assert_eq!(mb.folder_epochs(&f).current(), 0);
    assert_eq!(mb.folder_epochs(&f).newest_seen(), 1);
    assert_eq!(mb.role(&mb.me, &f, 1), None);

    ma2.refresh().unwrap();
    assert_eq!(ma2.folder_epochs(&f).current(), 1);
    assert_eq!(open_note(&ma2, &old).unwrap().text, "old");
    assert_eq!(open_note(&ma2, &new).unwrap().text, "new");
    let rec = &ma2.folder_epochs(&f).applied[&1];
    assert_eq!(
        rec.removed,
        vec![Removed {
            device: mb.me,
            cutoff: 7
        }]
    );
    // The removed member's records under the new epoch do not count: it
    // has no key, and its role at epoch 1 is none.
    assert!(!ma2
        .record_trust()
        .may_write(&mb.me, Kind::Manifest, &f, &meta(f, 1)));
    assert!(ma2.missing_escrows().unwrap().is_empty());
}

#[test]
fn two_folder_epochs_under_one_number_wait() {
    let (s1, s2) = (Mem::default(), Mem::default());
    let both: Vec<&dyn Storage> = vec![&s1, &s2];
    let only1: Vec<&dyn Storage> = vec![&s1];
    let only2: Vec<&dyn Storage> = vec![&s2];
    let keys = VaultKeys::genesis(SecretKey::random());
    let (a, a2) = (Dev::new(), Dev::new());
    let mut ma = device(&both, &a, &keys, "laptop");
    let mut ma2 = device(&both, &a2, &keys, "desktop");
    ma.refresh().unwrap();
    let f = ma.create_folder("Docs", BTreeMap::new(), None).unwrap();
    ma.approve(&f, &ma2.me.clone(), Role::Owner).unwrap();
    ma2.refresh().unwrap();
    // Each owner starts epoch 1 through a different first storage.
    let mut ma_1 = Membership::open(VAULT, &only1, &a.sign, &a.kem, keys.clone()).unwrap();
    let mut ma2_2 = Membership::open(VAULT, &only2, &a2.sign, &a2.kem, keys.clone()).unwrap();
    let ka = ma_1.start_folder_epoch(&f, &[], None).unwrap();
    let kb = ma2_2.start_folder_epoch(&f, &[], None).unwrap();
    assert_eq!((ka.epoch, kb.epoch), (1, 1));
    assert_ne!(ka.keys.epochs[&1].0, kb.keys.epochs[&1].0);

    ma.refresh().unwrap();
    let ep = ma.folder_epochs(&f);
    assert_eq!(ep.unresolved(), vec![1]);
    assert_eq!(
        ep.forks[&1],
        [ma.me, ma2.me]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
    );
    // Neither is applied, neither key is used, nothing new is signed.
    assert_eq!(ep.current(), 0);
    assert!(!ma.read_my_grants().holds(&f, 1));
    assert!(ma.start_folder_epoch(&f, &[], None).is_err());
    // Keeping one applies it.
    let keep = ma2.me;
    ma.resolve_folder_epoch(&f, 1, &keep).unwrap();
    assert_eq!(ma.folder_epochs(&f).current(), 1);
    assert_eq!(
        ma.read_my_grants().get(&f).unwrap().epochs[&1].0,
        kb.keys.epochs[&1].0
    );
}

#[test]
fn vault_words_and_recovery_words_restore_every_folder() {
    let s = Mem::default();
    let st: Vec<&dyn Storage> = vec![&s];
    let keys = VaultKeys::genesis(SecretKey::random());
    let (a, d2) = (Dev::new(), Dev::new());
    let k1 = RecoveryKey::generate();
    let mut ma = device(&st, &a, &keys, "laptop");
    let md2 = device(&st, &d2, &keys, "old phone");
    ma.refresh().unwrap();
    let f = ma
        .create_folder("Photos", BTreeMap::new(), Some(&k1))
        .unwrap();
    let g = ma
        .create_folder("Docs", BTreeMap::new(), Some(&k1))
        .unwrap();
    // A vault epoch, so K3₀ must come through the chain of epoch records.
    ma.remove_device(&md2.me.clone(), 3, false, Some(&k1))
        .unwrap();
    assert_eq!(ma.vault_keys.newest_epoch(), 1);
    ma.start_folder_epoch(&f, &[], Some(&k1)).unwrap();
    let note = seal_note(&ma, &a, f, 1, 1, "kept");
    let want: BTreeMap<Id16, FolderKeys> = ma.read_my_grants().folders.clone();
    let (newest_epoch, newest_k3) = {
        let (e, k) = ma.vault_keys.newest().unwrap();
        (e, k.clone())
    };
    assert_eq!(newest_epoch, 1);

    // Every device is lost. A new one joins with the kit's two word sets.
    let vault_words = crate::recovery::words_from_key(&newest_k3.to_hex()).unwrap();
    let recovery_words = k1.words().unwrap();
    let n = Dev::new();
    let k3 = SecretKey::from_hex(&crate::recovery::key_from_words(&vault_words).unwrap()).unwrap();
    let mut mn = Membership::join(VAULT, &st, &n.sign, &n.kem, k3).unwrap();
    mn.enrol("new laptop").unwrap();
    assert_eq!(mn.vault_keys.newest_epoch(), 1);
    assert_eq!(mn.vault_keys.k3_0().unwrap().0, keys.k3_0().unwrap().0);
    // The vault words alone: names, no content.
    assert!(mn.read_my_grants().folders.is_empty());
    assert_eq!(mn.registry.get(&g).unwrap().name, "Docs");
    assert_eq!(open_note(&mn, &note), Err(Refusal::Junk(Junk::KeyNotHeld)));
    // With the recovery words: every folder key of every epoch.
    let k1n = RecoveryKey::from_words(&recovery_words).unwrap();
    let got = mn.recover_all_folders(&k1n).unwrap();
    assert_eq!(got.folders.len(), 2);
    for (folder, keys) in &want {
        let have = mn.read_my_grants().get(folder).unwrap();
        assert_eq!(have.k11.0, keys.k11.0);
        assert_eq!(have.epochs.len(), keys.epochs.len());
        for (e, k) in &keys.epochs {
            assert_eq!(have.epochs[e].0, k.0);
        }
    }
    assert_eq!(open_note(&mn, &note).unwrap().text, "kept");
    assert_eq!(mn.folder_epochs(&f).current(), 1);
    // Shares of K1 work the same.
    let shares = k1.shares().unwrap();
    let back = RecoveryKey::from_shares(&shares[1..], Some(&k1.key_check().unwrap())).unwrap();
    assert_eq!(back.k2().0, k1.k2().0);
    // The kit prints both word sets.
    let kit = escrow::kit_text(&VAULT, newest_epoch, &newest_k3, &k1).unwrap();
    assert!(kit.contains(vault_words.split(' ').next().unwrap()));
    assert!(kit.contains("RECOVERY WORDS"));
}

#[test]
fn recovery_words_alone_give_nothing() {
    let s = Mem::default();
    let st: Vec<&dyn Storage> = vec![&s];
    let keys = VaultKeys::genesis(SecretKey::random());
    let a = Dev::new();
    let k1 = RecoveryKey::generate();
    let mut ma = device(&st, &a, &keys, "laptop");
    let f = ma
        .create_folder("Photos", BTreeMap::new(), Some(&k1))
        .unwrap();
    // Someone with K1 and every escrow object, but not K3₀: the escrow
    // key binds K3₀, so no body opens.
    let name = s
        .list("vault/escrow/")
        .unwrap()
        .into_iter()
        .next()
        .expect("an escrow record");
    let bytes = s.get(&name).unwrap().unwrap();
    let env = crate::record::SignedRecord::decode(&bytes).unwrap();
    let wrong = VaultKeys::genesis(SecretKey::random());
    let mut ring = KeyRing::vault_only([0; 16], &wrong);
    ring.recovery = Some(k1.escrow_key(&VAULT, wrong.k3_0().unwrap()));
    assert_eq!(env.open_part(&ring), Err(Junk::BodyDoesNotOpen));
    // With the right K3₀ it opens (the test above uses that path).
    ring.recovery = Some(k1.escrow_key(&VAULT, keys.k3_0().unwrap()));
    let body: EscrowRecord = decode_body(&env.open_part(&ring).unwrap()).unwrap();
    assert_eq!(body.folder, f);
    // And the vault words with another K1 recover nothing.
    let n = Dev::new();
    let mut mn = Membership::open(VAULT, &st, &n.sign, &n.kem, keys.clone()).unwrap();
    let got = mn.recover_all_folders(&RecoveryKey::generate()).unwrap();
    assert!(got.folders.is_empty());
    assert!(mn.read_my_grants().folders.is_empty());
}

#[test]
fn a_folder_without_escrow_is_reported() {
    let s = Mem::default();
    let st: Vec<&dyn Storage> = vec![&s];
    let keys = VaultKeys::genesis(SecretKey::random());
    let a = Dev::new();
    let mut ma = device(&st, &a, &keys, "laptop");
    let f = ma.create_folder("Photos", BTreeMap::new(), None).unwrap();
    let missing = ma.missing_escrows().unwrap();
    assert_eq!(missing.len(), 1);
    assert_eq!((missing[0].folder, missing[0].epoch), (f, 0));
    assert_eq!(
        missing[0].warning(),
        "folder Photos has no recovery copy: run varsto recovery escrow Photos"
    );
    ma.escrow_folder_epoch(&f, 0, &RecoveryKey::generate())
        .unwrap();
    assert!(ma.missing_escrows().unwrap().is_empty());
}

#[test]
fn removing_a_full_device_starts_a_vault_epoch_and_folder_epochs() {
    let s = Mem::default();
    let st: Vec<&dyn Storage> = vec![&s];
    let keys = VaultKeys::genesis(SecretKey::random());
    let (a, b, c) = (Dev::new(), Dev::new(), Dev::new());
    let k1 = RecoveryKey::generate();
    let mut ma = device(&st, &a, &keys, "laptop");
    let mut mb = device(&st, &b, &keys, "lost phone");
    let mut mc = device(&st, &c, &keys, "desktop");
    ma.refresh().unwrap();
    let f = ma
        .create_folder("Docs", BTreeMap::new(), Some(&k1))
        .unwrap();
    let g = ma
        .create_folder("Other", BTreeMap::new(), Some(&k1))
        .unwrap();
    ma.approve(&f, &mb.me.clone(), Role::Editor).unwrap();
    ma.approve(&f, &mc.me.clone(), Role::Viewer).unwrap();
    let report = ma
        .remove_device(&mb.me.clone(), 11, true, Some(&k1))
        .unwrap();
    assert_eq!(report.vault_epoch, 1);
    assert_eq!(report.folder_epochs, vec![(f, 1)]);
    assert!(report.vault_keys_sent_to.contains(&mc.me));
    assert!(!report.vault_keys_sent_to.contains(&mb.me));
    assert!(ma.is_revoked(&mb.me));
    assert_eq!(ma.folder_epochs(&g).current(), 0);
    assert_eq!(ma.revocations[&mb.me].cutoff_seq, 11);
    assert!(ma.revocations[&mb.me].wipe);

    // The device that stays adopts the new vault key and the folder epoch.
    mc.refresh().unwrap();
    assert_eq!(mc.vault_keys.newest_epoch(), 1);
    assert!(mc.is_revoked(&mb.me));
    assert!(mc.read_my_grants().holds(&f, 1));
    assert_eq!(mc.role(&mc.me, &f, 1), Some(Role::Viewer));
    // The removed one gets neither.
    mb.refresh().unwrap();
    assert_eq!(mb.vault_keys.newest_epoch(), 0);
    assert!(!mb.read_my_grants().holds(&f, 1));
    // Its old vault key no longer joins.
    let n = Dev::new();
    assert!(Membership::join(VAULT, &st, &n.sign, &n.kem, keys.k3_0().unwrap().clone()).is_err());
    // A full device's snapshot is allowed; the removed device's is not.
    let backup: Id16 = [0x0b; 16];
    assert!(mc
        .record_trust()
        .may_write(&ma.me, Kind::Snapshot, &backup, &meta(f, 1)));
    assert!(!mc
        .record_trust()
        .may_write(&mb.me, Kind::Snapshot, &backup, &meta(f, 1)));
    // A viewer's manifest is refused by the role check.
    assert!(!mc
        .record_trust()
        .may_write(&mc.me, Kind::Manifest, &f, &meta(f, 1)));
    assert!(mc
        .record_trust()
        .may_write(&ma.me, Kind::Manifest, &f, &meta(f, 1)));
}

#[test]
fn fingerprint_is_stable_and_changes_with_either_key() {
    let (d, e) = (Dev::new(), Dev::new());
    let k6 = d.sign.public().to_bytes();
    let k8 = d.kem.public().to_bytes();
    let fp = fingerprint(&k6, &k8);
    assert_eq!(fp.split(' ').count(), 6);
    assert_eq!(fp, fingerprint(&k6, &k8));
    assert_ne!(fp, fingerprint(&e.sign.public().to_bytes(), &k8));
    assert_ne!(fp, fingerprint(&k6, &e.kem.public().to_bytes()));
    // Same derivation as the format-2 request fingerprint, other context.
    let ek = d.kem.public();
    assert_ne!(fp, crate::share::fingerprint(&ek, ""));
    // The format-2 fingerprint is unchanged by sharing its derivation.
    let mut ikm = Vec::new();
    for part in [ek.to_bytes().as_slice(), b"Alice".as_slice()] {
        ikm.extend_from_slice(&(part.len() as u32).to_le_bytes());
        ikm.extend_from_slice(part);
    }
    let h = blake3::derive_key("varsto share-request fingerprint v1", &ikm);
    let words = bip39::Language::English.word_list();
    let mut bits: u128 = 0;
    for b in &h[..9] {
        bits = (bits << 8) | *b as u128;
    }
    let old: Vec<&str> = (0..6)
        .map(|i| words[((bits >> (72 - 11 * (i + 1))) & 0x7ff) as usize])
        .collect();
    assert_eq!(crate::share::fingerprint(&ek, "Alice"), old.join(" "));
}

/// A meta for the body checks of the fuzz loop.
fn any_meta(kind: Kind) -> RecordMeta {
    RecordMeta {
        kind,
        vault: VAULT,
        scope: [1; 16],
        device: [2; 16],
        seq: 1,
        parts: 1,
        key_id: KeyId::Registry(0),
        body_hash: [0; 32],
        epoch: Some(1),
        recipient: Some([3; 16]),
        size: 0,
    }
}

fn fuzz_one<T: RecordBody>(rng: &mut rand::rngs::StdRng, kind: Kind, valid: &T) {
    let enc = postcard::to_stdvec(valid).unwrap();
    for _ in 0..2000 {
        let bytes: Vec<u8> = if rng.gen_bool(0.5) {
            let n = rng.gen_range(0..256);
            (0..n).map(|_| rng.gen()).collect()
        } else {
            let mut b = enc.clone();
            for _ in 0..rng.gen_range(1..8) {
                match rng.gen_range(0..3) {
                    0 if !b.is_empty() => {
                        let i = rng.gen_range(0..b.len());
                        b[i] = rng.gen();
                    }
                    1 if !b.is_empty() => {
                        b.truncate(rng.gen_range(0..b.len()));
                    }
                    _ => b.push(rng.gen()),
                }
            }
            b
        };
        let z = zstd::bulk::compress(&bytes, 1).unwrap();
        if let Ok(body) = decode_body::<T>(&z) {
            let _ = body.check(&any_meta(kind));
            let _ = body.embedded_signing_key();
        }
        let mut raw = vec![0u8; rng.gen_range(0..64)];
        rng.fill_bytes(&mut raw);
        let _ = decode_body::<T>(&raw);
    }
}

#[test]
fn body_parsers_survive_random_bytes() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x8a);
    let d = Dev::new();
    let stamp = Stamp {
        lamport: 3,
        device: [2; 16],
    };
    let p = Participant {
        device: [4; 16],
        role: Role::Editor,
        stamp,
    };
    fuzz_one(
        &mut rng,
        Kind::Device,
        &DeviceRecord {
            device: [2; 16],
            name: "x".into(),
            sign_pub: d.sign.public().to_bytes(),
            kem_pub: d.kem.public().to_bytes()[..64].to_vec(),
            stamp,
        },
    );
    fuzz_one(
        &mut rng,
        Kind::Folder,
        &FolderRecord {
            id: [1; 16],
            name: "f".into(),
            settings: BTreeMap::from([("trash_days".into(), "30".into())]),
            stamp,
            creation: Some([5; 16]),
            participants: vec![p],
            denied: vec![Denied {
                device: [6; 16],
                stamp,
            }],
            members: Vec::new(),
        },
    );
    fuzz_one(
        &mut rng,
        Kind::Grant,
        &grants::GrantRecord {
            folder: [1; 16],
            epoch: 1,
            recipient: [3; 16],
            issuer: [2; 16],
            role: Role::Viewer,
            k9: [7; 32],
            k11: [8; 32],
            older: vec![(0, [9; 32])],
        },
    );
    fuzz_one(
        &mut rng,
        Kind::Grant,
        &VaultGrantRecord {
            epoch: 1,
            recipient: [3; 16],
            issuer: [2; 16],
            k3: [7; 32],
        },
    );
    fuzz_one(
        &mut rng,
        Kind::ShareEpoch,
        &FolderEpochRecord {
            folder: [1; 16],
            epoch: 1,
            issuer: [2; 16],
            participants: vec![p],
            removed: vec![Removed {
                device: [6; 16],
                cutoff: 4,
            }],
        },
    );
    fuzz_one(
        &mut rng,
        Kind::Epoch,
        &VaultEpochRecord {
            epoch: 1,
            issuer: [2; 16],
            previous_epoch: 0,
            previous_k3: [7; 32],
            members: vec![[4; 16]],
            revoked: vec![[6; 16]],
        },
    );
    fuzz_one(
        &mut rng,
        Kind::Revocation,
        &RevocationRecord {
            device: [1; 16],
            name: "n".into(),
            issuer: [2; 16],
            cutoff_seq: 4,
            wipe: true,
            new_epoch: 1,
        },
    );
    fuzz_one(
        &mut rng,
        Kind::Request,
        &RequestRecord {
            device: [2; 16],
            name: "n".into(),
            kem_pub: vec![1; 32],
            role_wanted: Role::Editor,
        },
    );
    fuzz_one(
        &mut rng,
        Kind::Escrow,
        &EscrowRecord {
            folder: [1; 16],
            epoch: 1,
            k9: [7; 32],
            k11: [8; 32],
        },
    );
}

#[test]
fn folder_record_replay_converges_in_any_order() {
    // Two owners edit at once: the result does not depend on the order
    // the records are read in.
    let s = Mem::default();
    let st: Vec<&dyn Storage> = vec![&s];
    let keys = VaultKeys::genesis(SecretKey::random());
    let (a, a2, b) = (Dev::new(), Dev::new(), Dev::new());
    let mut ma = device(&st, &a, &keys, "laptop");
    let mut ma2 = device(&st, &a2, &keys, "desktop");
    let mb = device(&st, &b, &keys, "phone");
    ma.refresh().unwrap();
    let f = ma.create_folder("Docs", BTreeMap::new(), None).unwrap();
    ma.approve(&f, &ma2.me.clone(), Role::Owner).unwrap();
    ma2.refresh().unwrap();
    // Concurrent: ma2 approves C without having seen ma's last record.
    let c = Dev::new();
    let mc = device(&st, &c, &keys, "tablet");
    ma2.refresh().unwrap();
    ma.approve(&f, &mb.me.clone(), Role::Viewer).unwrap();
    ma2.approve(&f, &mc.me.clone(), Role::Editor).unwrap();
    // Causally later: ma2 has seen ma's approval of B, then denies B.
    ma2.refresh().unwrap();
    ma2.deny(&f, &mb.me.clone()).unwrap();
    let recs: Vec<crate::record::Record<FolderRecord>> = {
        let mut c = crate::record::RecordsRefused::default();
        super::store::read_all(
            &st,
            VAULT,
            Kind::Folder,
            "vault/folders/",
            &ma.record_keys(),
            &ma.record_trust(),
            &mut c,
        )
        .unwrap()
    };
    let want = FolderState::build(&recs).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    for _ in 0..20 {
        let mut r = recs.clone();
        for i in (1..r.len()).rev() {
            r.swap(i, rng.gen_range(0..=i));
        }
        assert_eq!(FolderState::build(&r).unwrap(), want);
    }
    // ma2's denial came after ma's approval (larger stamp): denied wins.
    assert!(want.is_denied(&mb.me));
    assert_eq!(want.role(&mc.me), Some(Role::Editor));
}

/// The member's own K8 opens a grant sealed to it.
struct MemberKem<'a>(&'a Dev, Id16);

impl crate::record::RecordKeys for MemberKem<'_> {
    fn symmetric(&self, _: &KeyId) -> Option<SecretKey> {
        None
    }
    fn kem_decapsulate(&self, recipient: &Id16, ct: &[u8]) -> Option<Result<SecretKey>> {
        (*recipient == self.1).then(|| self.0.kem.decapsulate(ct))
    }
}

/// Section 9's member rows (work package 12): another person's devices
/// that an owner added to a folder from their request codes are trusted
/// for that folder only, an editor for manifests, maps and trash records
/// and its folder-scoped batches, a viewer for its batches alone. Every
/// owner device learns their keys from the folder record; the grant opens
/// with the member's own K8.
#[test]
fn a_member_of_another_vault_writes_by_the_member_rows() {
    let s = Mem::default();
    let st: Vec<&dyn Storage> = vec![&s];
    let keys = VaultKeys::genesis(SecretKey::random());
    let (a, a2) = (Dev::new(), Dev::new());
    let (friend, guest, stranger) = (Dev::new(), Dev::new(), Dev::new());
    let mut ma = device(&st, &a, &keys, "laptop");
    let mut ma2 = device(&st, &a2, &keys, "desktop");
    ma.refresh().unwrap();
    let f = ma.create_folder("Shared", BTreeMap::new(), None).unwrap();
    let g = ma.create_folder("Private", BTreeMap::new(), None).unwrap();
    ma.approve(&f, &ma2.me.clone(), Role::Owner).unwrap();
    let m = ma
        .add_member(
            &f,
            "friend's phone",
            &friend.sign.public().to_bytes(),
            &friend.kem.public().to_bytes(),
            Role::Editor,
        )
        .unwrap();
    let w = ma
        .add_member(
            &f,
            "guest tablet",
            &guest.sign.public().to_bytes(),
            &guest.kem.public().to_bytes(),
            Role::Viewer,
        )
        .unwrap();
    // A member is never an owner, and a device of the vault is approved.
    assert!(ma
        .add_member(
            &f,
            "x",
            &stranger.sign.public().to_bytes(),
            &stranger.kem.public().to_bytes(),
            Role::Owner
        )
        .is_err());
    assert!(ma
        .add_member(
            &f,
            "x",
            &a2.sign.public().to_bytes(),
            &a2.kem.public().to_bytes(),
            Role::Editor
        )
        .is_err());
    let s_id = device_id(&stranger.sign.public());
    ma2.refresh().unwrap();
    let trust = ma2.record_trust();
    use crate::record::WriterClass;
    assert_eq!(trust.class(&m, &f, 0), WriterClass::MemberEditor);
    assert_eq!(trust.class(&w, &f, 0), WriterClass::MemberViewer);
    assert_eq!(trust.class(&m, &g, 0), WriterClass::Untrusted);
    assert_eq!(trust.class(&s_id, &f, 0), WriterClass::Untrusted);
    assert_eq!(trust.class(&ma2.me, &f, 0), WriterClass::FullOwner);
    let ledger = KeyId::ShareLedger {
        folder: f,
        epoch: 0,
    };
    for kind in [Kind::Manifest, Kind::BlockMap, Kind::Trash] {
        assert!(trust.signer_key(&m, kind, &f).is_some());
        assert!(trust.may_write(&m, kind, &f, &meta(f, 0)), "{kind}");
        assert!(!trust.may_write(&w, kind, &f, &meta(f, 0)), "{kind}");
        assert!(trust.signer_key(&m, kind, &g).is_none());
        assert!(!trust.may_write(&m, kind, &g, &meta(g, 0)));
        assert!(trust.signer_key(&s_id, kind, &f).is_none());
    }
    assert!(trust.may_write(&m, Kind::Batch, &f, &ledger));
    assert!(trust.may_write(&w, Kind::Batch, &f, &ledger));
    assert!(!trust.may_write(&m, Kind::Batch, &[0; 16], &KeyId::Ledger(0)));
    for kind in [Kind::Notes, Kind::Access, Kind::Snapshot] {
        assert!(!trust.may_write(&m, kind, &f, &meta(f, 0)), "{kind}");
    }
    for kind in [Kind::Policy, Kind::Settings, Kind::Peer, Kind::Device] {
        assert!(
            !trust.may_write(&m, kind, &[0; 16], &KeyId::Registry(0)),
            "{kind}"
        );
        assert!(trust.signer_key(&m, kind, &[0; 16]).is_none());
    }
    // What the editor writes in the folder is accepted by an owner device;
    // the viewer's manifest is refused by the acceptance rule.
    let seal = |dev: &Dev, id: Id16, kind: Kind| {
        let signer = DeviceSigner {
            device: id,
            key: &dev.sign,
        };
        let ring = ma.record_keys();
        RecordWriter {
            vault: VAULT,
            signer: &signer,
            keys: &ring,
        }
        .seal(
            &StreamRef::new(kind, f, id),
            1,
            1,
            &meta(f, 0),
            &Note {
                text: "plan.txt".into(),
            },
        )
        .unwrap()
        .parts
    };
    let open = |parts: &[(String, Vec<u8>)]| {
        let keys = ma2.record_keys();
        let trust = ma2.record_trust();
        Acceptor {
            vault: VAULT,
            keys: &keys,
            trust: &trust,
        }
        .open::<Note>(parts)
        .map(|r| r.body.text)
        .map_err(|r| r.reason)
    };
    assert_eq!(open(&seal(&friend, m, Kind::Manifest)).unwrap(), "plan.txt");
    assert_eq!(
        open(&seal(&guest, w, Kind::Manifest)),
        Err(Refusal::Junk(Junk::NotAllowed))
    );
    assert_eq!(
        open(&seal(&stranger, s_id, Kind::Manifest)),
        Err(Refusal::Junk(Junk::UnknownSigner))
    );
    // The grant to the editor opens with its own K8 only.
    let names = s
        .list(&format!("vault/grants/{}/", hex::encode(f)))
        .unwrap();
    let to_m: Vec<&String> = names
        .iter()
        .filter(|n| n.contains(&hex::encode(m)))
        .collect();
    assert_eq!(to_m.len(), 1);
    let env = crate::record::SignedRecord::decode(&s.get(to_m[0]).unwrap().unwrap()).unwrap();
    let body = env.open_part(&MemberKem(&friend, m)).unwrap();
    let grant: grants::GrantRecord = decode_body(&body).unwrap();
    assert_eq!(
        (grant.folder, grant.recipient, grant.role),
        (f, m, Role::Editor)
    );
    assert!(env.open_part(&MemberKem(&guest, m)).is_err());
}
