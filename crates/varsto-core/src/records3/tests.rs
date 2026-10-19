// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Tests of the record bodies of kinds 11, 12, 19, 20, 21 and 22.

use super::*;
use crate::crypto::{SecretKey, SigningKey, VerifyingKey};
use crate::record::{
    Acceptor, DeviceSigner, Junk, KeyId, RecordKeys, RecordTrust, RecordWriter, Refusal,
};
use crate::storage::Storage;
use serde::Serialize;
use std::sync::Mutex;

const VAULT: Id16 = [0x44; 16];
const FOLDER: Id16 = [0x55; 16];

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

/// One key opens everything; the devices given are trusted.
struct World {
    key: SecretKey,
    devices: Vec<(Id16, VerifyingKey)>,
}

impl RecordKeys for World {
    fn symmetric(&self, _: &KeyId) -> Option<SecretKey> {
        Some(self.key.clone())
    }
}

impl RecordTrust for World {
    fn signer_key(&self, device: &Id16, _: Kind, _: &Id16) -> Option<VerifyingKey> {
        self.devices
            .iter()
            .find(|(d, _)| d == device)
            .map(|(_, k)| k.clone())
    }
    fn may_write(&self, _: &Id16, _: Kind, _: &Id16, _: &KeyId) -> bool {
        true
    }
}

struct Dev {
    id: Id16,
    sign: SigningKey,
}

fn dev() -> Dev {
    let sign = SigningKey::generate();
    Dev {
        id: crate::membership3::device_id(&sign.public()),
        sign,
    }
}

fn write<T: Serialize>(
    s: &Mem,
    w: &World,
    d: &Dev,
    stream: &StreamRef,
    seq: u64,
    key: KeyId,
    body: &T,
) {
    let signer = DeviceSigner {
        device: d.id,
        key: &d.sign,
    };
    let sealed = RecordWriter {
        vault: VAULT,
        signer: &signer,
        keys: w,
    }
    .seal(stream, seq, seq, &key, body)
    .unwrap();
    RecordWriter::publish(s, &sealed).unwrap();
}

fn meta(folder: Id16) -> KeyId {
    KeyId::Meta { folder, epoch: 0 }
}

fn policy(min: u32) -> PolicyWire {
    PolicyWire {
        min_copies: min,
        min_per_place: vec![("cloud".into(), 1), ("home".into(), min)],
        verified_within_days: Some(30),
    }
}

/// Every kind round-trips through a storage, the newest record of a
/// writer wins, and per folder the newest entry of any device decides.
#[test]
fn every_kind_round_trips_and_the_newest_wins() {
    let s = Mem::default();
    let (a, b) = (dev(), dev());
    let w = World {
        key: SecretKey::random(),
        devices: vec![(a.id, a.sign.public()), (b.id, b.sign.public())],
    };
    let entry = |p: Option<PolicyWire>, utc: i64| PolicyEntry {
        policy: p,
        updated_utc: utc,
        lamport: 1,
    };
    // Device a: an old record and a newer one; b: a newer policy of FOLDER.
    for (seq, utc) in [(1, 10), (2, 20)] {
        let body = PolicyBody {
            device: a.id,
            seq,
            folders: vec![(FOLDER, entry(Some(policy(seq as u32)), utc))],
        };
        write(
            &s,
            &w,
            &a,
            &policy_stream(a.id),
            seq,
            KeyId::Registry(0),
            &body,
        );
    }
    let body = PolicyBody {
        device: b.id,
        seq: 1,
        folders: vec![
            (FOLDER, entry(None, 30)),
            ([0x66; 16], entry(Some(policy(3)), 5)),
        ],
    };
    write(
        &s,
        &w,
        &b,
        &policy_stream(b.id),
        1,
        KeyId::Registry(0),
        &body,
    );
    let store = RecordStore {
        storage: &s,
        acceptor: Acceptor {
            vault: VAULT,
            keys: &w,
            trust: &w,
        },
    };
    let mut refused = RecordsRefused::default();
    let bodies: Vec<PolicyBody> = read_newest(
        &store,
        &[policy_stream(a.id), policy_stream(b.id)],
        &mut refused,
    )
    .unwrap();
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0].seq, 2);
    let newest = newest_policies(&bodies);
    // b cleared FOLDER's policy later than a set it.
    assert_eq!(newest[&FOLDER], (entry(None, 30), b.id));
    assert_eq!(newest[&[0x66; 16]].0.policy, Some(policy(3)));
    let p: crate::policy::Policy = (&policy(2)).into();
    assert_eq!(PolicyWire::from(&p), policy(2));

    // Placement: newest by (updated_utc, Lamport, device).
    let place = |d: &Dev, utc: i64, storages: Vec<&str>| PlacementBody {
        folder: FOLDER,
        device: d.id,
        seq: 1,
        lamport: 1,
        updated_utc: utc,
        storages: storages.into_iter().map(String::from).collect(),
        storage_ids: vec![("home-disk".into(), "id-1".into())],
        places: Vec::new(),
    };
    write(
        &s,
        &w,
        &a,
        &placement_stream(FOLDER, a.id),
        1,
        KeyId::Registry(0),
        &place(&a, 50, vec!["home-disk"]),
    );
    write(
        &s,
        &w,
        &b,
        &placement_stream(FOLDER, b.id),
        1,
        KeyId::Registry(0),
        &place(&b, 40, vec!["bucket"]),
    );
    let placements: Vec<PlacementBody> = read_newest(
        &store,
        &[
            placement_stream(FOLDER, a.id),
            placement_stream(FOLDER, b.id),
        ],
        &mut refused,
    )
    .unwrap();
    let p = newest_placement(&placements).unwrap();
    assert_eq!(p.device, a.id);
    assert_eq!(p.placement().storages, vec!["home-disk".to_string()]);

    // Storage names.
    let names = StorageNamesBody {
        device: a.id,
        seq: 1,
        updated_utc: 1,
        names: vec![
            ("bucket".into(), "id-2".into()),
            ("home".into(), "id-1".into()),
        ],
        settings: Vec::new(),
    };
    write(
        &s,
        &w,
        &a,
        &storage_names_stream(a.id),
        1,
        KeyId::Registry(0),
        &names,
    );
    let got: Vec<StorageNamesBody> =
        read_newest(&store, &[storage_names_stream(a.id)], &mut refused).unwrap();
    assert_eq!(got, vec![names]);

    // Access: newest time per path over both devices.
    for (d, t) in [(&a, 100), (&b, 200)] {
        let body = AccessBody {
            folder: FOLDER,
            device: d.id,
            seq: 1,
            updated_utc: t,
            accessed: vec![("docs/a.txt".into(), t), ("docs/b.txt".into(), 300 - t)],
        };
        write(
            &s,
            &w,
            d,
            &access_stream(FOLDER, d.id),
            1,
            meta(FOLDER),
            &body,
        );
    }
    let access: Vec<AccessBody> = read_newest(
        &store,
        &[access_stream(FOLDER, a.id), access_stream(FOLDER, b.id)],
        &mut refused,
    )
    .unwrap();
    let merged = merged_access(&access);
    assert_eq!(merged["docs/a.txt"], 200);
    assert_eq!(merged["docs/b.txt"], 200);

    // Notes: newest analysis per path.
    let note = |text: &str, utc: i64| NoteWire {
        analysis: text.into(),
        tags: vec!["invoice".into()],
        content_hash: "ab".repeat(32),
        by: Some("a model".into()),
        analysed_utc: utc,
    };
    for (d, text, utc) in [(&a, "old", 1), (&b, "new", 2)] {
        let body = NotesBody {
            folder: FOLDER,
            device: d.id,
            seq: 1,
            updated_utc: utc,
            notes: vec![("docs/a.txt".into(), note(text, utc))],
        };
        write(
            &s,
            &w,
            d,
            &notes_stream(FOLDER, d.id),
            1,
            meta(FOLDER),
            &body,
        );
    }
    let notes: Vec<NotesBody> = read_newest(
        &store,
        &[notes_stream(FOLDER, a.id), notes_stream(FOLDER, b.id)],
        &mut refused,
    )
    .unwrap();
    assert_eq!(merged_notes(&notes)["docs/a.txt"], (note("new", 2), b.id));

    // Thumbnails add up over a writer's records.
    for (seq, hash) in [(1u64, [1u8; 32]), (2, [2; 32])] {
        let body = ThumbsBody {
            folder: FOLDER,
            device: a.id,
            seq,
            thumbs: vec![(hash, vec![seq as u8; 100])],
        };
        write(
            &s,
            &w,
            &a,
            &thumbs_stream(FOLDER, a.id),
            seq,
            meta(FOLDER),
            &body,
        );
    }
    let thumbs: Vec<ThumbsBody> =
        read_all(&store, &thumbs_stream(FOLDER, a.id), &mut refused).unwrap();
    let all = thumbnails(&thumbs);
    assert_eq!(all.len(), 2);
    assert_eq!(all[&[2u8; 32]], &[2u8; 100][..]);
    // Thumbnails are padded to the record classes like every body.
    let names = s.list("thumbs/").unwrap();
    assert!(names
        .iter()
        .all(|n| s.get(n).unwrap().unwrap().len() >= 64 << 10));
    assert_eq!(refused.total(), 0);
}

/// Step 6 of the acceptance rule: a body that names another writer, seq or
/// folder than its envelope, or breaks its limits, is junk.
#[test]
fn bodies_that_disagree_with_their_envelope_or_limits_are_refused() {
    let s = Mem::default();
    let (a, b) = (dev(), dev());
    let w = World {
        key: SecretKey::random(),
        devices: vec![(a.id, a.sign.public()), (b.id, b.sign.public())],
    };
    let store = RecordStore {
        storage: &s,
        acceptor: Acceptor {
            vault: VAULT,
            keys: &w,
            trust: &w,
        },
    };
    let junk = |stream: &StreamRef, refused: &mut RecordsRefused| -> Vec<Refusal> {
        store
            .read_after::<AccessBody>(stream, 0, refused)
            .unwrap()
            .refused
            .into_iter()
            .map(|r| r.reason)
            .collect()
    };
    let mut refused = RecordsRefused::default();
    // Another device named in the body.
    let other_writer = AccessBody {
        folder: FOLDER,
        device: b.id,
        seq: 1,
        updated_utc: 1,
        accessed: Vec::new(),
    };
    write(
        &s,
        &w,
        &a,
        &access_stream(FOLDER, a.id),
        1,
        meta(FOLDER),
        &other_writer,
    );
    let r = junk(&access_stream(FOLDER, a.id), &mut refused);
    assert!(matches!(r.as_slice(), [Refusal::Junk(Junk::BadBody(_))]));
    // Paths out of order, and a path that is not a synced path.
    for (seq, accessed) in [
        (2u64, vec![("b".to_string(), 1), ("a".to_string(), 1)]),
        (3, vec![("../etc/passwd".to_string(), 1)]),
    ] {
        let body = AccessBody {
            folder: FOLDER,
            device: a.id,
            seq,
            updated_utc: 1,
            accessed,
        };
        write(
            &s,
            &w,
            &a,
            &access_stream(FOLDER, a.id),
            seq,
            meta(FOLDER),
            &body,
        );
    }
    let r = junk(&access_stream(FOLDER, a.id), &mut refused);
    assert_eq!(r.len(), 3);
    // A body for another folder than the record's scope.
    let other = [0x77; 16];
    let body = NotesBody {
        folder: other,
        device: a.id,
        seq: 1,
        updated_utc: 1,
        notes: Vec::new(),
    };
    write(
        &s,
        &w,
        &a,
        &notes_stream(FOLDER, a.id),
        1,
        meta(FOLDER),
        &body,
    );
    let r = store
        .read_after::<NotesBody>(&notes_stream(FOLDER, a.id), 0, &mut refused)
        .unwrap();
    assert!(r.accepted.is_empty() && r.refused.len() == 1);
    // A policy record with a scope is not a policy record.
    let body = PolicyBody {
        device: a.id,
        seq: 1,
        folders: Vec::new(),
    };
    let meta_of = |scope: Id16| RecordMeta {
        kind: Kind::Policy,
        vault: VAULT,
        scope,
        device: a.id,
        seq: 1,
        parts: 1,
        key_id: KeyId::Registry(0),
        body_hash: [0; 32],
        epoch: None,
        recipient: None,
        size: 0,
    };
    assert!(body.check(&meta_of([0; 16])).is_ok());
    assert!(body.check(&meta_of(FOLDER)).is_err());
    // Oversize thumbnails and analyses.
    let t = ThumbsBody {
        folder: FOLDER,
        device: a.id,
        seq: 1,
        thumbs: vec![([1; 32], vec![0; MAX_THUMB + 1])],
    };
    let mut m = meta_of(FOLDER);
    m.kind = Kind::Thumbs;
    assert!(t.check(&m).is_err());
    let n = NotesBody {
        folder: FOLDER,
        device: a.id,
        seq: 1,
        updated_utc: 1,
        notes: vec![(
            "a.txt".into(),
            NoteWire {
                analysis: "x".repeat(MAX_ANALYSIS + 1),
                tags: Vec::new(),
                content_hash: String::new(),
                by: None,
                analysed_utc: 1,
            },
        )],
    };
    m.kind = Kind::Notes;
    assert!(n.check(&m).is_err());
    assert!(refused.total() >= 4);
}
