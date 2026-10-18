// SPDX-License-Identifier: PolyForm-Shield-1.0.0
use super::*;
use crate::crypto::{SecretKey, SigningKey, VerifyingKey};
use crate::kem::{DecapsKey, EncapsKey};
use crate::storage::Storage;
use anyhow::Result;
use rand::{Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

const VAULT: Id16 = [0x11; 16];
const FOLDER: Id16 = [0x22; 16];
const OTHER: Id16 = [0x33; 16];

/// A storage in memory.
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

/// A device: id, signing key, KEM key.
struct Dev {
    id: Id16,
    sk: SigningKey,
    kem: DecapsKey,
}

impl Dev {
    fn new(n: u8) -> Dev {
        Dev {
            id: [n; 16],
            sk: SigningKey::generate(),
            kem: DecapsKey::generate(),
        }
    }
    /// A device whose id is the first 16 bytes of BLAKE3 of its public key.
    fn self_named() -> Dev {
        let sk = SigningKey::generate();
        let mut id = [0u8; 16];
        id.copy_from_slice(&crate::crypto::hash(&sk.public().to_bytes())[..16]);
        Dev {
            id,
            sk,
            kem: DecapsKey::generate(),
        }
    }
    fn signer(&self) -> DeviceSigner<'_> {
        DeviceSigner {
            device: self.id,
            key: &self.sk,
        }
    }
}

/// Keys of one device: symmetric keys by key_id, its own KEM key and the
/// KEM public keys of others.
#[derive(Default)]
struct Keys {
    sym: HashMap<KeyId, SecretKey>,
    own: Option<(Id16, Vec<u8>)>,
    kem_pub: HashMap<Id16, Vec<u8>>,
}

impl RecordKeys for Keys {
    fn symmetric(&self, key_id: &KeyId) -> Option<SecretKey> {
        self.sym.get(key_id).cloned()
    }
    fn kem_public(&self, recipient: &Id16) -> Option<EncapsKey> {
        EncapsKey::from_bytes(self.kem_pub.get(recipient)?).ok()
    }
    fn kem_decapsulate(&self, recipient: &Id16, ct: &[u8]) -> Option<Result<SecretKey>> {
        let (id, raw) = self.own.as_ref()?;
        if id != recipient {
            return None;
        }
        Some(DecapsKey::from_bytes(raw).and_then(|k| k.decapsulate(ct)))
    }
}

/// Trust: device keys, an allow-everything role check unless denied, and
/// announcements.
#[derive(Default)]
struct Trust {
    keys: HashMap<Id16, Vec<u8>>,
    denied: Vec<(Id16, Kind)>,
    ann: RefCell<HashMap<(Id16, Kind, Id16, u64), Announced>>,
}

impl Trust {
    fn announce(&self, device: Id16, p: &RecordPublished) {
        self.ann.borrow_mut().insert(
            (device, Kind::from_code(p.kind).unwrap(), p.scope, p.seq),
            Announced {
                parts: p.parts,
                body_hash: p.body_hash,
                base: p.base,
            },
        );
    }
}

impl RecordTrust for Trust {
    fn signer_key(&self, device: &Id16, _kind: Kind, _scope: &Id16) -> Option<VerifyingKey> {
        VerifyingKey::from_bytes(self.keys.get(device)?).ok()
    }
    fn may_write(&self, device: &Id16, kind: Kind, _scope: &Id16, _key_id: &KeyId) -> bool {
        !self.denied.contains(&(*device, kind))
    }
    fn announcement(&self, device: &Id16, kind: Kind, scope: &Id16, seq: u64) -> Option<Announced> {
        self.ann
            .borrow()
            .get(&(*device, kind, *scope, seq))
            .cloned()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Body {
    seq: u64,
    base: u64,
    prev: [u8; 32],
    data: Vec<u8>,
}

impl RecordBody for Body {
    fn base(&self) -> Option<u64> {
        Some(self.base)
    }
    fn prev(&self) -> Option<[u8; 32]> {
        Some(self.prev)
    }
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if self.seq != meta.seq {
            return Err("seq differs from the envelope".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct DeviceBody {
    name: String,
    key: Vec<u8>,
}

impl RecordBody for DeviceBody {
    fn embedded_signing_key(&self) -> Option<Vec<u8>> {
        Some(self.key.clone())
    }
}

fn body(seq: u64, data: &[u8]) -> Body {
    Body {
        seq,
        base: seq,
        prev: [0; 32],
        data: data.to_vec(),
    }
}

/// A world with two devices A (writer) and B (reader) that hold every
/// symmetric key and trust each other.
struct World {
    a: Dev,
    b: Dev,
    keys_a: Keys,
    keys_b: Keys,
    trust: Trust,
}

fn all_sym_keys() -> Vec<KeyId> {
    vec![
        KeyId::Registry(0),
        KeyId::Registry(1),
        KeyId::Ledger(0),
        KeyId::Epoch(0),
        KeyId::Meta {
            folder: FOLDER,
            epoch: 0,
        },
        KeyId::Meta {
            folder: FOLDER,
            epoch: 3,
        },
        KeyId::ShareLedger {
            folder: FOLDER,
            epoch: 0,
        },
        KeyId::Recovery,
        KeyId::Replica,
    ]
}

impl World {
    fn new() -> World {
        let a = Dev::new(0xa1);
        let b = Dev::new(0xb2);
        let mut keys_a = Keys::default();
        let mut keys_b = Keys::default();
        for k in all_sym_keys() {
            let s = SecretKey::random();
            keys_a.sym.insert(k.clone(), s.clone());
            keys_b.sym.insert(k, s);
        }
        keys_a.kem_pub.insert(b.id, b.kem.public().to_bytes());
        keys_a.own = Some((a.id, a.kem.to_bytes()));
        keys_b.own = Some((b.id, b.kem.to_bytes()));
        let mut trust = Trust::default();
        trust.keys.insert(a.id, a.sk.public().to_bytes());
        trust.keys.insert(b.id, b.sk.public().to_bytes());
        World {
            a,
            b,
            keys_a,
            keys_b,
            trust,
        }
    }
    fn acceptor(&self) -> Acceptor<'_> {
        Acceptor {
            vault: VAULT,
            keys: &self.keys_b,
            trust: &self.trust,
        }
    }
    fn seal(&self, stream: &StreamRef, seq: u64, key: &KeyId, b: &Body) -> SealedRecord {
        let signer = self.a.signer();
        RecordWriter {
            vault: VAULT,
            signer: &signer,
            keys: &self.keys_a,
        }
        .seal(stream, seq, b.base, key, b)
        .unwrap()
    }
}

fn meta0() -> KeyId {
    KeyId::Meta {
        folder: FOLDER,
        epoch: 0,
    }
}

fn manifest_stream(dev: Id16) -> StreamRef {
    StreamRef::new(Kind::Manifest, FOLDER, dev)
}

/// One stream and key_id per kind code, as a writer would use them.
fn stream_for(kind: Kind, a: Id16, b: Id16) -> (StreamRef, KeyId, u64) {
    let seq = 3;
    match kind {
        Kind::Manifest
        | Kind::BlockMap
        | Kind::Trash
        | Kind::Access
        | Kind::Notes
        | Kind::Thumbs
        | Kind::Placement
        | Kind::Folder
        | Kind::Request => {
            let key = if matches!(kind, Kind::Placement | Kind::Folder | Kind::Request) {
                KeyId::Registry(0)
            } else {
                meta0()
            };
            (StreamRef::new(kind, FOLDER, a), key, seq)
        }
        Kind::Snapshot => (StreamRef::new(kind, OTHER, a), meta0(), seq),
        Kind::Peer
        | Kind::Policy
        | Kind::Settings
        | Kind::StorageNames
        | Kind::Device
        | Kind::Replica
        | Kind::OrgManifest
        | Kind::OrgRoster
        | Kind::OrgLog
        | Kind::Mailbox => (StreamRef::new(kind, [0; 16], a), KeyId::Registry(0), seq),
        Kind::Strongroom => (StreamRef::new(kind, FOLDER, a), KeyId::Registry(0), seq),
        Kind::Epoch => (StreamRef::new(kind, [0; 16], a), KeyId::Epoch(0), 1),
        Kind::ShareEpoch => (
            StreamRef::new(kind, FOLDER, a),
            KeyId::Meta {
                folder: FOLDER,
                epoch: 3,
            },
            3,
        ),
        Kind::Grant => (StreamRef::grant(FOLDER, 2, b, a), KeyId::Kem(b), 1),
        Kind::Revocation => (StreamRef::new(kind, b, a), KeyId::Registry(0), 1),
        Kind::Checkpoint => (StreamRef::new(kind, [0; 16], a), KeyId::Ledger(0), seq),
        Kind::Batch => (StreamRef::new(kind, [0; 16], a), KeyId::Ledger(0), seq),
        Kind::Escrow => (StreamRef::escrow(FOLDER, 4, a), KeyId::Recovery, 1),
    }
}

fn expect_accepted<T: std::fmt::Debug>(o: Outcome<T>) -> Record<T> {
    match o {
        Outcome::Accepted(r) => r,
        other => panic!("not accepted: {other:?}"),
    }
}

fn expect_junk<T: std::fmt::Debug>(o: Outcome<T>) -> Junk {
    match o {
        Outcome::Refused(Refused {
            reason: Refusal::Junk(j),
            ..
        }) => j,
        other => panic!("not junk: {other:?}"),
    }
}

#[test]
fn key_ids_parse_and_format_one_spelling() {
    let f = hex::encode(FOLDER);
    for k in all_sym_keys().into_iter().chain([
        KeyId::Kem([9; 16]),
        KeyId::None,
        KeyId::Epoch(4_000_000_000),
    ]) {
        let s = k.to_string();
        assert!(s.len() <= MAX_KEY_ID, "{s}");
        assert_eq!(KeyId::parse(&s), Some(k), "{s}");
    }
    assert_eq!(
        KeyId::parse(&format!("meta:{f}@12")),
        Some(KeyId::Meta {
            folder: FOLDER,
            epoch: 12
        })
    );
    for bad in [
        "",
        "registry",
        "registry@",
        "registry@01",
        "registry@+1",
        "registry@-1",
        "registry@4294967296",
        "ledger@ 1",
        "Recovery",
        "kem:",
        &format!("kem:{}", "AB".repeat(16)),
        &format!("kem:{f}00"),
        &format!("meta:{f}"),
        &format!("meta:{}@0", &f[..30]),
        &format!("share-ledger:{f}@x"),
        "folder@1",
        &format!("share-ledger:{f}@0000000000000000000000000000000000"),
    ] {
        assert_eq!(KeyId::parse(bad), None, "{bad:?}");
    }
    // `share-ledger:<32 hex>@<10 digits>` is the longest form and fits.
    let longest = format!("share-ledger:{f}@4294967295");
    assert!(longest.len() <= MAX_KEY_ID);
    assert!(KeyId::parse(&format!("{longest}0")).is_none());
}

#[test]
fn every_kind_code_has_a_name_and_round_trips() {
    for (i, k) in Kind::ALL.iter().enumerate() {
        assert_eq!(k.code() as usize, i + 1);
        assert_eq!(Kind::from_code(k.code()), Some(*k));
    }
    assert_eq!(Kind::from_code(0), None);
    assert_eq!(Kind::from_code(29), None);
    let (a, b) = ([0xa1; 16], [0xb2; 16]);
    for k in Kind::ALL {
        let (stream, _, seq) = stream_for(k, a, b);
        let name = stream.part_name(seq, 7).unwrap();
        assert!(name.ends_with(&format!("{seq:016}-0007.rec")), "{name}");
        let n = RecordName::parse(&name).unwrap();
        assert_eq!(n.kind, k, "{name}");
        assert_eq!((n.seq, n.part), (seq, 7));
        if k.device_in_name() {
            assert_eq!(n.device, Some(a));
        }
        if k.scope_in_name() {
            assert_eq!(n.scope, stream.scope);
        }
        assert_eq!(n.epoch, stream.epoch);
        assert_eq!(n.recipient, stream.recipient);
        assert!(name.starts_with(&stream.prefix().unwrap()));
    }
    let a_hex = hex::encode(a);
    let f = hex::encode(FOLDER);
    assert_eq!(
        StreamRef::new(Kind::BlockMap, FOLDER, a)
            .part_name(17, 0)
            .unwrap(),
        format!("maps/{f}/{a_hex}/0000000000000017-0000.rec")
    );
    assert_eq!(
        StreamRef::new(Kind::Checkpoint, [0; 16], a)
            .part_name(5, 1)
            .unwrap(),
        format!("ledger/{a_hex}/checkpoint-0000000000000005-0001.rec")
    );
    assert_eq!(
        StreamRef::grant([0; 16], 2, b, a).part_name(1, 0).unwrap(),
        format!(
            "vault/grants/vault/0000000002/{}/{a_hex}/0000000000000001-0000.rec",
            hex::encode(b)
        )
    );
    assert_eq!(
        StreamRef::new(Kind::Epoch, [0; 16], a)
            .part_name(2, 0)
            .unwrap(),
        "vault/epochs/0000000000000002-0000.rec"
    );
    // Checkpoint names sort after every batch name of the device.
    let batch = StreamRef::new(Kind::Batch, [0; 16], a).part_name(u64::MAX / 2, 1023);
    let cp = StreamRef::new(Kind::Checkpoint, [0; 16], a).part_name(1, 0);
    assert!(cp > batch);
    // Names of another spelling do not parse.
    for bad in [
        format!("maps/{f}/{a_hex}/17-0000.rec"),
        format!("maps/{f}/{a_hex}/0000000000000017-0000.json"),
        format!("maps/{f}/{a_hex}/0000000000000017-00000.rec"),
        format!("maps/{}/{a_hex}/0000000000000017-0000.rec", "AB".repeat(16)),
        format!("maps/{f}/{a_hex}/x/0000000000000017-0000.rec"),
        format!(
            "vault/grants/{}/0000000002/{a_hex}/{a_hex}/0000000000000001-0000.rec",
            hex::encode([0u8; 16])
        ),
    ] {
        assert_eq!(RecordName::parse(&bad), None, "{bad}");
    }
}

#[test]
fn a_record_of_every_kind_round_trips() {
    let w = World::new();
    for k in Kind::ALL {
        let (stream, key, seq) = stream_for(k, w.a.id, w.b.id);
        let b = body(seq, format!("{k} body").as_bytes());
        let sealed = if k == Kind::Device {
            // A device record is signed by the key it carries.
            let d = Dev::self_named();
            let db = DeviceBody {
                name: "laptop".into(),
                key: d.sk.public().to_bytes(),
            };
            let signer = d.signer();
            let wr = RecordWriter {
                vault: VAULT,
                signer: &signer,
                keys: &w.keys_a,
            };
            let s = wr
                .seal(&StreamRef::new(k, [0; 16], d.id), 1, 1, &key, &db)
                .unwrap();
            let r = expect_accepted(w.acceptor().accept::<DeviceBody>(&s.parts));
            assert_eq!(r.body, db);
            // Under another device id the same record is refused.
            let wrong = Dev::new(0x77);
            let signer = DeviceSigner {
                device: wrong.id,
                key: &d.sk,
            };
            let wr = RecordWriter {
                vault: VAULT,
                signer: &signer,
                keys: &w.keys_a,
            };
            let s = wr
                .seal(&StreamRef::new(k, [0; 16], wrong.id), 1, 1, &key, &db)
                .unwrap();
            assert_eq!(
                expect_junk(w.acceptor().accept::<DeviceBody>(&s.parts)),
                Junk::BadSignature
            );
            continue;
        } else {
            w.seal(&stream, seq, &key, &b)
        };
        assert_eq!(sealed.parts.len(), 1);
        assert_eq!(sealed.published.kind, k.code());
        assert_eq!(sealed.published.seq, seq);
        assert_eq!(sealed.published.size, sealed.parts[0].1.len() as u64);
        if k.announced() {
            // Not yet announced: it waits.
            assert!(matches!(
                w.acceptor().accept::<Body>(&sealed.parts),
                Outcome::Waiting(_)
            ));
            w.trust.announce(w.a.id, &sealed.published);
        }
        let r = expect_accepted(w.acceptor().accept::<Body>(&sealed.parts));
        assert_eq!(r.body, b, "{k}");
        assert_eq!(r.meta.kind, k);
        assert_eq!(r.meta.key_id, key);
        assert_eq!(r.meta.body_hash, sealed.published.body_hash);
        assert_eq!(r.meta.epoch, stream.epoch);
    }
}

#[test]
fn a_grant_opens_only_for_its_recipient() {
    let w = World::new();
    let (stream, key, seq) = stream_for(Kind::Grant, w.a.id, w.b.id);
    let s = w.seal(&stream, seq, &key, &body(seq, b"K9"));
    // B opens it; A (the issuer) holds no decapsulation key for B.
    expect_accepted(w.acceptor().accept::<Body>(&s.parts));
    let as_a = Acceptor {
        vault: VAULT,
        keys: &w.keys_a,
        trust: &w.trust,
    };
    assert_eq!(expect_junk(as_a.accept::<Body>(&s.parts)), Junk::KeyNotHeld);
    // Under another recipient's name it is refused.
    let moved = s.parts[0]
        .0
        .replace(&hex::encode(w.b.id), &hex::encode(w.a.id));
    let parts = vec![(moved, s.parts[0].1.clone())];
    assert!(matches!(
        expect_junk(w.acceptor().accept::<Body>(&parts)),
        Junk::NameMismatch(_)
    ));
}

#[test]
fn bodies_land_on_size_classes_with_random_tails() {
    let w = World::new();
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    for len in [
        0usize,
        1,
        1000,
        60 << 10,
        64 << 10,
        (4 << 20) - 100,
        (4 << 20) + 1,
        9 << 20,
    ] {
        let mut data = vec![0u8; len];
        rng.fill_bytes(&mut data);
        let b = body(1, &data);
        let s = w.seal(&manifest_stream(w.a.id), 1, &meta0(), &b);
        let env = SignedRecord::decode(&s.parts[0].1).unwrap();
        let n = env.body.len();
        assert!(pad::is_class(n), "{len}: {n}");
        if n < pad::LARGE_FROM {
            assert_eq!(n % (64 << 10), 0);
        } else {
            assert_eq!(n % (1 << 20), 0);
        }
        // The smallest class that holds nonce, tag, `len` and the data.
        let compressed = zstd::bulk::compress(&postcard::to_stdvec(&b).unwrap(), 3).unwrap();
        assert_eq!(n, pad::class_for(40 + 4 + compressed.len()), "{len}");
        w.trust.announce(w.a.id, &s.published);
        assert_eq!(
            expect_accepted(w.acceptor().accept::<Body>(&s.parts)).body,
            b
        );
    }
    // The tail is random: two seals of one body differ after `len`, and
    // the reader takes `len`, not the whole plaintext.
    let key = w.keys_a.sym[&meta0()].clone();
    let b = body(1, b"short");
    let s1 = w.seal(&manifest_stream(w.a.id), 1, &meta0(), &b);
    let s2 = w.seal(&manifest_stream(w.a.id), 1, &meta0(), &b);
    let open = |s: &SealedRecord| {
        let e = SignedRecord::decode(&s.parts[0].1).unwrap();
        let aad = envelope::body_aad(Kind::Manifest, &VAULT, &FOLDER, &w.a.id, 1, 0, 1, &e.key_id);
        crate::crypto::decrypt(&key, &aad, &e.body).unwrap()
    };
    let (p1, p2) = (open(&s1), open(&s2));
    assert_eq!(p1.len(), p2.len());
    let len = u32::from_le_bytes(p1[..4].try_into().unwrap()) as usize;
    assert_eq!(&p1[..4 + len], &p2[..4 + len]);
    assert_ne!(&p1[4 + len..], &p2[4 + len..]);
    assert!(p1[4 + len..].iter().any(|&x| x != 0));
    assert_eq!(pad::unframe(&p1).unwrap().len(), len);
    // A `len` past the end does not open.
    let mut bad = p1.clone();
    bad[..4].copy_from_slice(&(p1.len() as u32).to_le_bytes());
    assert!(pad::unframe(&bad).is_none());
    assert_eq!(pad::class_for(0), 64 << 10);
    assert_eq!(pad::class_for(4 << 20), 4 << 20);
    assert_eq!(pad::class_for((4 << 20) + 1), 5 << 20);
    assert_eq!(pad::class_for((4 << 20) - 1), 4 << 20);
    assert!(!pad::is_class((4 << 20) + (64 << 10)));
}

#[test]
fn large_records_split_into_parts_and_join_again() {
    let w = World::new();
    let mut data = vec![0u8; 40 << 20];
    rand::rngs::StdRng::seed_from_u64(3).fill_bytes(&mut data);
    let b = body(1, &data);
    let stream = manifest_stream(w.a.id);
    let s = w.seal(&stream, 1, &meta0(), &b);
    assert_eq!(s.parts.len(), 2);
    assert_eq!(s.published.parts, 2);
    let envs: Vec<SignedRecord> = s
        .parts
        .iter()
        .map(|(_, b)| SignedRecord::decode(b).unwrap())
        .collect();
    assert_eq!(envs[0].body.len(), MAX_PART_BODY);
    assert!(envs
        .iter()
        .all(|e| e.parts == 2 && pad::is_class(e.body.len())));
    assert!(s.parts.iter().all(|(_, b)| b.len() as u64 <= MAX_PART_READ));
    let mut h = blake3::Hasher::new();
    h.update(&envs[0].body_hash);
    h.update(&envs[1].body_hash);
    assert_eq!(s.published.body_hash, *h.finalize().as_bytes());
    assert_eq!(
        s.published.size,
        s.parts.iter().map(|(_, b)| b.len() as u64).sum::<u64>()
    );
    w.trust.announce(w.a.id, &s.published);
    // Parts in any order join in part order.
    let reversed: Vec<_> = s.parts.iter().rev().cloned().collect();
    assert_eq!(
        expect_accepted(w.acceptor().accept::<Body>(&reversed)).body,
        b
    );
    // A missing part: incomplete, not junk.
    match w.acceptor().accept::<Body>(&s.parts[..1]) {
        Outcome::Refused(r) => {
            assert_eq!(r.reason, Refusal::Incomplete { have: 1, parts: 2 });
            assert!(!r.counts());
        }
        other => panic!("{other:?}"),
    }
    // The same part twice.
    let twice = vec![s.parts[0].clone(), s.parts[0].clone()];
    assert_eq!(
        expect_junk(w.acceptor().accept::<Body>(&twice)),
        Junk::PartsDisagree
    );
    // A part from another sealing of the same record: each part verifies,
    // the joined hash is not the announced one.
    let other = w.seal(&stream, 1, &meta0(), &b);
    let mixed = vec![s.parts[0].clone(), other.parts[1].clone()];
    match w.acceptor().accept::<Body>(&mixed) {
        Outcome::Refused(r) => assert_eq!(r.reason, Refusal::Forked),
        other => panic!("{other:?}"),
    }
    // Part 1 named as part 0's object.
    let renamed = vec![
        (s.parts[0].0.clone(), s.parts[1].1.clone()),
        (s.parts[1].0.clone(), s.parts[0].1.clone()),
    ];
    assert_eq!(
        expect_junk(w.acceptor().accept::<Body>(&renamed)),
        Junk::NameMismatch("part")
    );
}

/// Re-encode an envelope after changing it (no new signature).
fn mutate(bytes: &[u8], f: impl FnOnce(&mut SignedRecord)) -> Vec<u8> {
    let mut e = SignedRecord::decode(bytes).unwrap();
    f(&mut e);
    e.encode()
}

/// Re-encode and re-sign with `sk` (an attacker holding a device key, or
/// a test of a check that comes after the signature).
fn resign(bytes: &[u8], sk: &SigningKey, f: impl FnOnce(&mut SignedRecord)) -> Vec<u8> {
    let mut e = SignedRecord::decode(bytes).unwrap();
    f(&mut e);
    e.body_hash = crate::crypto::hash(&e.body);
    e.sig = sk.sign(&envelope::signed_message(
        e.kind,
        &e.vault,
        &e.scope,
        &e.device,
        e.seq,
        e.part,
        e.parts,
        &e.key_id,
        &e.body_hash,
    ));
    e.encode()
}

#[test]
fn refusals() {
    let w = World::new();
    let stream = manifest_stream(w.a.id);
    let b = body(5, b"files");
    let s = w.seal(&stream, 5, &meta0(), &b);
    w.trust.announce(w.a.id, &s.published);
    let (name, bytes) = s.parts[0].clone();
    let acc = w.acceptor();
    let one = |n: &str, b: Vec<u8>| vec![(n.to_string(), b)];
    expect_accepted(acc.accept::<Body>(&one(&name, bytes.clone())));

    // Wrong magic, wrong format.
    let mut m = bytes.clone();
    m[3] = b'2';
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::BadMagic
    );
    let m = mutate(&bytes, |e| e.format = 2);
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::WrongFormat(2)
    );
    // Trailing bytes.
    let mut m = bytes.clone();
    m.push(0);
    assert!(matches!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::Malformed(_)
    ));
    // Another vault.
    let other_vault = Acceptor {
        vault: [0x99; 16],
        keys: &w.keys_b,
        trust: &w.trust,
    };
    assert_eq!(
        expect_junk(other_vault.accept::<Body>(&one(&name, bytes.clone()))),
        Junk::WrongVault
    );
    // Moved: other seq, other device, other folder, other kind's prefix.
    for (what, moved) in [
        ("seq", stream.part_name(6, 0).unwrap()),
        ("device", manifest_stream(w.b.id).part_name(5, 0).unwrap()),
        (
            "scope",
            StreamRef::new(Kind::Manifest, OTHER, w.a.id)
                .part_name(5, 0)
                .unwrap(),
        ),
        (
            "kind",
            StreamRef::new(Kind::Trash, FOLDER, w.a.id)
                .part_name(5, 0)
                .unwrap(),
        ),
    ] {
        assert_eq!(
            expect_junk(acc.accept::<Body>(&one(&moved, bytes.clone()))),
            Junk::NameMismatch(what),
            "{what}"
        );
    }
    // Bad signature: a flipped signature byte; a relabelled key_id (a
    // valid one of the same class); a body swapped from another record.
    let m = mutate(&bytes, |e| e.sig[100] ^= 1);
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::BadSignature
    );
    let m = mutate(&bytes, |e| {
        e.key_id = KeyId::Meta {
            folder: FOLDER,
            epoch: 3,
        }
        .to_string()
    });
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::BadSignature
    );
    let s2 = w.seal(&stream, 5, &meta0(), &body(5, b"other files"));
    let other_body = SignedRecord::decode(&s2.parts[0].1).unwrap().body;
    let m = mutate(&bytes, |e| e.body = other_body.clone());
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::BadSignature
    );
    let m = mutate(&bytes, |e| e.body_hash = crate::crypto::hash(&other_body));
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::BadSignature
    );
    // Unknown signer, writer not allowed.
    let stranger = Dev::new(0x55);
    let m = resign(&bytes, &stranger.sk, |_| {});
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::BadSignature
    );
    let strangers = StreamRef::new(Kind::Manifest, FOLDER, stranger.id);
    let m = resign(&bytes, &stranger.sk, |e| e.device = stranger.id);
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&strangers.part_name(5, 0).unwrap(), m))),
        Junk::UnknownSigner
    );
    let denied = Trust {
        keys: w.trust.keys.clone(),
        denied: vec![(w.a.id, Kind::Manifest)],
        ..Default::default()
    };
    let deny = Acceptor {
        vault: VAULT,
        keys: &w.keys_b,
        trust: &denied,
    };
    assert_eq!(
        expect_junk(deny.accept::<Body>(&one(&name, bytes.clone()))),
        Junk::NotAllowed
    );
    // Unknown key_id: not held, not of the grammar, not of the kind,
    // longer than 64 bytes.
    let m = resign(&bytes, &w.a.sk, |e| {
        e.key_id = KeyId::Meta {
            folder: FOLDER,
            epoch: 9,
        }
        .to_string()
    });
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::KeyNotHeld
    );
    let m = resign(&bytes, &w.a.sk, |e| e.key_id = "meta:zz@0".into());
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::BadKeyId
    );
    let m = resign(&bytes, &w.a.sk, |e| e.key_id = "ledger@0".into());
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::KeyNotForKind
    );
    let m = resign(&bytes, &w.a.sk, |e| {
        e.key_id = format!("{}x", "a".repeat(64))
    });
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::KeyIdTooLong
    );
    // A body that does not open: right key_id, another key behind it.
    let mut keys_c = Keys::default();
    keys_c.sym.insert(meta0(), SecretKey::random());
    let c = Acceptor {
        vault: VAULT,
        keys: &keys_c,
        trust: &w.trust,
    };
    assert_eq!(
        expect_junk(c.accept::<Body>(&one(&name, bytes.clone()))),
        Junk::BodyDoesNotOpen
    );
    // Body bytes re-signed by the writer but tampered: does not open.
    let m = resign(&bytes, &w.a.sk, |e| e.body[50] ^= 1);
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::BodyDoesNotOpen
    );
    // Oversize part, body length not a class, empty body.
    let m = resign(&bytes, &w.a.sk, |e| {
        e.body = vec![0; MAX_PART_BODY + (1 << 20)]
    });
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::OversizePart
    );
    let m = resign(&bytes, &w.a.sk, |e| e.body.truncate(1000));
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::BadBodyLength(1000)
    );
    let m = resign(&bytes, &w.a.sk, |e| e.body.clear());
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::BadSignature
    );
    let huge = vec![0u8; (MAX_PART_READ + 1) as usize];
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, huge))),
        Junk::OversizePart
    );
    // Too many parts, part index out of range.
    let m = resign(&bytes, &w.a.sk, |e| e.parts = MAX_PARTS + 1);
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::TooManyParts
    );
    let m = resign(&bytes, &w.a.sk, |e| e.parts = 0);
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::TooManyParts
    );
    let m = resign(&bytes, &w.a.sk, |e| {
        e.part = 1;
        e.parts = 1
    });
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&stream.part_name(5, 1).unwrap(), m))),
        Junk::PartOutOfRange
    );
    // Signature algorithm other than the hybrid one.
    let m = mutate(&bytes, |e| e.sig_alg = 0);
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::BadSignature
    );
    let m = mutate(&bytes, |e| e.sig.truncate(64));
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::BadSignature
    );
    // Unknown kind.
    let m = mutate(&bytes, |e| e.kind = 99);
    assert_eq!(
        expect_junk(acc.accept::<Body>(&one(&name, m))),
        Junk::UnknownKind(99)
    );
    // Kind check (6): a body whose seq is not the envelope's.
    let wrong_seq = Body {
        seq: 7,
        base: 6,
        prev: [0; 32],
        data: Vec::new(),
    };
    let s3 = w.seal(&stream, 6, &meta0(), &wrong_seq);
    w.trust.announce(w.a.id, &s3.published);
    assert!(matches!(
        expect_junk(acc.accept::<Body>(&s3.parts)),
        Junk::BadBody(_)
    ));
}

#[test]
fn announcements_decide_waiting_accepted_and_forked() {
    let w = World::new();
    let stream = manifest_stream(w.a.id);
    let base = w.seal(&stream, 1, &meta0(), &body(1, b"base"));
    let acc = w.acceptor();
    // Ahead of its batch: waits; applies once the batch arrives.
    let rec = match acc.accept::<Body>(&base.parts) {
        Outcome::Waiting(r) => r,
        other => panic!("{other:?}"),
    };
    w.trust.announce(w.a.id, &base.published);
    expect_accepted(acc.finish(rec));
    // A delta whose prev is the announced hash of seq 1.
    let d = Body {
        seq: 2,
        base: 1,
        prev: base.published.body_hash,
        data: b"delta".to_vec(),
    };
    let delta = w.seal(&stream, 2, &meta0(), &d);
    assert_eq!(delta.published.base, 1);
    w.trust.announce(w.a.id, &delta.published);
    expect_accepted(acc.accept::<Body>(&delta.parts));
    // A delta with another prev: forked, with the design's message.
    let bad = Body {
        prev: [7; 32],
        seq: 3,
        ..d.clone()
    };
    let s = w.seal(&stream, 3, &meta0(), &bad);
    w.trust.announce(w.a.id, &s.published);
    match acc.accept::<Body>(&s.parts) {
        Outcome::Refused(r) => {
            assert_eq!(r.reason, Refusal::Forked);
            assert_eq!(
                r.to_string(),
                format!(
                    "record manifest 3 of {} does not match what its batch announced",
                    hex::encode(w.a.id)
                )
            );
        }
        other => panic!("{other:?}"),
    }
    // A record whose announcement names another hash: forked.
    let s4 = w.seal(&stream, 4, &meta0(), &body(4, b"one"));
    let s4b = w.seal(&stream, 4, &meta0(), &body(4, b"two"));
    w.trust.announce(w.a.id, &s4.published);
    assert!(matches!(
        acc.accept::<Body>(&s4b.parts),
        Outcome::Refused(Refused {
            reason: Refusal::Forked,
            ..
        })
    ));
    expect_accepted(acc.accept::<Body>(&s4.parts));
    // Unannounced kinds need no batch.
    let peer = StreamRef::new(Kind::Peer, [0; 16], w.a.id);
    let p = w.seal(&peer, 9, &KeyId::Registry(0), &body(9, b"addr"));
    expect_accepted(acc.accept::<Body>(&p.parts));
}

#[test]
fn record_store_reads_streams_and_drops_past_max_ahead() {
    let w = World::new();
    let mem = Mem::default();
    let stream = manifest_stream(w.a.id);
    let n = MAX_AHEAD as u64 + 6;
    let mut published = Vec::new();
    for seq in 1..=n {
        let s = w.seal(&stream, seq, &meta0(), &body(seq, b"m"));
        RecordWriter::publish(&mem, &s).unwrap();
        // Publishing a taken seq again fails.
        assert!(RecordWriter::publish(&mem, &s).is_err());
        published.push(s.published);
    }
    // A checkpoint, a batch and another device's stream nearby are not
    // listed with this stream; a junk name in the stream is skipped.
    let cp = w.seal(
        &StreamRef::new(Kind::Peer, [0; 16], w.a.id),
        1,
        &KeyId::Registry(0),
        &body(1, b"p"),
    );
    RecordWriter::publish(&mem, &cp).unwrap();
    let prefix = stream.prefix().unwrap();
    mem.put_if_absent(&format!("{prefix}notes.txt"), b"x")
        .unwrap();
    let store = RecordStore {
        storage: &mem,
        acceptor: w.acceptor(),
    };
    assert_eq!(store.highest_seq(&stream).unwrap(), n);
    let listed = store.list_after(&stream, 3).unwrap();
    assert_eq!(listed.len() as u64, n - 3);
    assert_eq!(listed[0].seq, 4);
    let mut counter = RecordsRefused::default();
    // Nothing announced: MAX_AHEAD wait, the rest is dropped.
    let r = store.read_after::<Body>(&stream, 0, &mut counter).unwrap();
    assert!(r.accepted.is_empty());
    assert_eq!(r.waiting.len(), MAX_AHEAD);
    assert_eq!(r.dropped_ahead, 6);
    assert_eq!(counter.total(), 0);
    // Announce everything: all accepted in order.
    for p in &published {
        w.trust.announce(w.a.id, p);
    }
    let r = store.read_after::<Body>(&stream, 0, &mut counter).unwrap();
    assert_eq!(r.accepted.len() as u64, n);
    assert!(r
        .accepted
        .windows(2)
        .all(|x| x[0].meta.seq + 1 == x[1].meta.seq));
    // A junk record in the stream is counted once by kind.
    let junk_name = stream.part_name(n + 1, 0).unwrap();
    mem.put_if_absent(&junk_name, b"VSR3garbage").unwrap();
    let r = store.read_after::<Body>(&stream, n, &mut counter).unwrap();
    assert_eq!(r.refused.len(), 1);
    assert!(r.refused[0].to_string().starts_with(&format!(
        "record manifest {} of {} refused: ",
        n + 1,
        hex::encode(w.a.id)
    )));
    store.read_after::<Body>(&stream, n, &mut counter).unwrap();
    assert_eq!(counter.get(Kind::Manifest), 1);
    assert_eq!(counter.total(), 1);
    // An oversize part on the storage is junk, read no further than the limit.
    let big_name = stream.part_name(n + 2, 0).unwrap();
    mem.put_if_absent(&big_name, &vec![0u8; MAX_PART_READ as usize + 1])
        .unwrap();
    let r = store
        .read_after::<Body>(&stream, n + 1, &mut counter)
        .unwrap();
    assert_eq!(r.refused[0].reason, Refusal::Junk(Junk::OversizePart));
    assert_eq!(crate::storage::read_limit(&big_name), MAX_PART_READ);
}

#[test]
fn writers_refuse_what_readers_would_refuse() {
    let w = World::new();
    let signer = w.a.signer();
    let wr = RecordWriter {
        vault: VAULT,
        signer: &signer,
        keys: &w.keys_a,
    };
    // Another device's stream.
    assert!(wr
        .seal(&manifest_stream(w.b.id), 1, 1, &meta0(), &body(1, b""))
        .is_err());
    // A key of the wrong class or folder.
    assert!(wr
        .seal(
            &manifest_stream(w.a.id),
            1,
            1,
            &KeyId::Registry(0),
            &body(1, b"")
        )
        .is_err());
    let other_folder = KeyId::Meta {
        folder: OTHER,
        epoch: 0,
    };
    assert!(wr
        .seal(&manifest_stream(w.a.id), 1, 1, &other_folder, &body(1, b""))
        .is_err());
    // A key it does not hold.
    let unheld = KeyId::Meta {
        folder: FOLDER,
        epoch: 8,
    };
    assert!(wr
        .seal(&manifest_stream(w.a.id), 1, 1, &unheld, &body(1, b""))
        .is_err());
    // A share-epoch record under a key of another epoch than its seq.
    let se = StreamRef::new(Kind::ShareEpoch, FOLDER, w.a.id);
    assert!(wr.seal(&se, 4, 4, &meta0(), &body(4, b"")).is_err());
    // Revocations only under registry@0; `none` only for requests.
    let rv = StreamRef::new(Kind::Revocation, w.b.id, w.a.id);
    assert!(wr
        .seal(&rv, 1, 1, &KeyId::Registry(1), &body(1, b""))
        .is_err());
    assert!(wr
        .seal(&manifest_stream(w.a.id), 1, 1, &KeyId::None, &body(1, b""))
        .is_err());
    let rq = StreamRef::new(Kind::Request, FOLDER, w.a.id);
    let s = wr
        .seal(&rq, 1, 1, &KeyId::None, &body(1, b"kem pub"))
        .unwrap();
    expect_accepted(w.acceptor().accept::<Body>(&s.parts));
    // A grant whose name and key_id name other recipients.
    let g = StreamRef::grant(FOLDER, 1, w.b.id, w.a.id);
    assert!(wr
        .seal(&g, 1, 1, &KeyId::Kem(w.a.id), &body(1, b""))
        .is_err());
    // The section 9 matrix.
    assert!(section9_allows(WriterClass::FullOwner, Kind::Grant));
    assert!(!section9_allows(WriterClass::FullEditor, Kind::Grant));
    assert!(section9_allows(WriterClass::FullEditor, Kind::BlockMap));
    assert!(!section9_allows(WriterClass::FullViewer, Kind::Manifest));
    assert!(section9_allows(WriterClass::FullViewer, Kind::Access));
    assert!(section9_allows(WriterClass::FullNoGrant, Kind::Request));
    assert!(!section9_allows(WriterClass::FullNoGrant, Kind::Manifest));
    assert!(section9_allows(WriterClass::MemberEditor, Kind::Trash));
    assert!(!section9_allows(WriterClass::MemberEditor, Kind::Snapshot));
    assert!(!section9_allows(WriterClass::MemberViewer, Kind::Manifest));
    assert!(section9_allows(WriterClass::Replica, Kind::Batch));
    assert!(!section9_allows(WriterClass::Replica, Kind::Peer));
    assert!(Kind::ALL
        .iter()
        .all(|k| !section9_allows(WriterClass::Untrusted, *k)));
}

#[test]
fn only_full_devices_write_snapshots() {
    // Section 4: `snapshot_taken` comes from the backup's source device, a
    // full device; section 9: members and replicas write no snapshots.
    assert!(section9_allows(WriterClass::FullVault, Kind::Snapshot));
    assert!(section9_allows(WriterClass::FullOwner, Kind::Snapshot));
    for class in [
        WriterClass::MemberEditor,
        WriterClass::MemberViewer,
        WriterClass::Replica,
        WriterClass::Untrusted,
    ] {
        assert!(!section9_allows(class, Kind::Snapshot), "{class:?}");
    }
}

#[test]
fn no_single_flipped_byte_verifies() {
    let w = World::new();
    let stream = manifest_stream(w.a.id);
    let s = w.seal(&stream, 2, &meta0(), &body(2, b"flip me"));
    w.trust.announce(w.a.id, &s.published);
    let (name, bytes) = s.parts[0].clone();
    let acc = w.acceptor();
    expect_accepted(acc.accept::<Body>(&[(name.clone(), bytes.clone())]));
    let env = SignedRecord::decode(&bytes).unwrap();
    // Every byte in front of the signature and the body (the signed
    // fields), the first and last bytes of the signature, and random
    // positions across the whole object, each with a random non-zero flip.
    let head = bytes.len() - env.body.len() - env.sig.len();
    let mut positions: Vec<usize> = (0..head + 80).collect();
    positions.extend(bytes.len() - 80..bytes.len());
    let mut rng = rand::rngs::StdRng::seed_from_u64(11);
    positions.extend((0..400).map(|_| rng.gen_range(0..bytes.len())));
    for pos in positions {
        let mut m = bytes.clone();
        m[pos] ^= rng.gen_range(1..=255u8);
        match acc.accept::<Body>(&[(name.clone(), m)]) {
            Outcome::Accepted(_) => panic!("a flip at {pos} still verifies"),
            Outcome::Waiting(_) => panic!("a flip at {pos} opens"),
            Outcome::Refused(_) => {}
        }
    }
}

#[test]
fn random_bytes_never_panic_the_parser() {
    let w = World::new();
    let acc = w.acceptor();
    let s = w.seal(&manifest_stream(w.a.id), 1, &meta0(), &body(1, b"seed"));
    let (name, valid) = s.parts[0].clone();
    let mut rng = rand::rngs::StdRng::seed_from_u64(5);
    for i in 0..3000 {
        let mut input = match i % 4 {
            // Pure noise.
            0 => {
                let mut v = vec![0u8; rng.gen_range(0..600)];
                rng.fill_bytes(&mut v);
                v
            }
            // The magic followed by noise.
            1 => {
                let mut v = MAGIC.to_vec();
                let mut t = vec![0u8; rng.gen_range(0..600)];
                rng.fill_bytes(&mut t);
                v.extend(t);
                v
            }
            // A valid envelope cut short.
            2 => valid[..rng.gen_range(0..valid.len())].to_vec(),
            // A valid header with noise after a random point.
            _ => {
                let cut = rng.gen_range(4..200);
                let mut v = valid[..cut].to_vec();
                let mut t = vec![0u8; rng.gen_range(0..300)];
                rng.fill_bytes(&mut t);
                v.extend(t);
                v
            }
        };
        if i % 7 == 0 && input.len() > 6 {
            // Huge varint lengths.
            input[5] = 0xff;
            input[6] = 0xff;
        }
        let _ = SignedRecord::decode(&input);
        assert!(!matches!(
            acc.accept::<Body>(&[(name.clone(), input)]),
            Outcome::Accepted(_)
        ));
    }
    // Random names never panic either.
    for _ in 0..2000 {
        let len = rng.gen_range(0..120);
        let alphabet = b"vault/grants0123456789abcdef-.rec";
        let n: String = (0..len)
            .map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char)
            .collect();
        let _ = RecordName::parse(&n);
        let _ = KeyId::parse(&n);
    }
    // Random compressed bodies never panic the body decoder.
    for _ in 0..300 {
        let mut v = vec![0u8; rng.gen_range(0..200)];
        rng.fill_bytes(&mut v);
        let _ = envelope::decode_body::<Body>(&v);
        if let Ok(z) = zstd::bulk::compress(&v, 3) {
            let _ = envelope::decode_body::<Body>(&z);
        }
    }
}

#[test]
fn byte_field_encoding_is_postcard_of_a_plain_vec() {
    #[derive(Serialize)]
    struct Plain {
        a: u8,
        sig: Vec<u8>,
        body: Vec<u8>,
    }
    let w = World::new();
    let s = w.seal(&manifest_stream(w.a.id), 1, &meta0(), &body(1, b"x"));
    let e = SignedRecord::decode(&s.parts[0].1).unwrap();
    let mine = postcard::to_stdvec(&e).unwrap();
    // The tail of the encoding (sig, body) equals postcard of plain Vecs.
    let plain = postcard::to_stdvec(&Plain {
        a: e.sig_alg,
        sig: e.sig.clone(),
        body: e.body.clone(),
    })
    .unwrap();
    assert!(mine.ends_with(&plain));
}

/// Timings for the PR (run with `--release --ignored --nocapture`).
#[test]
#[ignore]
fn bench_sign_verify_seal() {
    use std::time::Instant;
    let w = World::new();
    let stream = manifest_stream(w.a.id);
    let b = body(1, b"small");
    let n = 50;
    let t = Instant::now();
    let mut last = None;
    for _ in 0..n {
        last = Some(w.seal(&stream, 1, &meta0(), &b));
    }
    let seal_small = t.elapsed() / n;
    let s = last.unwrap();
    w.trust.announce(w.a.id, &s.published);
    let t = Instant::now();
    for _ in 0..n {
        expect_accepted(w.acceptor().accept::<Body>(&s.parts));
    }
    let accept_small = t.elapsed() / n;
    let e = SignedRecord::decode(&s.parts[0].1).unwrap();
    let pk = w.a.sk.public();
    let t = Instant::now();
    for _ in 0..n {
        e.verify_signature(&pk).unwrap();
    }
    let verify = t.elapsed() / n;
    let msg = b"m".repeat(300);
    let t = Instant::now();
    for _ in 0..n {
        w.a.sk.sign(&msg);
    }
    let sign = t.elapsed() / n;
    // One full 32 MiB part of incompressible data.
    let mut data = vec![0u8; MAX_PART_BODY - 64 * 1024];
    rand::rngs::StdRng::seed_from_u64(1).fill_bytes(&mut data);
    let big = body(2, &data);
    let t = Instant::now();
    let sb = w.seal(&stream, 2, &meta0(), &big);
    let seal_big = t.elapsed();
    w.trust.announce(w.a.id, &sb.published);
    let t = Instant::now();
    expect_accepted(w.acceptor().accept::<Body>(&sb.parts));
    let accept_big = t.elapsed();
    println!(
        "sign {sign:?}, verify {verify:?}, seal small record {seal_small:?}, accept small record {accept_small:?}, \
         seal {} parts of a {} MiB body {seal_big:?}, accept it {accept_big:?}",
        sb.parts.len(),
        data.len() >> 20
    );
}
