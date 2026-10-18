// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A small vault for the tests of fsck, rebuild and scrub: real packs on
//! local-directory storages, real signed map and manifest records, real
//! ledger batches pushed to every storage.

use super::StorageDesc;
use crate::blockmap::{class_of_len, table_path, MapTable, MapWriter, WrittenMember, WrittenPack};
use crate::crypto::{SecretKey, SigningKey, VerifyingKey};
use crate::ledger3::checkpoint::batch_key;
use crate::ledger3::events::{Announcement, DeviceEnrolled, Event};
use crate::ledger3::{
    device_bin_for, DeviceBin, EventScope, LedgerStore, LedgerView, ObjectBin, PackId, NO_FOLDER,
};
use crate::manifest3::{
    announcement, BaseRule, Chunk3, FileEntry, FolderManifests, ManifestWriter, WriterView,
};
use crate::record::{DeviceSigner, Id16, KeyId, Kind, RecordKeys, RecordTrust, RecordWriter};
use crate::storage::{LocalDirStorage, Storage};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

pub const VAULT: Id16 = [0x11; 16];
pub const FOLDER: Id16 = [0x22; 16];
pub const LEDGER_KEY_ID: &str = "ledger@0";
/// 256 KiB, class 0.
pub const PACK_LEN: usize = 256 << 10;

pub struct Keys(pub SecretKey);

impl RecordKeys for Keys {
    fn symmetric(&self, key_id: &KeyId) -> Option<SecretKey> {
        matches!(key_id, KeyId::Meta { folder, .. } if *folder == FOLDER).then(|| self.0.clone())
    }
}

pub struct Trust {
    pub keys: HashMap<Id16, VerifyingKey>,
    pub view: RefCell<LedgerView>,
}

impl RecordTrust for Trust {
    fn signer_key(&self, device: &Id16, _: Kind, _: &Id16) -> Option<VerifyingKey> {
        self.keys.get(device).cloned()
    }
    fn may_write(&self, device: &Id16, _: Kind, _: &Id16, _: &KeyId) -> bool {
        self.keys.contains_key(device)
    }
    fn announcement(
        &self,
        device: &Id16,
        kind: Kind,
        scope: &Id16,
        seq: u64,
    ) -> Option<crate::record::Announced> {
        announcement(&self.view.borrow(), device, kind, scope, seq)
    }
}

pub struct KitDev {
    pub id: DeviceBin,
    pub sk: SigningKey,
    pub store: LedgerStore,
    pub map: MapWriter,
    pub man: ManifestWriter,
    pub table: MapTable,
    pub files: BTreeMap<String, FileEntry>,
}

pub struct Kit {
    pub dir: tempfile::TempDir,
    pub st: Vec<LocalDirStorage>,
    pub keys: Keys,
    pub ledger_key: SecretKey,
    pub trust: Trust,
    pub devs: Vec<KitDev>,
    pub lamport: u64,
    pub rng: StdRng,
}

pub fn key_for(ledger_key: &SecretKey) -> impl Fn(&str) -> Option<SecretKey> + '_ {
    move |id| id.starts_with("ledger@").then(|| ledger_key.clone())
}

pub fn scope_of(_: &DeviceBin, id: &str) -> Option<EventScope> {
    EventScope::of_key_id(id)
}

impl Kit {
    /// `n` devices, two hot metadata storages `h1` and `h2`.
    pub fn new(n: u8) -> Kit {
        let dir = tempfile::tempdir().unwrap();
        let st: Vec<LocalDirStorage> = ["h1", "h2"]
            .iter()
            .map(|n| LocalDirStorage::new(n.to_string(), dir.path().join(n)).unwrap())
            .collect();
        let mut keys = HashMap::new();
        let mut devs = Vec::new();
        for i in 1..=n {
            let sk = SigningKey::from_bytes(&[i; 64]).unwrap();
            let id = device_bin_for(&sk.public());
            keys.insert(id, sk.public());
            devs.push(KitDev {
                id,
                store: LedgerStore::open(&dir.path().join(format!("dev{i}/ledger")), VAULT)
                    .unwrap(),
                map: MapWriter::from_view(FOLDER, id, 0, &LedgerView::default(), 0),
                man: ManifestWriter::new(FOLDER, id),
                table: MapTable::open(
                    &table_path(&dir.path().join(format!("dev{i}/state")), &FOLDER),
                    FOLDER,
                )
                .unwrap(),
                files: BTreeMap::new(),
                sk,
            });
        }
        Kit {
            dir,
            st,
            keys: Keys(SecretKey([9; 32])),
            ledger_key: SecretKey([8; 32]),
            trust: Trust {
                keys,
                view: RefCell::new(LedgerView::default()),
            },
            devs,
            lamport: 0,
            rng: StdRng::seed_from_u64(7),
        }
    }

    pub fn descs(&self) -> Vec<StorageDesc<'_>> {
        self.st
            .iter()
            .map(|s| StorageDesc::new(s.name(), s))
            .collect()
    }

    pub fn view(&self, d: usize) -> LedgerView {
        let k = key_for(&self.ledger_key);
        self.devs[d]
            .store
            .view_scoped(&k, |_, _| true, scope_of)
            .unwrap()
    }

    fn push_batch(&mut self, d: usize, events: &[Event]) -> u64 {
        self.lamport += 1;
        let (id, seen) = (
            self.devs[d].id,
            self.devs[d].store.vault_seen(&self.devs[d].id),
        );
        let rec = {
            let dev = &mut self.devs[d];
            dev.store
                .append_own(
                    &id,
                    events.iter().map(Event::to_raw).collect(),
                    seen,
                    self.lamport,
                    &self.ledger_key,
                    LEDGER_KEY_ID,
                    NO_FOLDER,
                    &dev.sk,
                )
                .unwrap()
        };
        for s in &self.st {
            s.put_if_absent(&batch_key(&id, rec.seq), &rec.encode())
                .unwrap();
        }
        // The other devices' local stores take it in.
        let pubkey = self.devs[d].sk.public();
        for (i, other) in self.devs.iter_mut().enumerate() {
            if i != d {
                other
                    .store
                    .ingest(rec.clone(), &pubkey, Some(&self.ledger_key))
                    .unwrap();
            }
        }
        *self.trust.view.borrow_mut() = self.view(0);
        rec.seq
    }

    pub fn enroll(&mut self, d: usize) {
        self.push_batch(
            d,
            &[
                Event::DeviceEnrolled(DeviceEnrolled {
                    name: format!("device {d}"),
                }),
                Event::FolderAdded(crate::ledger3::events::FolderAdded { folder: FOLDER }),
            ],
        );
    }

    /// A pack of `members` objects of 1 000 bytes each, written
    /// byte-identical to the storages `on` (indexes into `st`).
    pub fn pack(&mut self, on: &[usize], members: usize) -> WrittenPack {
        let mut bytes = vec![0u8; PACK_LEN];
        self.rng.fill_bytes(&mut bytes);
        let id = crate::crypto::hash(&bytes);
        let mut list = Vec::new();
        for m in 0..members {
            let mut object = [0u8; 32];
            let mut chunk = [0u8; 32];
            self.rng.fill_bytes(&mut object);
            self.rng.fill_bytes(&mut chunk);
            list.push(WrittenMember {
                object,
                chunk,
                offset: (m * 1000) as u32,
                len: 1000,
                plain_len: 900,
                epoch: 0,
            });
        }
        let key = crate::packs::pack_key(&hex::encode(id));
        for i in on {
            self.st[*i].put_if_absent(&key, &bytes).unwrap();
        }
        WrittenPack {
            id,
            class: class_of_len(PACK_LEN as u64).unwrap(),
            storages: on.iter().map(|i| self.st[*i].name().to_string()).collect(),
            members: list,
        }
    }

    /// Write bytes of a pack as a file on a storage (for orphans).
    pub fn orphan(&mut self, on: usize) -> PackId {
        let mut bytes = vec![0u8; PACK_LEN];
        self.rng.fill_bytes(&mut bytes);
        let id = crate::crypto::hash(&bytes);
        self.st[on]
            .put_if_absent(&crate::packs::pack_key(&hex::encode(id)), &bytes)
            .unwrap();
        id
    }

    /// Device `d` publishes a map record for `packs`, a manifest with
    /// `files` (path, objects) added, and one batch announcing both.
    /// `class_in_ledger` makes the batch claim another class than the
    /// map's (to test a lying map).
    pub fn publish(
        &mut self,
        d: usize,
        packs: &[WrittenPack],
        files: &[(&str, Vec<ObjectBin>)],
        class_in_ledger: Option<u8>,
    ) {
        let id = self.devs[d].id;
        for (path, objects) in files {
            let e = FileEntry {
                path: path.to_string(),
                version: BTreeMap::new(),
                deleted: false,
                size: 900 * objects.len() as u64,
                mtime: 0,
                content_hash: Some([1; 32]),
                chunks: objects
                    .iter()
                    .map(|o| Chunk3 {
                        chunk: [2; 32],
                        object: *o,
                        size: 900,
                        epoch: 0,
                    })
                    .collect(),
                modified_by: id,
                modified_clock: 1,
                meta: None,
                chunking: 2,
                held: true,
            };
            self.devs[d].files.insert(path.to_string(), e);
        }
        self.lamport += 1;
        let lamport = self.lamport;
        let view = self.view(d);
        let mut events = {
            let Kit { st, keys, devs, .. } = self;
            let dev = &mut devs[d];
            let signer = DeviceSigner {
                device: id,
                key: &dev.sk,
            };
            let rw = RecordWriter {
                vault: VAULT,
                signer: &signer,
                keys: &*keys,
            };
            let stores: Vec<&dyn Storage> = st.iter().map(|s| s as &dyn Storage).collect();
            let mp = dev
                .map
                .publish(&rw, &stores, packs, lamport, Some(&dev.table), &view)
                .unwrap();
            mp.apply_to(&mut dev.table, &|_| true).unwrap();
            let mut events = mp.events.clone();
            dev.man.rule = BaseRule::default();
            let key = KeyId::Meta {
                folder: FOLDER,
                epoch: 0,
            };
            if let Some(p) = dev.man.seal(&rw, &key, &dev.files, lamport, 0).unwrap() {
                for s in st.iter() {
                    for (name, bytes) in &p.sealed.parts {
                        s.put_if_absent(name, bytes).unwrap();
                    }
                }
                let a = &p.sealed.published;
                events.push(Event::RecordPublished(Announcement {
                    kind: a.kind,
                    scope: a.scope,
                    seq: a.seq,
                    base: a.base,
                    parts: a.parts,
                    body_hash: a.body_hash,
                    size: a.size,
                }));
                dev.man.commit(p);
            }
            events
        };
        if let Some(c) = class_in_ledger {
            for e in &mut events {
                if let Event::PackStored(p) = e {
                    p.class = c;
                }
            }
        }
        self.push_batch(d, &events);
    }

    /// The manifests `fsck` reads: every device's files as published.
    pub fn manifests(&self) -> FolderManifests {
        let mut m = FolderManifests::new(FOLDER);
        for dev in &self.devs {
            m.insert_view(WriterView {
                device: dev.id,
                seq: dev.man.seq,
                base: dev.man.base_seq,
                hash: dev.man.hash,
                lamport: 0,
                created_utc: 0,
                files: dev.files.clone(),
            });
        }
        m
    }

    pub fn pack_path(&self, storage: usize, pack: &PackId) -> std::path::PathBuf {
        self.dir
            .path()
            .join(self.st[storage].name())
            .join(crate::packs::pack_key(&hex::encode(pack)))
    }

    pub fn delete_pack(&self, storage: usize, pack: &PackId) {
        std::fs::remove_file(self.pack_path(storage, pack)).unwrap();
    }

    pub fn flip_byte(&self, storage: usize, pack: &PackId) {
        let p = self.pack_path(storage, pack);
        let mut b = std::fs::read(&p).unwrap();
        b[100] ^= 0xff;
        std::fs::write(&p, b).unwrap();
    }
}
