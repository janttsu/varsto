// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A small world for the tests of this work package (and `snapshot3`):
//! devices with signing keys, two in-memory storages, a ledger view that
//! records announcements, and helpers to publish and acknowledge.

use super::Id16;
use crate::crypto::{SecretKey, SigningKey, VerifyingKey};
use crate::ledger3::events::{Batch, Event};
use crate::ledger3::{Announcement, EventScope, LedgerView};
use crate::record::{
    Acceptor, Announced, DeviceSigner, KeyId, Kind, RecordKeys, RecordPublished, RecordStore,
    RecordTrust, RecordWriter,
};
use crate::storage::Storage;
use anyhow::Result;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

pub const VAULT: Id16 = [0x11; 16];
pub const FOLDER: Id16 = [0x22; 16];
pub const BACKUP: Id16 = [0x33; 16];

#[derive(Default)]
pub struct Mem {
    name: String,
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl Mem {
    pub fn named(n: &str) -> Mem {
        Mem {
            name: n.into(),
            ..Default::default()
        }
    }
    pub fn names(&self) -> Vec<String> {
        self.objects.lock().unwrap().keys().cloned().collect()
    }
}

impl Storage for Mem {
    fn name(&self) -> &str {
        &self.name
    }
    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        let mut m = self.objects.lock().unwrap();
        if m.contains_key(key) {
            return Ok(false);
        }
        m.insert(key.to_string(), data.to_vec());
        Ok(true)
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.objects.lock().unwrap().get(key).cloned())
    }
    fn exists(&self, key: &str) -> Result<bool> {
        Ok(self.objects.lock().unwrap().contains_key(key))
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        Ok(self
            .objects
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }
}

/// One key opens every record of the test world.
pub struct Keys(pub SecretKey);

impl RecordKeys for Keys {
    fn symmetric(&self, key_id: &KeyId) -> Option<SecretKey> {
        matches!(key_id, KeyId::Meta { .. } | KeyId::Registry(_)).then(|| self.0.clone())
    }
}

pub fn meta_key(folder: Id16) -> KeyId {
    KeyId::Meta { folder, epoch: 0 }
}

pub struct Trust {
    pub keys: HashMap<Id16, VerifyingKey>,
    pub view: RefCell<LedgerView>,
}

impl RecordTrust for Trust {
    fn signer_key(&self, device: &Id16, _kind: Kind, _scope: &Id16) -> Option<VerifyingKey> {
        self.keys.get(device).cloned()
    }
    fn may_write(&self, _device: &Id16, _kind: Kind, _scope: &Id16, _key_id: &KeyId) -> bool {
        true
    }
    fn announcement(&self, device: &Id16, kind: Kind, scope: &Id16, seq: u64) -> Option<Announced> {
        crate::manifest3::announcement(&self.view.borrow(), device, kind, scope, seq)
    }
}

pub struct Dev {
    pub id: Id16,
    pub sk: SigningKey,
    pub batch: u64,
}

pub struct World {
    pub hot: Mem,
    pub cold: Mem,
    pub keys: Keys,
    pub trust: Trust,
    pub devs: Vec<Dev>,
}

impl World {
    pub fn new(n: u8) -> World {
        let devs: Vec<Dev> = (1..=n)
            .map(|i| Dev {
                id: [i; 16],
                sk: SigningKey::from_bytes(&[i; 64]).unwrap(),
                batch: 0,
            })
            .collect();
        World {
            hot: Mem::named("hot"),
            cold: Mem::named("cold"),
            keys: Keys(SecretKey::random()),
            trust: Trust {
                keys: devs.iter().map(|d| (d.id, d.sk.public())).collect(),
                view: RefCell::new(LedgerView::default()),
            },
            devs,
        }
    }

    pub fn id(&self, i: usize) -> Id16 {
        self.devs[i].id
    }

    /// Run `f` with device `i`'s record writer.
    pub fn with_writer<R>(&self, i: usize, f: impl FnOnce(&RecordWriter) -> R) -> R {
        let d = &self.devs[i];
        let signer = DeviceSigner {
            device: d.id,
            key: &d.sk,
        };
        let rw = RecordWriter {
            vault: VAULT,
            signer: &signer,
            keys: &self.keys,
        };
        f(&rw)
    }

    /// Write the parts to both storages and announce the record in a batch
    /// (with `extra` events); the batch seq.
    pub fn publish_sealed(
        &mut self,
        i: usize,
        sealed: &crate::record::SealedRecord,
        extra: Vec<Event>,
    ) -> u64 {
        RecordWriter::publish(&self.hot, sealed).unwrap();
        RecordWriter::publish(&self.cold, sealed).unwrap();
        let mut events = vec![announcement(&sealed.published)];
        events.extend(extra);
        self.batch(i, events, Vec::new(), EventScope::Full)
    }

    pub fn batch(
        &mut self,
        i: usize,
        events: Vec<Event>,
        seen: Vec<(Id16, u64)>,
        scope: EventScope,
    ) -> u64 {
        let d = &mut self.devs[i];
        d.batch += 1;
        let b = Batch {
            device: d.id,
            seq: d.batch,
            prev: [0; 32],
            lamport: d.batch,
            created_utc: 0,
            seen,
            events: events.iter().map(Event::to_raw).collect(),
        };
        self.trust.view.borrow_mut().apply_scoped(&b, &scope);
        d.batch
    }

    /// Device `reader` says it holds `of`'s batches up to `upto`.
    pub fn ack(&mut self, reader: usize, of: usize, upto: u64, scope: EventScope) {
        let of = self.id(of);
        self.batch(reader, Vec::new(), vec![(of, upto)], scope);
    }

    pub fn store<'a>(&'a self, storage: &'a dyn Storage) -> RecordStore<'a> {
        RecordStore {
            storage,
            acceptor: Acceptor {
                vault: VAULT,
                keys: &self.keys,
                trust: &self.trust,
            },
        }
    }
}

pub fn announcement(p: &RecordPublished) -> Event {
    Event::RecordPublished(Announcement {
        kind: p.kind,
        scope: p.scope,
        seq: p.seq,
        base: p.base,
        parts: p.parts,
        body_hash: p.body_hash,
        size: p.size,
    })
}
