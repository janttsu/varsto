// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Reading and writing the record streams the engine keeps outside the
//! ledger's announcements (`docs/spec/format-3-design.md` section 5): the
//! records of snapshots (announced), access times, analyses and thumbnails
//! (not announced). One place seals a record of this device's stream onto
//! the hot metadata storages and one place reads other writers' streams
//! through the acceptance rule with the engine's keys and trust.

use super::*;
use crate::ledger3::LedgerView as View3;
use crate::record::{
    Acceptor, DeviceSigner, Id16, KeyId, RecordPublished, RecordStore, RecordWriter,
    RecordsRefused, StreamRef,
};

impl Engine {
    /// Run `f` for every storage of `storages` with a `RecordStore` that
    /// accepts records under this engine's keys and trust. Returns the
    /// records refused meanwhile.
    pub(super) fn each_store(
        &self,
        storages: &OpenStorages,
        view: &View3,
        mut f: impl FnMut(&str, &RecordStore<'_>, &mut RecordsRefused) -> Result<()>,
    ) -> Result<RecordsRefused> {
        let vault = members3::bin(&self.vault.vault_id)?;
        let vault_keys = self.vault_keys3();
        let keys = self.keys3(&vault_keys);
        let trust = members3::EngineTrust {
            inner: self.f3.members.trust(),
            view,
        };
        let mut refused = RecordsRefused::default();
        for (spec, backend) in storages {
            let store = RecordStore {
                storage: backend.as_ref(),
                acceptor: Acceptor {
                    vault,
                    keys: &keys,
                    trust: &trust,
                },
            };
            f(spec.name(), &store, &mut refused)?;
        }
        Ok(refused)
    }

    /// Run `f` with a writer of records of this device.
    pub(super) fn with_writer3<R>(
        &self,
        f: impl FnOnce(&RecordWriter<'_>) -> Result<R>,
    ) -> Result<R> {
        let vault = members3::bin(&self.vault.vault_id)?;
        let vault_keys = self.vault_keys3();
        let keys = self.keys3(&vault_keys);
        let signer = DeviceSigner {
            device: self.me3(),
            key: &self.keys.signer,
        };
        let rw = RecordWriter {
            vault,
            signer: &signer,
            keys: &keys,
        };
        f(&rw)
    }

    /// The highest seq of `stream` on any of `storages` (0: none).
    pub(super) fn highest_seq3(&self, storages: &OpenStorages, stream: &StreamRef) -> Result<u64> {
        let vault = members3::bin(&self.vault.vault_id)?;
        let vault_keys = self.vault_keys3();
        let keys = self.keys3(&vault_keys);
        let trust = crate::membership3::Trust {
            devices: &self.f3.members.devices,
            revoked: &self.f3.members.revoked,
            folders: None,
            members: None,
        };
        let mut highest = 0;
        for (_, backend) in storages {
            let store = RecordStore {
                storage: backend.as_ref(),
                acceptor: Acceptor {
                    vault,
                    keys: &keys,
                    trust: &trust,
                },
            };
            highest = highest.max(store.highest_seq(stream)?);
        }
        Ok(highest)
    }

    /// Every device that may have a stream of a record kind: the vault's
    /// devices and the members of shared folders.
    pub(super) fn stream_writers(&self) -> Vec<Id16> {
        let m = &self.f3.members;
        let mut out: BTreeSet<Id16> = m.devices.devices.keys().copied().collect();
        out.insert(self.me3());
        out.extend(m.members.members.keys().map(|(_, d)| *d));
        out.into_iter().collect()
    }

    /// Seal the next record of this device's `stream` with the body
    /// `body(seq)` and write its parts to `storages` (the first one
    /// decides whether the seq is free; a seq taken by an interrupted
    /// attempt is skipped). Returns the record's announcement data.
    pub(super) fn write_record3<T: Serialize>(
        &self,
        storages: &OpenStorages,
        stream: &StreamRef,
        key: &KeyId,
        body: impl Fn(u64) -> T,
    ) -> Result<RecordPublished> {
        if storages.is_empty() {
            bail!("no storage to write the record to");
        }
        let highest = self.highest_seq3(storages, stream)?;
        for highest in (highest + 1..).take(8) {
            let sealed =
                self.with_writer3(|rw| rw.seal(stream, highest, highest, key, &body(highest)))?;
            let mut taken = false;
            for (name, bytes) in &sealed.parts {
                if !storages[0].1.put_if_absent(name, bytes)? {
                    taken = true;
                    break;
                }
            }
            if taken {
                continue;
            }
            for (_, backend) in &storages[1..] {
                for (name, bytes) in &sealed.parts {
                    backend.put_if_absent(name, bytes)?;
                }
            }
            return Ok(sealed.published);
        }
        bail!("no free sequence number for the next record")
    }

    /// Copy the record parts of the streams under `prefix` that a storage
    /// lacks from the others (a storage added later gets every record).
    pub(super) fn replicate_records3(
        &self,
        storages: &OpenStorages,
        prefix: &str,
    ) -> Result<usize> {
        let mut copied = 0;
        let mut names: BTreeMap<String, usize> = BTreeMap::new();
        let mut listed: Vec<BTreeSet<String>> = Vec::new();
        for (i, (_, b)) in storages.iter().enumerate() {
            let set: BTreeSet<String> = b.list(prefix)?.into_iter().collect();
            for n in &set {
                names.entry(n.clone()).or_insert(i);
            }
            listed.push(set);
        }
        for (name, from) in names {
            let mut bytes = None;
            for (i, (_, b)) in storages.iter().enumerate() {
                if listed[i].contains(&name) {
                    continue;
                }
                if bytes.is_none() {
                    bytes = storages[from]
                        .1
                        .get_bounded(&name, crate::record::MAX_PART_READ)?;
                }
                if let Some(data) = &bytes {
                    if b.put_if_absent(&name, data)? {
                        copied += 1;
                    }
                }
            }
        }
        Ok(copied)
    }
}
