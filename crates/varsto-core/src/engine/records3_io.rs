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
    /// records refused meanwhile. A storage that cannot be reached is
    /// skipped (`health`); when none answers, that is the error.
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
        let (mut answered, mut unreachable) = (0usize, None::<anyhow::Error>);
        for (spec, backend) in storages {
            let store = RecordStore {
                storage: backend.as_ref(),
                acceptor: Acceptor {
                    vault,
                    keys: &keys,
                    trust: &trust,
                },
            };
            match f(spec.name(), &store, &mut refused) {
                Ok(()) => answered += 1,
                Err(e) if self.health.failed(spec.name(), &e) => {
                    unreachable.get_or_insert(e);
                }
                Err(e) => return Err(e),
            }
        }
        match unreachable {
            Some(e) if answered == 0 => Err(e),
            _ => Ok(refused),
        }
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

    /// The highest seq of `stream` on any of `storages` that answers (0:
    /// none), and never below a seq this device wrote of it while a
    /// storage was down (that storage may be the one not answering now).
    /// An error only when no storage answers.
    pub(super) fn highest_seq3(
        &self,
        storages: &[(StorageSpec, Box<dyn Storage>)],
        stream: &StreamRef,
    ) -> Result<u64> {
        let vault = members3::bin(&self.vault.vault_id)?;
        let vault_keys = self.vault_keys3();
        let keys = self.keys3(&vault_keys);
        let trust = crate::membership3::Trust {
            devices: &self.f3.members.devices,
            revoked: &self.f3.members.revoked,
            folders: None,
            members: None,
        };
        let mut highest = self.health.written_seq(&stream_key(stream));
        let (mut answered, mut unreachable) = (0usize, None::<anyhow::Error>);
        for (spec, backend) in storages {
            let store = RecordStore {
                storage: backend.as_ref(),
                acceptor: Acceptor {
                    vault,
                    keys: &keys,
                    trust: &trust,
                },
            };
            match store.highest_seq(stream) {
                Ok(h) => {
                    highest = highest.max(h);
                    answered += 1;
                }
                Err(e) if self.health.failed(spec.name(), &e) => {
                    unreachable.get_or_insert(e);
                }
                Err(e) => return Err(e),
            }
        }
        match unreachable {
            Some(e) if answered == 0 => Err(e),
            _ => Ok(highest),
        }
    }

    /// Write the parts of one sealed record: the first storage of
    /// `storages` that answers decides whether its seq is free (false:
    /// taken, by an interrupted earlier attempt or another copy of this
    /// device); the others take the parts where they are free. A storage
    /// that cannot be reached gets them later (`heal_partial_writes`), and
    /// `stream` remembers the seq so that it is not written twice. An error
    /// when no storage answers.
    pub(super) fn put_record_parts3(
        &self,
        storages: &OpenStorages,
        copies: Copies,
        stream: &StreamRef,
        seq: u64,
        parts: &[(String, Vec<u8>)],
    ) -> Result<bool> {
        let names = || parts.iter().map(|(n, _)| n.clone());
        let mut deciding = None;
        let mut unreachable = None::<anyhow::Error>;
        let mut missed: Vec<&str> = Vec::new();
        for (i, (spec, backend)) in storages.iter().enumerate() {
            let put = (|| -> Result<bool> {
                for (name, bytes) in parts {
                    if !backend.put_if_absent(name, bytes)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            })();
            match put {
                Ok(true) => {
                    deciding = Some(i);
                    break;
                }
                Ok(false) => return Ok(false),
                Err(e) if self.health.failed(spec.name(), &e) => {
                    missed.push(spec.name());
                    unreachable.get_or_insert(e);
                }
                Err(e) => return Err(e),
            }
        }
        let Some(first) = deciding else {
            return Err(unreachable.unwrap_or_else(|| anyhow!("no storage to write the record to")));
        };
        for (spec, backend) in &storages[first + 1..] {
            let put = (|| -> Result<()> {
                for (name, bytes) in parts {
                    backend.put_if_absent(name, bytes)?;
                }
                Ok(())
            })();
            if self.tolerate(spec.name(), put)?.is_none() {
                missed.push(spec.name());
            }
        }
        let left_out = self.down_storages_left_out(storages, copies);
        if !missed.is_empty() || !left_out.is_empty() {
            for storage in missed.into_iter().map(str::to_string).chain(left_out) {
                self.health.queue_heal(&storage, names());
            }
            self.health.note_written_seq(&stream_key(stream), seq);
        }
        Ok(true)
    }

    /// The configured storages of `copies` that this run left out of
    /// `storages` because they are down: a record written now reaches them
    /// later (`heal_partial_writes`).
    pub(super) fn down_storages_left_out(
        &self,
        storages: &[(StorageSpec, Box<dyn Storage>)],
        copies: Copies,
    ) -> Vec<String> {
        let drained = self.drained_storages();
        self.config
            .storages
            .iter()
            .filter(|s| !s.is_data_only() && !drained.contains(s.name()))
            .filter(|s| match copies {
                Copies::Hot => !s.is_cold(),
                Copies::Backup => !s.is_carrier(),
            })
            .filter(|s| self.storage_down(s.name()))
            .filter(|s| !storages.iter().any(|(o, _)| o.name() == s.name()))
            .map(|s| s.name().to_string())
            .collect()
    }

    /// Queue the parts `names` of a record written to `storages` for the
    /// storages of `copies` that are down now.
    pub(super) fn heal_later(
        &self,
        storages: &[(StorageSpec, Box<dyn Storage>)],
        copies: Copies,
        names: &[String],
    ) {
        for storage in self.down_storages_left_out(storages, copies) {
            self.health.queue_heal(&storage, names.iter().cloned());
        }
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
    /// `body(seq)` and write its parts to `storages` (the first one that
    /// answers decides whether the seq is free; a seq taken by an
    /// interrupted attempt is skipped; `put_record_parts3`). Returns the
    /// record's announcement data.
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
            if !self.put_record_parts3(storages, Copies::Hot, stream, highest, &sealed.parts)? {
                continue;
            }
            return Ok(sealed.published);
        }
        bail!("no free sequence number for the next record")
    }

    /// Copy the record parts of the streams under `prefix` that a storage
    /// lacks from the others (a storage added later gets every record). A
    /// storage that cannot be reached is left out this time.
    pub(super) fn replicate_records3(
        &self,
        storages: &OpenStorages,
        prefix: &str,
    ) -> Result<usize> {
        let mut copied = 0;
        let mut names: BTreeMap<String, usize> = BTreeMap::new();
        // `None`: the storage did not answer the listing.
        let mut listed: Vec<Option<BTreeSet<String>>> = Vec::new();
        for (i, (spec, b)) in storages.iter().enumerate() {
            let Some(found) = self.tolerate(spec.name(), b.list(prefix))? else {
                listed.push(None);
                continue;
            };
            let set: BTreeSet<String> = found.into_iter().collect();
            for n in &set {
                names.entry(n.clone()).or_insert(i);
            }
            listed.push(Some(set));
        }
        if listed.iter().all(|l| l.is_none()) && !storages.is_empty() {
            bail!("no storage could be reached to copy records under {prefix}");
        }
        for (name, from) in names {
            let mut bytes = None;
            for (i, (spec, b)) in storages.iter().enumerate() {
                let Some(set) = &listed[i] else {
                    continue;
                };
                if set.contains(&name) || self.storage_down(spec.name()) {
                    continue;
                }
                if bytes.is_none() {
                    let (from_spec, from_b) = &storages[from];
                    bytes = self
                        .tolerate(
                            from_spec.name(),
                            from_b.get_bounded(&name, crate::record::MAX_PART_READ),
                        )?
                        .flatten();
                    if bytes.is_none() {
                        break;
                    }
                }
                if let Some(data) = &bytes {
                    if self.tolerate(spec.name(), b.put_if_absent(&name, data))? == Some(true) {
                        copied += 1;
                    }
                }
            }
        }
        if listed.iter().any(|l| l.is_none()) {
            // Not every storage was reached: the caller tries again later.
            bail!("a storage could not be reached to copy records under {prefix}");
        }
        Ok(copied)
    }
}

/// Which storages a record is meant for: the hot metadata storages, or
/// those of a backup (cold ones too, no transferrer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Copies {
    Hot,
    Backup,
}

/// A stream's name in `state/storage-health.json`.
fn stream_key(stream: &StreamRef) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        stream.kind.code(),
        hex::encode(stream.scope),
        hex::encode(stream.device),
        stream.epoch.map(|e| e.to_string()).unwrap_or_default(),
        stream.recipient.map(hex::encode).unwrap_or_default()
    )
}
