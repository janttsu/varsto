// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The records of a folder in a format-3 vault (`docs/spec/format-3-design.md`
//! sections 3 and 7): the block map table kept per folder
//! (`state/maps/<folder>.tbl`, handed to the pack layer as the place of
//! every block), every writer's manifest view (`state/manifests3/<folder>.json`),
//! and publishing this device's map deltas and manifests.
//!
//! A push writes its packs, then one map record listing their members, then
//! its manifest record, then one batch that claims the packs and announces
//! both records (`push_inner`). A pull reads the records the view announces
//! past what was applied, through the acceptance rule of every record
//! (`record::Acceptor` with the engine's keys and trust).

use super::*;
use crate::blockmap::{self, MapTable, MapWriter, WrittenPack};
use crate::ledger3::events::{Announcement, Event as Event3};
use crate::ledger3::LedgerView as View3;
use crate::manifest3::{FileEntry, FolderManifests, ManifestWriter, WriterView};
use crate::record::{
    Acceptor, DeviceSigner, Id16, KeyId, Kind, RecordStore, RecordWriter, RecordsRefused,
};
use std::sync::{Arc, RwLock};

/// A writer's view as kept on disk.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredView {
    device: String,
    seq: u64,
    base: u64,
    hash: String,
    lamport: u64,
    created_utc: i64,
    /// Each file with the writer's `held` flag.
    files: Vec<(FileState, bool)>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoredManifests {
    views: Vec<StoredView>,
    #[serde(default)]
    forked: Vec<String>,
}

fn id16_of_hex(s: &str) -> Option<Id16> {
    hex::decode(s).ok()?.try_into().ok()
}

fn hash32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    let _ = hex::decode_to_slice(s, &mut out);
    out
}

impl StoredManifests {
    fn of(m: &FolderManifests) -> StoredManifests {
        StoredManifests {
            views: m
                .views
                .values()
                .map(|v| StoredView {
                    device: hex::encode(v.device),
                    seq: v.seq,
                    base: v.base,
                    hash: hex::encode(v.hash),
                    lamport: v.lamport,
                    created_utc: v.created_utc,
                    files: v.files.values().map(|f| (f.to_state(), f.held)).collect(),
                })
                .collect(),
            forked: m.forked.iter().map(hex::encode).collect(),
        }
    }

    fn into_manifests(self, folder: Id16) -> FolderManifests {
        let mut m = FolderManifests::new(folder);
        for v in self.views {
            let Some(device) = id16_of_hex(&v.device) else {
                continue;
            };
            let mut files = BTreeMap::new();
            for (f, held) in v.files {
                if let Ok(e) = FileEntry::from_state(&f, held) {
                    files.insert(e.path.clone(), e);
                }
            }
            m.insert_view(WriterView {
                device,
                seq: v.seq,
                base: v.base,
                hash: hash32(&v.hash),
                lamport: v.lamport,
                created_utc: v.created_utc,
                files,
            });
        }
        for f in self.forked {
            if let Some(d) = id16_of_hex(&f) {
                m.forked.insert(d);
            }
        }
        m
    }
}

/// Whether this device holds every block of `f` (section 4's `held`): the
/// version on disk (or in the block cache) is the one the state lists.
pub(super) fn held_here(state: &FolderState, f: &FileState) -> bool {
    !f.deleted
        && state
            .local_index
            .get(&f.path)
            .is_some_and(|ix| ix.content_hash == f.content_hash)
}

impl Engine {
    /// The block map table of `folder`, opened once per process and handed
    /// to the pack layer as the place of the folder's blocks.
    pub(super) fn table3(&self, folder: &Id16) -> Result<Arc<RwLock<MapTable>>> {
        let mut tables = self.f3.tables.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(t) = tables.get(folder) {
            return Ok(t.clone());
        }
        let path = blockmap::table_path(&self.home.join("state"), folder);
        let t = Arc::new(RwLock::new(MapTable::open(&path, *folder)?));
        self.pack_caches
            .add_place_source(t.clone() as Arc<dyn crate::packs::PlaceSource>);
        tables.insert(*folder, t.clone());
        Ok(t)
    }

    /// Open the map table of every folder whose keys this device holds, so
    /// that reads of their blocks find their places.
    pub(super) fn ensure_tables3(&self) {
        for rec in self.keyring.folders.values() {
            if rec.is_removed() || (rec.key_hex.is_empty() && rec.epoch_keys.is_empty()) {
                continue;
            }
            let Ok(id) = members3::bin(&rec.folder_id) else {
                continue;
            };
            if let Err(e) = self.table3(&id) {
                log::warn!(folder:% = rec.folder_id; "block map table not opened: {e:#}");
            }
        }
    }

    fn manifests3_path(&self, folder: &Id16) -> PathBuf {
        self.home
            .join("state")
            .join("manifests3")
            .join(format!("{}.json", hex::encode(folder)))
    }

    /// Every writer's manifest view of `folder` as read so far.
    pub(super) fn load_manifests3(&self, folder: &Id16) -> FolderManifests {
        util::read_json_or_default::<StoredManifests>(&self.manifests3_path(folder))
            .unwrap_or_default()
            .into_manifests(*folder)
    }

    pub(super) fn save_manifests3(&self, m: &FolderManifests) -> Result<()> {
        let p = self.manifests3_path(&m.folder);
        if let Some(dir) = p.parent() {
            fs::create_dir_all(dir)?;
        }
        util::write_json(&p, &StoredManifests::of(m))
    }

    /// The hot metadata storages records are written to and read from.
    pub(super) fn record_storages3(&self) -> Result<OpenStorages> {
        Ok(self
            .metadata_storages(false)?
            .into_iter()
            .filter(|(s, _)| !s.is_carrier())
            .collect())
    }

    /// Read the map and manifest records of `folder` that the view
    /// announces past what this device applied, from every hot metadata
    /// storage. Returns every writer's manifests and the paths that changed
    /// per writer.
    pub(super) fn pull_folder_records3(
        &self,
        folder: &Id16,
        view: &View3,
    ) -> Result<(FolderManifests, BTreeMap<Id16, BTreeSet<String>>)> {
        let table = self.table3(folder)?;
        let mut manifests = self.load_manifests3(folder);
        let me = self.me3();
        let vault = members3::bin(&self.vault.vault_id)?;
        let vault_keys = self.vault_keys3();
        let keys = self.keys3(&vault_keys);
        let trust = members3::EngineTrust {
            inner: self.f3.members.trust(),
            view,
        };
        let mut refused = RecordsRefused::default();
        let mut changed: BTreeMap<Id16, BTreeSet<String>> = BTreeMap::new();
        for (_, backend) in self.record_storages3()? {
            let store = RecordStore {
                storage: backend.as_ref(),
                acceptor: Acceptor {
                    vault,
                    keys: &keys,
                    trust: &trust,
                },
            };
            {
                let mut t = table.write().unwrap_or_else(|e| e.into_inner());
                let r = blockmap::pull(&mut t, &store, view, &mut refused)?;
                for (d, seq, why) in r.skipped {
                    log::debug!(device = hex::encode(d).as_str(), seq = seq; "block map record skipped: {why}");
                }
            }
            let r = manifests.pull(&store, view, &me, &mut refused)?;
            for (d, paths) in r.changed {
                changed.entry(d).or_default().extend(paths);
            }
            for x in &r.refused {
                log::warn!("manifest refused: {x}");
            }
        }
        // Writers that are no longer trusted (removed past their cut-off):
        // their views do not count.
        let trusted: Vec<Id16> = manifests.views.keys().copied().collect();
        for d in trusted {
            if d != me
                && self.f3.members.devices.get(&d).is_none()
                && self.f3.members.members.get(folder, &d).is_none()
            {
                manifests.remove_writer(&d);
            }
        }
        self.save_manifests3(&manifests)?;
        Ok((manifests, changed))
    }

    fn record_writer_parts(&self) -> (Id16, Id16, crate::membership3::VaultKeys) {
        (
            members3::bin(&self.vault.vault_id).expect("a vault id is 16 bytes"),
            self.me3(),
            self.vault_keys3(),
        )
    }

    /// The storages holding a live place of `object` of `folder` (design
    /// section 4, "Copies of a block"); empty without the folder's keys.
    pub(super) fn block_copies3(
        &self,
        view: &View3,
        folder: &FolderId,
        object: &ObjectName,
    ) -> BTreeSet<String> {
        let (Ok(f), Ok(obj)) = (members3::bin(folder), crate::storages3::object_bin(object)) else {
            return BTreeSet::new();
        };
        let Ok(t) = self.table3(&f) else {
            return BTreeSet::new();
        };
        let t = t.read().unwrap_or_else(|e| e.into_inner());
        crate::storages3::block_copies(view, &*t, &obj)
    }

    /// Publish this push's map delta: the members of `written` at their
    /// places, to every hot metadata storage; the events go into this
    /// device's next batch.
    pub(super) fn publish_map3(
        &mut self,
        folder: &Id16,
        epoch: u32,
        written: &[WrittenPack],
        view: &View3,
    ) -> Result<()> {
        if written.is_empty() {
            return Ok(());
        }
        let lamport = self.tick()?;
        let (vault, me, vault_keys) = self.record_writer_parts();
        let table = self.table3(folder)?;
        let storages = self.record_storages3()?;
        let refs: Vec<&dyn Storage> = storages.iter().map(|(_, b)| &**b).collect();
        let events =
            {
                let keys = self.keys3(&vault_keys);
                let signer = DeviceSigner {
                    device: me,
                    key: &self.keys.signer,
                };
                let rw = RecordWriter {
                    vault,
                    signer: &signer,
                    keys: &keys,
                };
                let highest =
                    match refs.first() {
                        Some(s) => RecordStore {
                            storage: *s,
                            acceptor: Acceptor {
                                vault,
                                keys: &keys,
                                trust: &crate::membership3::Trust {
                                    devices: &self.f3.members.devices,
                                    revoked: &self.f3.members.revoked,
                                    folders: None,
                                    members: None,
                                },
                            },
                        }
                        .highest_seq(&crate::record::StreamRef::new(Kind::BlockMap, *folder, me))?,
                        None => 0,
                    };
                let mut writer = MapWriter::from_view(*folder, me, epoch, view, highest);
                let mut t = table.write().unwrap_or_else(|e| e.into_inner());
                let p = writer.publish(&rw, &refs, written, lamport, Some(&t), view)?;
                let folder_pack = |p: &[u8; 32]| view.pack_folder(p).is_none_or(|f| f == *folder);
                p.apply_to(&mut t, &folder_pack)?;
                p.events
            };
        self.f3.pending.extend(events);
        Ok(())
    }

    /// Publish this device's manifest of `folder` when its view changed
    /// since the last one: a delta (or a base, by section 7's rule) to every
    /// hot metadata storage; the announcement goes into the next batch.
    /// Returns the record's seq.
    pub(super) fn publish_manifest3(
        &mut self,
        folder: &Id16,
        epoch: u32,
        state: &FolderState,
    ) -> Result<Option<u64>> {
        let storages = self.record_storages3()?;
        if storages.is_empty() {
            return Ok(None);
        }
        let mut current = BTreeMap::new();
        for f in state.files.values() {
            let e = FileEntry::from_state(f, held_here(state, f))?;
            current.insert(e.path.clone(), e);
        }
        let mut manifests = self.load_manifests3(folder);
        let (vault, me, vault_keys) = self.record_writer_parts();
        let view = self.view3()?;
        let mut writer = ManifestWriter::new(*folder, me);

        if let Some(own) = manifests.views.get(&me) {
            // Nothing changed since the last record: no storage is asked.
            if own.files == current {
                return Ok(None);
            }
            writer.seq = own.seq;
            writer.base_seq = own.base;
            writer.hash = own.hash;
            writer.published = own.files.clone();
            if own.files == current {
                // Nothing changed: no listing, no record.
                return Ok(None);
            }
        }
        if let Some(st) = view.stream(Kind::Manifest.code(), folder, &me) {
            if let Some((b, _, _)) = st.base() {
                writer.base_bytes = st.records.get(&b).map_or(0, |a| a.size);
                writer.delta_bytes = st.records.range(b + 1..).map(|(_, a)| a.size).sum();
            }
        }
        let lamport = self.tick()?;
        let now = util::now_utc();
        let key = KeyId::Meta {
            folder: *folder,
            epoch,
        };
        let refs: Vec<&dyn Storage> = storages.iter().map(|(_, b)| &**b).collect();
        let published = {
            let keys = self.keys3(&vault_keys);
            let signer = DeviceSigner {
                device: me,
                key: &self.keys.signer,
            };
            let rw = RecordWriter {
                vault,
                signer: &signer,
                keys: &keys,
            };
            let highest = RecordStore {
                storage: refs[0],
                acceptor: Acceptor {
                    vault,
                    keys: &keys,
                    trust: &crate::membership3::Trust {
                        devices: &self.f3.members.devices,
                        revoked: &self.f3.members.revoked,
                        folders: None,
                        members: None,
                    },
                },
            }
            .highest_seq(&crate::manifest3::stream(*folder, me))?;
            writer.resume(highest);
            let mut out = None;
            for _ in 0..4 {
                let Some(p) = writer.seal(&rw, &key, &current, lamport, now)? else {
                    break;
                };
                let mut taken = false;
                for (name, bytes) in &p.sealed.parts {
                    if !refs[0].put_if_absent(name, bytes)? {
                        taken = true;
                        break;
                    }
                }
                if taken {
                    writer.abandon(p);
                    continue;
                }
                for s in &refs[1..] {
                    for (name, bytes) in &p.sealed.parts {
                        s.put_if_absent(name, bytes)?;
                    }
                }
                out = Some(p.sealed.published.clone());
                writer.commit(p);
                break;
            }
            out
        };
        let Some(a) = published else {
            return Ok(None);
        };
        manifests.insert_view(WriterView {
            device: me,
            seq: writer.seq,
            base: writer.base_seq,
            hash: writer.hash,
            lamport,
            created_utc: now,
            files: writer.published.clone(),
        });
        self.save_manifests3(&manifests)?;
        self.f3.pending.push(Event3::RecordPublished(Announcement {
            kind: a.kind,
            scope: a.scope,
            seq: a.seq,
            base: a.base,
            parts: a.parts,
            body_hash: a.body_hash,
            size: a.size,
        }));
        Ok(Some(a.seq))
    }
}
