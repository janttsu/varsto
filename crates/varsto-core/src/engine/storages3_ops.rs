// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Storages on the pack-level ledger in the engine
//! (`docs/spec/format-3-design.md` sections 3 and 4, spec section 77.9):
//! the helpers the data moves, drains, quotas, pools, policies, replicas,
//! transferrers, forwarding, the mailbox and imports share.
//!
//! - Every question about copies goes to `storages3` with the view
//!   (`view3`) and the folder's block map table (`table3`).
//! - The view names storages by each writer's local name; `storage-names`
//!   records (kind 19) map those names to storage identities
//!   (`vault/storage-id.json`), and `localize_view` renames the places of
//!   other writers to this device's names, so a pack another device
//!   claimed on "nas" counts as held on this device's "home-nas" when both
//!   are one storage.

use super::*;
use crate::blockmap::MapTable;
use crate::ledger3::LedgerView as View3;
use crate::record::{Acceptor, DeviceSigner, Id16, KeyId, RecordStore, RecordWriter};
use crate::records3::{storage_names_stream, StorageNamesBody};
use std::sync::{Arc, RwLock};

/// Other devices' names for storages: device -> (their name -> identity).
pub(super) type TheirNames = BTreeMap<Id16, BTreeMap<String, String>>;

impl Engine {
    /// The map table of a folder whose keys this device holds (`None`
    /// without them: no block of it can be placed here).
    pub(super) fn folder_table3(
        &self,
        rec: &FolderRecord,
    ) -> Result<Option<Arc<RwLock<MapTable>>>> {
        if rec.key_hex.is_empty() && rec.epoch_keys.is_empty() {
            return Ok(None);
        }
        let Ok(f) = members3::bin(&rec.folder_id) else {
            return Ok(None);
        };
        Ok(Some(self.table3(&f)?))
    }

    /// Objects with a live place on `storage` (its pack held there, the
    /// place not marked dead or lost), over every folder whose map is held
    /// here. Hex object names.
    pub fn objects_on_storage3(&self, storage: &str) -> Result<BTreeSet<String>> {
        let view = self.view3()?;
        let mut out = BTreeSet::new();
        for rec in self.keyring.folders.values().filter(|r| !r.is_removed()) {
            let Some(t) = self.folder_table3(rec)? else {
                continue;
            };
            let t = t.read().unwrap_or_else(|e| e.into_inner());
            for row in t.scan() {
                let row = row?;
                if view.is_held(&row.place.pack, storage)
                    && crate::blockmap::place_is_live(&t, &row)?
                {
                    out.insert(hex::encode(row.object));
                }
            }
        }
        Ok(out)
    }

    /// The bytes of the live blocks on `storage` (each object once), as the
    /// map lists their lengths.
    pub fn block_bytes_on_storage3(&self, storage: &str) -> Result<u64> {
        let view = self.view3()?;
        let mut seen = HashSet::new();
        let mut bytes = 0u64;
        for rec in self.keyring.folders.values().filter(|r| !r.is_removed()) {
            let Some(t) = self.folder_table3(rec)? else {
                continue;
            };
            let t = t.read().unwrap_or_else(|e| e.into_inner());
            for row in t.scan() {
                let row = row?;
                if view.is_held(&row.place.pack, storage)
                    && crate::blockmap::place_is_live(&t, &row)?
                    && seen.insert(row.object)
                {
                    bytes += u64::from(row.place.len);
                }
            }
        }
        Ok(bytes)
    }

    /// Packs the view shows held on `storage`, with their classes.
    pub fn packs_on_storage3(&self, storage: &str) -> Result<BTreeMap<String, u8>> {
        let view = self.view3()?;
        Ok(view
            .packs_on(storage)
            .map(|(id, r)| (hex::encode(id), r.class))
            .collect())
    }

    /// Seal the events recorded so far into a batch and push it now, also
    /// inside an action that seals one batch at its end (`one_batch`): a
    /// move, a drain or a transferrer deletes a pack only after the batch
    /// with its drop is on the storages.
    pub(super) fn commit_now3(&mut self) -> Result<()> {
        let cycle = self.cycle.take();
        let r = self.commit_batch();
        self.cycle = cycle;
        r.map(|_| ())
    }

    /// Run `f` with a record store over every hot metadata storage, judging
    /// records with this device's keys and trust.
    pub(super) fn with_records3(
        &self,
        mut f: impl FnMut(&RecordStore) -> Result<()>,
    ) -> Result<()> {
        let vault = members3::bin(&self.vault.vault_id)?;
        let vault_keys = self.vault_keys3();
        let keys = self.keys3(&vault_keys);
        let trust = self.f3.members.trust();
        for (_, backend) in self.record_storages3()? {
            let store = RecordStore {
                storage: backend.as_ref(),
                acceptor: Acceptor {
                    vault,
                    keys: &keys,
                    trust: &trust,
                },
            };
            f(&store)?;
        }
        Ok(())
    }

    /// Publish the next record of one of this device's unannounced,
    /// vault-wide streams (newest seq wins) under the registry key of the
    /// newest vault epoch, on every hot metadata storage. `body` makes the
    /// body for the seq.
    pub(super) fn publish_newest3<T: crate::record::RecordBody>(
        &self,
        stream: &crate::record::StreamRef,
        body: impl Fn(u64) -> T,
    ) -> Result<()> {
        let storages = self.record_storages3()?;
        if storages.is_empty() {
            return Ok(());
        }
        let vault = members3::bin(&self.vault.vault_id)?;
        let me = self.me3();
        let vault_keys = self.vault_keys3();
        let keys = self.keys3(&vault_keys);
        let trust = self.f3.members.trust();
        let mut highest = 0u64;
        for (_, backend) in &storages {
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
        let signer = DeviceSigner {
            device: me,
            key: &self.keys.signer,
        };
        let rw = RecordWriter {
            vault,
            signer: &signer,
            keys: &keys,
        };
        let seq = highest + 1;
        let sealed = rw.seal(
            stream,
            seq,
            seq,
            &KeyId::Registry(vault_keys.newest_epoch()),
            &body(seq),
        )?;
        for (_, backend) in &storages {
            for (name, bytes) in &sealed.parts {
                backend.put_if_absent(name, bytes)?;
            }
        }
        Ok(())
    }

    /// For `fsck`: the packs the view holds on a pool whose disks are all
    /// away, and the disks away that hold any ("<label> (<place>), last
    /// verified <date>"). With `verified` every attached disk was read in
    /// full and its check is recorded.
    pub(super) fn pools_offline3(
        &mut self,
        view: &View3,
        verified: bool,
    ) -> Result<(u64, Vec<String>)> {
        let mut offline = 0u64;
        let mut disks = Vec::new();
        for spec in self.pool_specs() {
            let pool = self.open_pool(&spec)?;
            for (id, _) in view.packs_on(spec.name()) {
                let locs = pool.locate_all(&crate::packs::pack_key(&hex::encode(id)));
                if !locs.is_empty() && !locs.iter().any(|l| l.attached) {
                    offline += 1;
                }
            }
            if verified {
                let attached: Vec<String> = pool
                    .statuses()
                    .into_iter()
                    .filter(|d| d.attached)
                    .map(|d| d.disk_id)
                    .collect();
                pool.mark_verified(&attached)?;
            }
            for d in pool.statuses() {
                if !d.attached && d.objects > 0 {
                    disks.push(format!(
                        "{} ({}), last verified {}",
                        d.label,
                        d.place,
                        if d.last_verified_utc > 0 {
                            util::format_date(d.last_verified_utc)
                        } else {
                            "never".to_string()
                        }
                    ));
                }
            }
            let list = pool.disks();
            drop(pool);
            self.save_pool_disks(spec.name(), list)?;
        }
        Ok((offline, disks))
    }

    /// Copy every record of the vault (membership, map, manifest, trash and
    /// other records, every device's ledger batches and checkpoints) that a
    /// newly added storage lacks from the hot metadata storages that hold
    /// them, so a device that reads only the new storage finds them too.
    /// Packs are not copied (placement and moves decide where blocks go).
    /// Returns how many objects were copied.
    pub(super) fn copy_records_to(&self, name: &str) -> Result<u64> {
        let Some(spec) = self.config.storages.iter().find(|s| s.name() == name) else {
            return Ok(0);
        };
        if spec.is_data_only() || spec.is_cold() {
            return Ok(0);
        }
        let target = self.open_spec(spec)?;
        let have: HashSet<String> = target.list("")?.into_iter().collect();
        let mut copied = 0u64;
        for (other, backend) in self.metadata_storages(false)? {
            if other.name() == name {
                continue;
            }
            let Ok(keys) = backend.list("") else {
                continue;
            };
            for key in keys {
                let record = !key.starts_with("chunks/")
                    && !key.starts_with(crate::packs::PREFIX)
                    && key != super::verify::STORAGE_ID_KEY
                    && key != VaultMeta::STORAGE_KEY
                    && !key.contains("-leases/")
                    && !key.split('/').any(|p| p.starts_with('.'));
                if !record || have.contains(&key) {
                    continue;
                }
                if let Ok(Some(bytes)) = backend.get_bounded(&key, crate::record::MAX_PART_READ) {
                    if target.put_if_absent(&key, &bytes)? {
                        copied += 1;
                    }
                }
            }
        }
        Ok(copied)
    }

    // ----- policies (kind 11) and placements (kind 12) ------------------------

    /// Publish this device's `policy` record: the policy of every folder
    /// it knows one of (set here or adopted), each with the time it was
    /// set; per folder the newest entry of any device wins.
    pub(super) fn publish_policies3(&self) -> Result<()> {
        let me = self.me3();
        let mut folders: Vec<(Id16, crate::records3::PolicyEntry)> = self
            .keyring
            .folders
            .values()
            .filter(|r| r.policy_updated_utc > 0 && !r.is_removed())
            .filter_map(|r| {
                Some((
                    members3::bin(&r.folder_id).ok()?,
                    crate::records3::PolicyEntry {
                        policy: r
                            .policy
                            .as_ref()
                            .filter(|p| {
                                p.min_copies > 0
                                    || !p.min_per_place.is_empty()
                                    || p.verified_within_days.is_some()
                            })
                            .map(crate::records3::PolicyWire::from),
                        updated_utc: r.policy_updated_utc,
                        lamport: 0,
                    },
                ))
            })
            .collect();
        folders.sort_by_key(|(f, _)| *f);
        self.publish_newest3(&crate::records3::policy_stream(me), |seq| {
            crate::records3::PolicyBody {
                device: me,
                seq,
                folders: folders.clone(),
            }
        })
    }

    /// Publish this device's `placement` record of a folder.
    pub(super) fn publish_placement3(
        &self,
        rec: &FolderRecord,
        placement: Option<&crate::placement::Placement>,
        updated_utc: i64,
    ) -> Result<()> {
        let me = self.me3();
        let folder = members3::bin(&rec.folder_id)?;
        let lamport = self.clock.lamport;
        let empty = crate::placement::Placement::default();
        let p = placement.unwrap_or(&empty);
        self.publish_newest3(&crate::records3::placement_stream(folder, me), |seq| {
            crate::records3::PlacementBody {
                folder,
                device: me,
                seq,
                lamport,
                updated_utc,
                storages: p.storages.clone(),
                storage_ids: p
                    .storage_ids
                    .iter()
                    .map(|(n, i)| (n.clone(), i.clone()))
                    .collect(),
                places: p.places.clone(),
            }
        })
    }

    /// Adopt the newest policy and placement of every folder from the full
    /// devices' records (in an organization only from devices its policy
    /// lets set them). Returns whether a folder changed.
    pub(super) fn refresh_folder_rules3(&mut self) -> Result<bool> {
        if self.vault.member {
            return Ok(false);
        }
        let devices: Vec<Id16> = self
            .f3
            .members
            .devices
            .devices
            .keys()
            .filter(|d| !self.f3.members.revoked.contains(*d))
            .copied()
            .collect();
        let folders: Vec<Id16> = self
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed())
            .filter_map(|r| members3::bin(&r.folder_id).ok())
            .collect();
        let mut policies: Vec<crate::records3::PolicyBody> = Vec::new();
        let mut placements: BTreeMap<Id16, Vec<crate::records3::PlacementBody>> = BTreeMap::new();
        self.with_records3(|store| {
            let mut refused = crate::record::RecordsRefused::default();
            let streams: Vec<_> = devices
                .iter()
                .map(|d| crate::records3::policy_stream(*d))
                .collect();
            policies.extend(crate::records3::read_newest::<crate::records3::PolicyBody>(
                store,
                &streams,
                &mut refused,
            )?);
            for f in &folders {
                let streams: Vec<_> = devices
                    .iter()
                    .map(|d| crate::records3::placement_stream(*f, *d))
                    .collect();
                placements
                    .entry(*f)
                    .or_default()
                    .extend(crate::records3::read_newest::<
                        crate::records3::PlacementBody,
                    >(store, &streams, &mut refused)?);
            }
            Ok(())
        })?;
        let accepted: BTreeSet<Id16> = devices
            .iter()
            .filter(|d| {
                let id = DeviceId::from_bytes(*d);
                self.trusted(&id) && self.org_accepts_policy_from(&id)
            })
            .copied()
            .collect();
        let accepts = |d: &Id16| accepted.contains(d);
        policies.retain(|b| accepts(&b.device));
        let newest = crate::records3::newest_policies(&policies);
        let mut changed = false;
        for rec in self.keyring.folders.values_mut() {
            let Ok(f) = members3::bin(&rec.folder_id) else {
                continue;
            };
            if let Some((e, _)) = newest.get(&f) {
                if e.updated_utc > rec.policy_updated_utc {
                    rec.policy = Some(
                        e.policy
                            .as_ref()
                            .map(crate::policy::Policy::from)
                            .unwrap_or_default(),
                    );
                    rec.policy_updated_utc = e.updated_utc;
                    changed = true;
                }
            }
            let list: Vec<&crate::records3::PlacementBody> = placements
                .get(&f)
                .into_iter()
                .flatten()
                .filter(|b| accepts(&b.device))
                .collect();
            if let Some(b) = crate::records3::newest_placement(list) {
                if b.updated_utc > rec.placement_updated_utc {
                    let p = b.placement();
                    rec.placement = (!p.is_everywhere()).then_some(p);
                    rec.placement_updated_utc = b.updated_utc;
                    changed = true;
                }
            }
        }
        if changed {
            self.keyring.save(
                &self.home,
                &self.keys,
                &self.vault.vault_id,
                &self.vault.device_id,
            )?;
        }
        Ok(changed)
    }

    // ----- replicas (kind 23) ------------------------------------------------

    /// The replicas of the vault: the `replica` records of the full devices
    /// (kind 23), and the enrolment requests replicas left on the storages,
    /// which this device enrols by writing its own record (a request opens
    /// only under the replica key, which only the owner's token carries).
    pub(super) fn refresh_replicas3(&mut self) {
        if self.vault.member {
            return;
        }
        let me = self.me3();
        let Ok(vault) = members3::bin(&self.vault.vault_id) else {
            return;
        };
        let devices: Vec<Id16> = self
            .f3
            .members
            .devices
            .devices
            .keys()
            .filter(|d| !self.f3.members.revoked.contains(*d))
            .copied()
            .collect();
        let mut known: BTreeMap<Id16, (String, crate::crypto::VerifyingKey)> = BTreeMap::new();
        let mut mine: Vec<crate::replica::ReplicaEntry> = Vec::new();
        let mut mine_seq = 0u64;
        let read = self.with_records3(|store| {
            let streams: Vec<_> = devices
                .iter()
                .map(|d| crate::replica::replica_stream(*d))
                .collect();
            let mut refused = crate::record::RecordsRefused::default();
            for b in crate::records3::read_newest::<crate::replica::ReplicaBody>(
                store,
                &streams,
                &mut refused,
            )? {
                if b.device == me && b.seq > mine_seq {
                    mine_seq = b.seq;
                    mine = b.replicas.clone();
                }
                for e in &b.replicas {
                    if let Ok(k) = crate::crypto::VerifyingKey::from_bytes(&e.k6) {
                        known.insert(e.replica, (e.name.clone(), k));
                    }
                }
            }
            Ok(())
        });
        if let Err(e) = read {
            log::debug!("replica records not read: {e:#}");
        }
        // Requests not enrolled yet.
        let key = crate::replica::replica_key(self.root_key(), &self.vault.vault_id);
        let mut fresh: Vec<crate::replica::ReplicaEntry> = Vec::new();
        if let Ok(storages) = self.record_storages3() {
            for (_, backend) in &storages {
                let Ok(names) = backend.list(crate::replica::REPLICA_PREFIX) else {
                    continue;
                };
                for name in names {
                    let Some(id) = name
                        .strip_prefix(crate::replica::REPLICA_PREFIX)
                        .and_then(|s| s.strip_suffix(".enc"))
                        .and_then(|s| hex::decode(s).ok())
                        .and_then(|b| Id16::try_from(b).ok())
                    else {
                        continue;
                    };
                    if known.contains_key(&id) || fresh.iter().any(|e| e.replica == id) {
                        continue;
                    }
                    let Ok(Some(blob)) = backend.get_bounded(&name, 1 << 20) else {
                        continue;
                    };
                    let Ok(req) = crate::replica::EnrolmentRequest::open(&blob, &vault, &id, &key)
                    else {
                        log::warn!("replica enrolment request {name} refused");
                        continue;
                    };
                    let Ok(k6) = hex::decode(&req.k6) else {
                        continue;
                    };
                    fresh.push(crate::replica::ReplicaEntry {
                        replica: id,
                        name: req.name,
                        k6,
                        enrolled_utc: util::now_utc(),
                    });
                }
            }
        }
        if !fresh.is_empty() {
            mine.extend(fresh.iter().cloned());
            mine.sort_by_key(|e| e.replica);
            let body = |seq| crate::replica::ReplicaBody {
                device: me,
                seq,
                replicas: mine.clone(),
            };
            match self.publish_newest3(&crate::replica::replica_stream(me), body) {
                Ok(()) => {
                    for e in fresh {
                        if let Ok(k) = crate::crypto::VerifyingKey::from_bytes(&e.k6) {
                            log::info!(replica = e.name.as_str(); "replica enrolled");
                            known.insert(e.replica, (e.name, k));
                        }
                    }
                }
                Err(e) => log::warn!("replica not enrolled: {e:#}"),
            }
        }
        let before: BTreeSet<Id16> = self.f3.replicas.keys().copied().collect();
        let after: BTreeSet<Id16> = known.keys().copied().collect();
        self.f3.replicas = known;
        if before != after {
            self.reset_view3();
        }
    }

    // ----- storage names (kind 19) -------------------------------------------

    /// This device's storages and their identities (pools are known by
    /// their pool identity).
    pub(super) fn own_storage_ids(
        &self,
        readable: &BTreeMap<String, Box<dyn Storage>>,
    ) -> BTreeMap<String, String> {
        let mut mine = BTreeMap::new();
        for spec in &self.config.storages {
            if spec.is_data_only() {
                mine.insert(
                    spec.name().to_string(),
                    format!("pool:{}", self.pool_identity(spec.name()).pool_id),
                );
                continue;
            }
            if let Some(b) = readable.get(spec.name()) {
                if let Ok(id) = super::verify::storage_identity(b.as_ref()) {
                    mine.insert(spec.name().to_string(), id);
                }
            }
        }
        mine
    }

    /// The shared settings of this device's storages as a record carries
    /// them (by storage key).
    fn own_storage_settings(&self) -> Vec<crate::records3::StorageSettingsEntry> {
        let keys = self.storage_keys();
        let me = self.me3();
        let mut out: Vec<crate::records3::StorageSettingsEntry> = self
            .config
            .storage_settings
            .iter()
            .filter_map(|(name, e)| {
                Some(crate::records3::StorageSettingsEntry {
                    storage: keys.get(name)?.to_string(),
                    by: e
                        .by
                        .as_ref()
                        .and_then(|d| members3::bin(d).ok())
                        .unwrap_or(me),
                    updated_utc: e.updated_utc,
                    settings_json: serde_json::to_vec(&e.settings).ok()?,
                })
            })
            .collect();
        out.sort_by(|a, b| a.storage.cmp(&b.storage));
        out.dedup_by(|a, b| a.storage == b.storage);
        out
    }

    /// Publish this device's storage names and the shared storage settings
    /// it knows (when they changed) as a `storage-names` record on every
    /// hot metadata storage, and read the newest record of every other full
    /// device.
    pub(super) fn exchange_storage_names3(
        &self,
        mine: &BTreeMap<String, String>,
    ) -> Vec<StorageNamesBody> {
        let mut out: Vec<StorageNamesBody> = Vec::new();
        if self.vault.member {
            return out;
        }
        let me = self.me3();
        let devices: Vec<Id16> = self.f3.members.devices.devices.keys().copied().collect();
        let mut own: Option<StorageNamesBody> = None;
        let mut newest: BTreeMap<Id16, StorageNamesBody> = BTreeMap::new();
        let read = self.with_records3(|store| {
            let streams: Vec<_> = devices.iter().map(|d| storage_names_stream(*d)).collect();
            let mut refused = crate::record::RecordsRefused::default();
            for b in
                crate::records3::read_newest::<StorageNamesBody>(store, &streams, &mut refused)?
            {
                if b.device == me {
                    if own.as_ref().is_none_or(|o| o.seq < b.seq) {
                        own = Some(b);
                    }
                    continue;
                }
                if newest.get(&b.device).is_none_or(|o| o.seq < b.seq) {
                    newest.insert(b.device, b);
                }
            }
            Ok(())
        });
        if let Err(e) = read {
            log::debug!("storage names not read: {e:#}");
        }
        let names: Vec<(String, String)> =
            mine.iter().map(|(n, i)| (n.clone(), i.clone())).collect();
        let settings = self.own_storage_settings();
        let same = own
            .as_ref()
            .is_some_and(|o| o.names == names && o.settings == settings);
        if !same && (!names.is_empty() || !settings.is_empty()) {
            let published =
                self.publish_newest3(&storage_names_stream(me), |seq| StorageNamesBody {
                    device: me,
                    seq,
                    updated_utc: util::now_utc(),
                    names: names.clone(),
                    settings: settings.clone(),
                });
            if let Err(e) = published {
                log::debug!("storage names not published: {e:#}");
            }
        }
        out.extend(newest.into_values());
        out
    }

    /// Other devices' storage names, by device: (their name -> identity).
    pub(super) fn their_names3(bodies: &[StorageNamesBody]) -> TheirNames {
        bodies
            .iter()
            .map(|b| (b.device, b.names.iter().cloned().collect()))
            .collect()
    }

    /// Other devices' storage names that are one of this device's storages
    /// by identity: device -> (their name -> local name).
    pub(super) fn storage_aliases3(&self) -> BTreeMap<Id16, BTreeMap<String, String>> {
        util::read_json_or_default::<StoredAliases>(&self.aliases3_path())
            .unwrap_or_default()
            .into_map()
    }

    fn aliases3_path(&self) -> PathBuf {
        self.home.join("state").join("storage-aliases3.json")
    }

    /// Bring the aliases and the shared storage settings up to date:
    /// publish this device's names and settings, read the others', keep
    /// (their name -> local name) for the storages that are configured here
    /// and adopt newer settings of storages this device has.
    pub(super) fn refresh_storage_aliases3(&mut self) {
        let mut readable: BTreeMap<String, Box<dyn Storage>> = BTreeMap::new();
        for spec in &self.config.storages {
            if spec.is_data_only() || spec.is_cold() {
                continue;
            }
            if let Ok(b) = self.open_spec(spec) {
                readable.insert(spec.name().to_string(), b);
            }
        }
        let mine = self.own_storage_ids(&readable);
        drop(readable);
        let bodies = self.exchange_storage_names3(&mine);
        let theirs = Self::their_names3(&bodies);
        let by_id: BTreeMap<&String, &String> = mine.iter().map(|(n, i)| (i, n)).collect();
        let mut map: BTreeMap<Id16, BTreeMap<String, String>> = BTreeMap::new();
        for (d, names) in &theirs {
            for (n, id) in names {
                if let Some(local) = by_id.get(id) {
                    if *local != n {
                        map.entry(*d)
                            .or_default()
                            .insert(n.clone(), (*local).clone());
                    }
                } else if mine.contains_key(n) {
                    // Their storage of this name is not ours: keep their
                    // copies apart from ours.
                    map.entry(*d)
                        .or_default()
                        .insert(n.clone(), format!("{n}@{}", &hex::encode(d)[..8]));
                }
            }
        }
        let stored = StoredAliases::of(&map);
        let path = self.aliases3_path();
        if util::read_json_or_default::<StoredAliases>(&path).ok() != Some(stored.clone()) {
            let _ = util::write_json(&path, &stored);
            self.reset_view3();
        }
        if let Err(e) = self.adopt_storage_settings3(&bodies) {
            log::warn!("storage settings not adopted: {e:#}");
        }
    }

    /// Take the newest shared settings of each storage this device has from
    /// other devices' records. In an organization only an administrator's
    /// count, unless members may add storages.
    fn adopt_storage_settings3(&mut self, bodies: &[StorageNamesBody]) -> Result<()> {
        let keys = self.storage_keys();
        let by_key: BTreeMap<String, String> = keys
            .iter()
            .map(|(n, k)| (k.to_string(), n.clone()))
            .collect();
        let mut changed = false;
        for b in bodies {
            for e in &b.settings {
                let Some(name) = by_key.get(&e.storage) else {
                    continue;
                };
                let known = self
                    .config
                    .storage_settings
                    .get(name)
                    .map(|x| x.updated_utc)
                    .unwrap_or(0);
                if e.updated_utc <= known {
                    continue;
                }
                let by = DeviceId::from_bytes(&e.by);
                let allowed = match &self.org {
                    Some(o) => o.is_admin(&by) || o.policy().members_may_add_storages,
                    None => true,
                };
                if !allowed || !self.trusted(&by) {
                    continue;
                }
                let Ok(settings) = serde_json::from_slice::<crate::storage_settings::StorageSettings>(
                    &e.settings_json,
                ) else {
                    continue;
                };
                self.config.storage_settings.insert(
                    name.clone(),
                    crate::storage_settings::SettingsEntry {
                        settings,
                        updated_utc: e.updated_utc,
                        by: Some(by),
                    },
                );
                changed = true;
            }
        }
        if changed {
            self.config.save(&self.home)?;
        }
        Ok(())
    }
}

/// The aliases as kept on disk (hex device ids).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct StoredAliases {
    aliases: BTreeMap<String, BTreeMap<String, String>>,
}

impl StoredAliases {
    fn of(map: &BTreeMap<Id16, BTreeMap<String, String>>) -> StoredAliases {
        StoredAliases {
            aliases: map
                .iter()
                .map(|(d, m)| (hex::encode(d), m.clone()))
                .collect(),
        }
    }

    fn into_map(self) -> BTreeMap<Id16, BTreeMap<String, String>> {
        self.aliases
            .into_iter()
            .filter_map(|(d, m)| {
                let d: Id16 = hex::decode(d).ok()?.try_into().ok()?;
                Some((d, m))
            })
            .collect()
    }
}

/// `view` with every other device's storage names replaced by this
/// device's names for the same storages (`crate::storages3::localize`).
pub(super) fn localized(view: View3, aliases: &BTreeMap<Id16, BTreeMap<String, String>>) -> View3 {
    if aliases.is_empty() {
        return view;
    }
    crate::storages3::localize(view, aliases)
}
