// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The pack-level ledger of storage format 3 in the engine
//! (`docs/spec/format-3-design.md` section 4): this device's batches are
//! signed records under the ledger key of the newest vault epoch, pushed to
//! every hot metadata storage at `ledger/<device>/<seq 16>-0000.rec`; a
//! pull lists each known device's batches after the head held here and
//! hands them to `ledger3::LedgerStore`; the view is replayed from the
//! batches under the keys, cut-offs, scopes and folder roles of the
//! membership (`Members3`), and kept between calls.
//!
//! Events of the rest of the engine that are recorded in the format-2 form
//! (`Engine::pending`) are carried over into the batch where format 3 has
//! them (enrolment, folders, retirements, snapshots); the per-block events
//! of format 2 are not part of format 3 and are left out (format 3 claims
//! packs: `Engine::pending3`).

use super::*;
use crate::ledger3::events::{
    BackupStopped, DeviceEnrolled, Event as Event3, FolderAdded, SnapshotExpired, SnapshotTaken,
    StorageRetired,
};
use crate::ledger3::{self, EventScope, LedgerView as View3, ViewCache};
use crate::record::{Id16, KeyId};

/// The format-3 part of an engine.
pub(crate) struct Core3 {
    pub ledger: ledger3::LedgerStore,
    pub members: members3::Members3,
    /// The raw view and the context it was built under.
    pub view: std::sync::Mutex<Option<ViewCache>>,
    /// The folder block map tables opened in this process.
    pub tables: std::sync::Mutex<BTreeMap<Id16, std::sync::Arc<std::sync::RwLock<MapTable3>>>>,
    /// The recovery key of this session (`set_recovery_key`).
    pub recovery: Option<crate::membership3::RecoveryKey>,
    /// Events of the next batch.
    pub pending: Vec<Event3>,
    /// Replicas the vault's `replica` records name (`storages3_ops`):
    /// their batches count in the replica scope.
    pub replicas: BTreeMap<Id16, (String, crypto::VerifyingKey)>,
    /// Folder records (manifests, maps, trash) refused in this process,
    /// by kind.
    pub records_refused: std::sync::Mutex<crate::record::RecordsRefused>,
}

pub(crate) type MapTable3 = crate::blockmap::MapTable;

/// Shared folders this device announced its earlier work of in their
/// folder-scoped batches.
const ANNOUNCED_FILE: &str = "shared3.json";

impl Core3 {
    pub fn open(home: &Path, vault: &VaultId) -> Result<Core3> {
        Ok(Core3 {
            ledger: ledger3::LedgerStore::open(&home.join("ledger"), members3::bin(vault)?)?,
            members: Default::default(),
            view: Default::default(),
            tables: Default::default(),
            recovery: None,
            pending: Vec::new(),
            replicas: BTreeMap::new(),
            records_refused: Default::default(),
        })
    }
}

/// `Engine::key_for3` over the parts of an engine it needs (so that the
/// ledger store can be borrowed apart from them). `member`: this device is
/// a member device of another vault.
pub(crate) fn key_for3_in(
    epochs: &membership::VaultEpochs,
    members: &members3::Members3,
    member: bool,
    key_id: &str,
) -> Option<SecretKey> {
    match KeyId::parse(key_id)? {
        // A member device of another vault holds no vault key: the
        // owners' vault batches stay closed to it (stored, not applied).
        KeyId::Ledger(_) if member => None,
        KeyId::Ledger(e) => Some(crate::membership3::derive3(
            epochs.keys.get(&e)?,
            "ledger",
            &[],
        )),
        KeyId::ShareLedger { folder, epoch } => members.granted.get(&folder)?.share_ledger(epoch),
        // Replicas: `Engine::key_for3` (it holds the replica key).
        _ => None,
    }
}

/// `Engine::scope3` over the membership alone (the organization's check
/// of `org_untrusted3` is the caller's).
pub(crate) fn scope3_in(m: &members3::Members3, device: &Id16, key_id: &str) -> Option<EventScope> {
    match EventScope::of_key_id(key_id)? {
        EventScope::Full => m.devices.get(device).map(|_| EventScope::Full),
        EventScope::Member(f) if m.devices.get(device).is_some() => Some(EventScope::Owner(f)),
        EventScope::Member(f) => {
            m.members.get(&f, device)?;
            let st = m.registry.get(&f)?;
            let wrote = st.history.get(device).is_some_and(|h| {
                h.iter()
                    .any(|(_, r)| matches!(r, Some(r) if *r != crate::membership3::Role::Viewer))
            });
            if wrote {
                Some(EventScope::Member(f))
            } else {
                Some(EventScope::Viewer(f))
            }
        }
        // Replicas: `Engine::scope3` (it knows the enrolled ones).
        _ => None,
    }
}

impl Engine {
    /// Folder records of other writers refused by the acceptance rule in
    /// this process (a viewer's manifests, junk under a writer's name).
    pub fn records_refused3(&self) -> u64 {
        self.f3
            .records_refused
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .total()
    }
}

/// The format-3 form of a format-2 event, where format 3 has one.
pub(crate) fn convert(ev: &Event) -> Option<Event3> {
    let b = |id: &crate::ids::Id| members3::bin(id).ok();
    Some(match ev {
        Event::DeviceEnrolled { name } => {
            Event3::DeviceEnrolled(DeviceEnrolled { name: name.clone() })
        }
        Event::FolderAdded { folder } => Event3::FolderAdded(FolderAdded { folder: b(folder)? }),
        Event::StorageRetired { storage } => Event3::StorageRetired(StorageRetired {
            storage: storage.clone(),
        }),
        Event::SnapshotTaken {
            backup,
            seq,
            taken_utc,
            expires_utc,
            files,
            bytes,
            ..
        } => Event3::SnapshotTaken(SnapshotTaken {
            backup: b(backup)?,
            seq: *seq,
            taken_utc: *taken_utc,
            expires_utc: *expires_utc,
            files: *files,
            bytes: *bytes,
        }),
        Event::SnapshotExpired {
            backup,
            device,
            seq,
        } => Event3::SnapshotExpired(SnapshotExpired {
            backup: b(backup)?,
            device: b(device)?,
            seq: *seq,
        }),
        Event::BackupStopped { backup } => {
            Event3::BackupStopped(BackupStopped { backup: b(backup)? })
        }
        // Per-block events of format 2: format 3 claims packs instead.
        Event::ChunkStored { .. }
        | Event::ChunkOnDevice { .. }
        | Event::ManifestPublished { .. }
        | Event::ChunkDropped { .. }
        | Event::Unknown => return None,
    })
}

impl Engine {
    /// The ledger key id and key of this device's batches: the newest vault
    /// epoch held.
    pub(crate) fn ledger_key3(&self) -> Result<(String, SecretKey)> {
        let keys = self.vault_keys3();
        let e = keys.newest_epoch();
        let k = keys
            .ledger(e)
            .ok_or_else(|| anyhow!("no vault key of epoch {e} is held here"))?;
        Ok((ledger3::scope::ledger_key_id(e), k))
    }

    /// The key that opens a batch or checkpoint with `key_id`, if held.
    pub(crate) fn key_for3(&self, key_id: &str) -> Option<SecretKey> {
        // Replicas' batches (`storages3_ops`).
        if !self.vault.member && matches!(KeyId::parse(key_id), Some(KeyId::Replica)) {
            return Some(crate::replica::replica_key(
                self.root_key(),
                &self.vault.vault_id,
            ));
        }
        key_for3_in(&self.epochs, &self.f3.members, self.vault.member, key_id)
    }

    /// Whether batch `seq` of `device` counts: a removed device's only up
    /// to its cut-off.
    fn keep3(&self, device: &Id16, seq: u64) -> bool {
        self.f3
            .members
            .cutoffs
            .get(device)
            .is_none_or(|c| seq <= *c)
    }

    /// The role a batch of `device` under `key_id` is read with: full
    /// devices of the registry under the vault ledger key, and under a
    /// folder's key for a folder shared with other people (`Owner`);
    /// member devices of shared folders under their folder's key. When a
    /// folder event counts is the folder roles' (by Lamport time): what a
    /// member wrote while it was an editor stays.
    pub(crate) fn scope3(&self, device: &Id16, key_id: &str) -> Option<EventScope> {
        // In an organization, a device the roster does not list (or a
        // platform its policy refuses) writes nothing that counts.
        if self.org_untrusted3(device) {
            return None;
        }
        // Replicas a `replica` record of a full device names.
        if matches!(EventScope::of_key_id(key_id), Some(EventScope::Replica)) {
            return self
                .f3
                .replicas
                .contains_key(device)
                .then_some(EventScope::Replica);
        }
        scope3_in(&self.f3.members, device, key_id)
    }

    /// What decides which batches count, as text: the keys held, the
    /// cut-offs, every device's scope and the folder roles.
    fn view_context3(&self) -> String {
        let m = &self.f3.members;
        let mut parts: Vec<Vec<u8>> = Vec::new();
        for (e, k) in &self.epochs.keys {
            parts.push(e.to_le_bytes().to_vec());
            parts.push(crypto::hash(&k.0).to_vec());
        }
        for (f, k) in &m.granted.folders {
            parts.push(f.to_vec());
            for (e, k9) in &k.epochs {
                parts.push(e.to_le_bytes().to_vec());
                parts.push(crypto::hash(&k9.0).to_vec());
            }
        }
        for (d, c) in &m.cutoffs {
            parts.push(d.to_vec());
            parts.push(c.to_le_bytes().to_vec());
        }
        for d in m.devices.devices.keys() {
            parts.push(d.to_vec());
            parts.push(vec![self.org_untrusted3(d) as u8]);
        }
        for (f, d) in m.members.members.keys() {
            parts.push(f.to_vec());
            parts.push(d.to_vec());
        }
        for d in self.f3.replicas.keys() {
            parts.push(b"replica".to_vec());
            parts.push(d.to_vec());
        }
        for (f, st) in &m.registry.folders {
            parts.push(f.to_vec());
            for (d, h) in &st.history {
                parts.push(d.to_vec());
                for (s, r) in h {
                    parts.push(s.lamport.to_le_bytes().to_vec());
                    parts.push(s.device.to_vec());
                    parts.push(vec![r.map_or(0, |r| r as u8 + 1)]);
                }
            }
        }
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        hex::encode(crypto::hash(&crypto::aad("ledger3-view-context", &refs)))
    }

    /// The pack-level view: the batches held here applied under the
    /// membership's keys, cut-offs, scopes and folder roles (kept between
    /// calls and brought up to date with new batches).
    pub(crate) fn view3(&self) -> Result<View3> {
        let context = self.view_context3();
        let mut slot = self.f3.view.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            // The view saved by an earlier process (`ledger/view.rec`).
            *slot = self.load_view();
        }
        let fits = slot.as_ref().is_some_and(|c| {
            c.format == ViewCache::FORMAT && c.context == context && self.f3.ledger.cache_fits(c)
        });
        if !fits {
            *slot = Some(ViewCache::new(context));
        }
        let cache = slot.as_mut().expect("set above");
        let applied = self.f3.ledger.update_view_with_roles(
            cache,
            |id| self.key_for3(id),
            |d, seq| self.keep3(d, seq),
            |d, id| self.scope3(d, id),
            &self.f3.members.registry,
        )?;
        if applied > 0 {
            if let Err(e) = self.save_view(cache) {
                log::debug!("ledger view not saved: {e:#}");
            }
        }
        // Other devices' names for this device's storages become its own.
        let view = self.f3.ledger.finish(&cache.raw);
        Ok(storages3_ops::localized(view, &self.storage_aliases()))
    }

    pub(crate) fn view3_path(&self) -> PathBuf {
        self.home.join("ledger").join("view.rec")
    }

    /// The local key of the saved view, and its associated data.
    fn view3_key(&self) -> (SecretKey, Vec<u8>) {
        (
            self.keys.master.derive("ledger3-view-cache", &[]),
            crypto::aad(
                "ledger3-view-cache",
                &[
                    self.vault.vault_id.as_str().as_bytes(),
                    self.vault.device_id.as_str().as_bytes(),
                ],
            ),
        )
    }

    pub(crate) fn load_view(&self) -> Option<ViewCache> {
        let blob = fs::read(self.view3_path()).ok()?;
        let (key, aad) = self.view3_key();
        ViewCache::open(&blob, &key, &aad).ok()
    }

    fn save_view(&self, cache: &ViewCache) -> Result<()> {
        let path = self.view3_path();
        // Never recreate a ledger directory that was removed (reset, wipe).
        if !path.parent().is_some_and(|p| p.is_dir()) {
            return Ok(());
        }
        let (key, aad) = self.view3_key();
        util::write_atomic(&path, &cache.seal(&key, &aad)?)
    }

    /// The view replayed from every local batch, without the one kept in
    /// memory (tests: the kept view must equal it).
    pub fn view3_replayed(&self) -> Result<View3> {
        let view = self.f3.ledger.view_with_roles(
            |id| self.key_for3(id),
            |d, seq| self.keep3(d, seq),
            |d, id| self.scope3(d, id),
            &self.f3.members.registry,
        )?;
        Ok(storages3_ops::localized(view, &self.storage_aliases()))
    }

    /// The pack-level view (`view3`), for tests and tools.
    pub fn ledger_view(&self) -> Result<View3> {
        self.view3()
    }

    /// This device's newest batch.
    pub fn own_head3(&self) -> u64 {
        self.f3.ledger.head(&self.me3()).seq
    }

    /// Forget the view kept in memory (keys or roles changed).
    pub(crate) fn reset_view(&self) {
        *self.f3.view.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Seal the events recorded since the last batch (format-3 events and
    /// the format-2 ones format 3 carries) into one batch and push it.
    pub(crate) fn commit3(&mut self) -> Result<Option<u64>> {
        if self.removal.is_some() {
            self.pending.clear();
            self.f3.pending.clear();
            self.clear_deferred();
            return self.ensure_active().map(|_| None);
        }
        if self.cycle.is_some() {
            // One batch at the end of the action (`one_batch`).
            self.defer_events()?;
            return Ok(None);
        }
        let mut events: Vec<Event3> = self.pending.iter().filter_map(convert).collect();
        if !events.is_empty() || !self.f3.pending.is_empty() {
            // A lost or damaged local ledger, a fork or a fence: nothing
            // is signed until a rebuild ran (the events stay pending).
            self.ensure_ledger_writable()?;
        }
        events.append(&mut self.f3.pending);
        self.pending.clear();
        self.clear_deferred();
        if self.forked_self && !events.is_empty() {
            bail!("this device's ledger is forked; it must be re-enrolled as a new device");
        }
        // Folders shared with other people: the folder's events go into a
        // folder-scoped batch under its share-ledger key, which the members
        // read (they hold no vault key); the first time this device sees a
        // folder shared, it announces there again what it published of it
        // before (its packs and its records), so a member that joins later
        // finds them. A member device writes folder-scoped batches only.
        let mut groups: BTreeMap<Id16, Vec<Event3>> = BTreeMap::new();
        let view = if self.vault.member || !self.shared_folders().is_empty() {
            self.view3().ok()
        } else {
            None
        };
        for ev in events {
            let f = self.batch_folder(&ev, view.as_ref());
            groups.entry(f).or_default().push(ev);
        }
        let announced = self.reannounce(&mut groups, view.as_ref())?;
        if groups.values().all(|g| g.is_empty()) {
            return Ok(None);
        }
        let me = self.me3();
        let seen = self.f3.ledger.vault_seen(&me);
        let n: usize = groups.values().map(|g| g.len()).sum();
        let mut last = None;
        for (folder, evs) in groups {
            if evs.is_empty() {
                continue;
            }
            let (key_id, key) = if folder == ledger3::NO_FOLDER {
                if self.vault.member {
                    bail!("a member device writes only for its shared folder");
                }
                self.ledger_key3()?
            } else {
                self.share_ledger_key(&folder)?
            };
            let raw: Vec<_> = evs.iter().map(Event3::to_raw).collect();
            // One batch per action (and folder), more only past the size limits.
            for group in ledger3::events::split_events(raw) {
                let lamport = self.tick()?;
                let rec = self.f3.ledger.append_own(
                    &me,
                    group,
                    seen.clone(),
                    lamport,
                    &key,
                    &key_id,
                    folder,
                    &self.keys.signer,
                )?;
                last = Some(rec.seq);
            }
        }
        log::debug!(events = n, seq = last.unwrap_or(0); "ledger batch sealed");
        if !announced.is_empty() {
            let mut done = self.announced3();
            done.extend(announced.iter().map(hex::encode));
            util::write_json(&self.home.join("state").join(ANNOUNCED_FILE), &done)?;
        }
        // The batch is sealed and kept here: a storage that does not answer
        // gets it with the next push, so an action done offline stands. A
        // fork of this device's ledger stays an error.
        if let Err(e) = self.push_own_batches3() {
            if self.forked_self {
                return Err(e);
            }
            log::warn!("ledger batch kept on this device, not pushed yet: {e:#}");
        }
        Ok(last)
    }

    /// Tests: what a modified client could sign, one batch of exactly
    /// `events` (a member device: its folder-scoped batch; otherwise under
    /// the vault ledger key) at Lamport time `lamport`, pushed to every
    /// storage. Other devices must take from it only what this device's
    /// role allows.
    #[doc(hidden)]
    pub fn seal_batch3_unchecked(&mut self, events: Vec<Event3>, lamport: u64) -> Result<u64> {
        let me = self.me3();
        let (key_id, key, scope) = match &self.f3.members.member {
            Some(m) => {
                let f = m.folder;
                let (id, k) = self.share_ledger_key(&f)?;
                (id, k, f)
            }
            None => {
                let (id, k) = self.ledger_key3()?;
                (id, k, ledger3::NO_FOLDER)
            }
        };
        let seen = self.f3.ledger.vault_seen(&me);
        let raw = events.iter().map(Event3::to_raw).collect();
        let rec = self.f3.ledger.append_own(
            &me,
            raw,
            seen,
            lamport,
            &key,
            &key_id,
            scope,
            &self.keys.signer,
        )?;
        self.push_own_batches3()?;
        Ok(rec.seq)
    }

    /// A full device of the registry that the organization does not trust
    /// (not in its roster, or on a platform its policy refuses). Removed
    /// devices are judged by their cut-off instead.
    pub(crate) fn org_untrusted3(&self, device: &Id16) -> bool {
        if self.org.is_none() || *device == self.me3() || self.f3.members.revoked.contains(device) {
            return false;
        }
        self.f3.members.devices.get(device).is_some()
            && !self.trusted(&DeviceId::from_bytes(device))
    }

    /// The share-ledger key id and key of `folder`'s newest epoch held.
    fn share_ledger_key(&self, folder: &Id16) -> Result<(String, SecretKey)> {
        let k =
            self.f3.members.granted.get(folder).ok_or_else(|| {
                anyhow!("this device holds no key of folder {}", hex::encode(folder))
            })?;
        let (e, _) = k
            .newest()
            .ok_or_else(|| anyhow!("no folder epoch is held here"))?;
        let key = k
            .share_ledger(e)
            .ok_or_else(|| anyhow!("no folder epoch is held here"))?;
        Ok((ledger3::scope::share_ledger_key_id(folder, e), key))
    }

    /// Folders shared with other people whose keys this device holds.
    fn shared_folders(&self) -> Vec<Id16> {
        let m = &self.f3.members;
        m.granted
            .folders
            .keys()
            .filter(|f| m.shared(f))
            .copied()
            .collect()
    }

    /// The folder whose folder-scoped batch an event goes into, or
    /// `NO_FOLDER` for the vault batch.
    fn batch_folder(&self, ev: &Event3, view: Option<&View3>) -> Id16 {
        if let Some(m) = &self.f3.members.member {
            return m.folder;
        }
        let f = match ev {
            Event3::PackVerified(p) | Event3::PackDropped(p) => {
                view.and_then(|v| v.pack_folder(&p.pack))
            }
            other => ledger3::scope::folder_written(other),
        };
        match f {
            Some(f) if self.f3.members.shared(&f) && self.f3.members.granted.get(&f).is_some() => f,
            _ => ledger3::NO_FOLDER,
        }
    }

    /// Folders this device announced its earlier work of in their
    /// folder-scoped batches (`state/shared3.json`).
    fn announced3(&self) -> BTreeSet<String> {
        util::read_json_or_default(&self.home.join("state").join(ANNOUNCED_FILE))
            .unwrap_or_default()
    }

    /// Add, for every shared folder not announced yet, this device's claims
    /// of the packs it wrote and its announcements of the folder's records
    /// to the folder's group. Returns the folders announced now.
    fn reannounce(
        &self,
        groups: &mut BTreeMap<Id16, Vec<Event3>>,
        view: Option<&View3>,
    ) -> Result<Vec<Id16>> {
        if self.vault.member {
            return Ok(Vec::new());
        }
        let Some(view) = view else {
            return Ok(Vec::new());
        };
        let done = self.announced3();
        let me = self.me3();
        let mut out = Vec::new();
        for f in self.shared_folders() {
            if done.contains(&hex::encode(f)) {
                continue;
            }
            let g = groups.entry(f).or_default();
            for (id, rec) in &view.packs {
                if view.pack_folder(id) != Some(f) || view.pack_writer(id) != Some(me) {
                    continue;
                }
                for c in view.copies(id) {
                    if c.claimed_by.contains(&me) {
                        g.push(Event3::PackStored(crate::ledger3::events::PackStored {
                            storage: c.storage.clone(),
                            pack: *id,
                            class: rec.class,
                            folder: f,
                            map_seq: rec.map_seq,
                        }));
                    }
                }
            }
            for kind in [
                crate::record::Kind::Manifest,
                crate::record::Kind::BlockMap,
                crate::record::Kind::Trash,
            ] {
                if let Some(s) = view.stream(kind.code(), &f, &me) {
                    for (seq, a) in &s.records {
                        g.push(Event3::RecordPublished(
                            crate::ledger3::events::Announcement {
                                kind: kind.code(),
                                scope: f,
                                seq: *seq,
                                base: a.base,
                                parts: a.parts,
                                body_hash: a.body_hash,
                                size: a.size,
                            },
                        ));
                    }
                }
            }
            out.push(f);
        }
        Ok(out)
    }

    /// Push every own batch a hot metadata storage does not have yet. A
    /// storage that holds another batch under one of this device's numbers
    /// (a copy of this identity restored from an old backup) stops it.
    pub(crate) fn push_own_batches3(&mut self) -> Result<()> {
        let me = self.me3();
        let head = self.f3.ledger.head(&me);
        // Transferrers carry the ledger too (F-048).
        for (spec, backend) in self.metadata_storages(false)? {
            // One storage that cannot be reached is left as it is: the
            // batches are sealed here and go there at a later push (`health`).
            let pushed = (|| -> Result<()> {
                let mut done = self.f3.ledger.pushed(spec.name()).min(head.seq);
                // A storage that lost the newest batch it was known to hold (or
                // a new storage under a known name) is filled from the start.
                if done > head.dropped
                    && !backend.exists(&ledger3::checkpoint::batch_key(&me, done))?
                {
                    done = 0;
                }
                for seq in done.max(head.dropped) + 1..=head.seq {
                    let Some(rec) = self.f3.ledger.get(&me, seq)? else {
                        continue;
                    };
                    let key = ledger3::checkpoint::batch_key(&me, seq);
                    let bytes = rec.encode();
                    if !backend.put_if_absent(&key, &bytes)? {
                        let same = backend
                            .get_bounded(&key, crate::record::MAX_PART_READ)?
                            .is_some_and(|b| b == bytes);
                        if !same {
                            let theirs = backend
                                .get_bounded(&key, crate::record::MAX_PART_READ)?
                                .and_then(|b| crate::record::SignedRecord::decode(&b).ok());
                            if theirs.is_some_and(|r| r.verify(&self.keys.signer.public()).is_ok())
                            {
                                self.forked_self = true;
                                bail!("ledger fork: storage {} already holds a different batch {} of this device (restored from an old copy?)", backend.name(), seq);
                            }
                            log::warn!(storage = backend.name(), seq = seq; "ledger: junk under this device's batch name");
                        }
                    }
                }
                Ok(())
            })();
            if self.tolerate(spec.name(), pushed)?.is_none() {
                continue;
            }
            self.f3.ledger.set_pushed(spec.name(), head.seq)?;
        }
        Ok(())
    }

    /// Pull the membership and every known device's new batches from every
    /// hot metadata storage. Returns the devices found forked.
    pub(crate) fn pull_ledger3(&mut self) -> Result<Vec<DeviceId>> {
        // With no storage reachable the peers still give their batches
        // (the head exchange below), on the membership known here.
        if let Err(e) = self.refresh_members() {
            if !is_network_error(&e) {
                return Err(e);
            }
            log::warn!("membership not read, no storage answered: {e:#}");
        }
        // Replicas the vault enrolled, and other devices' names for this
        // device's storages (`storages3_ops`).
        self.refresh_replicas();
        self.refresh_storage_aliases();
        // Folders' policies and placements (kinds 11 and 12).
        if let Err(e) = self.refresh_folder_rules() {
            log::warn!("policies and placements not read: {e:#}");
        }
        // Head exchange first (design section 8): what peers prove, and the
        // batches every storage withholds, fetched from the peers.
        let pull_utc = util::now_utc();
        if let Err(e) = self.p2p_catch_up() {
            log::debug!("head exchange with peers failed: {e:#}");
        }
        let me = self.me3();
        let mut keys: BTreeMap<Id16, crypto::VerifyingKey> = BTreeMap::new();
        for (d, (rec, _)) in &self.f3.members.devices.devices {
            if let Some(k) = rec.signing_key() {
                keys.insert(*d, k);
            }
        }
        for m in self.f3.members.members.members.values() {
            if let Some(k) = m.signing_key() {
                keys.entry(m.device).or_insert(k);
            }
        }
        for (d, (_, k)) in &self.f3.replicas {
            keys.entry(*d).or_insert_with(|| k.clone());
        }
        let mut forks = BTreeSet::new();
        let (mut malformed, mut refused) = (0u64, 0u64);
        let limit = self.clock.lamport.saturating_add(Self::CLOCK_LEAP);
        // What each storage's listing showed, for the rollback judge: the
        // storage's own newest batch, never the head held here (that may
        // have come from a peer or another storage). The listing starts at
        // the head held here, so a storage that has it lists it; one that
        // lists nothing from there is listed in full for its own newest.
        let mut views: Vec<crate::p2p::v3::heads::StorageView> = Vec::new();
        // Transferrers carry the ledger too (F-048), but are no
        // storage view for the rollback judge (they may lag).
        for (spec, backend) in self.metadata_storages(false)? {
            let mut shown: BTreeMap<Id16, u64> = BTreeMap::new();
            // A storage that cannot be reached is skipped (and told to the
            // rollback judge as such); what the others and the peers gave
            // is kept.
            let pulled = (|| -> Result<()> {
                for (dev, pk) in &keys {
                    let head = self.f3.ledger.head(dev);
                    if !self.keep3(dev, head.seq + 1) {
                        continue;
                    }
                    let prefix = format!("ledger/{}/", hex::encode(dev));
                    let after = if head.forked || head.seq <= 1 {
                        String::new()
                    } else {
                        ledger3::checkpoint::batch_key(dev, head.seq - 1)
                    };
                    let names = backend.list_after(&prefix, &after)?;
                    let newest = |names: &[String]| {
                        names
                            .iter()
                            .filter_map(|n| n.strip_prefix(&prefix))
                            .filter_map(ledger3::LedgerObject::parse)
                            .map(|o| match o {
                                ledger3::LedgerObject::Batch(s) => s,
                                ledger3::LedgerObject::Checkpoint(s, _) => s,
                            })
                            .max()
                            .unwrap_or(0)
                    };
                    let mut top = newest(&names);
                    if top < head.seq && !after.is_empty() {
                        top = newest(&backend.list(&prefix)?);
                    }
                    shown.insert(*dev, top);
                    // The newest checkpoint first: it stands in for batches a
                    // pruning device deleted (other devices' only; one of this
                    // device's own is its own).
                    let newest_cp = names
                        .iter()
                        .filter_map(|n| n.strip_prefix(&prefix))
                        .filter_map(ledger3::LedgerObject::parse)
                        .filter_map(|o| match o {
                            ledger3::LedgerObject::Checkpoint(s, 0) => Some(s),
                            _ => None,
                        })
                        .filter(|s| self.keep3(dev, *s))
                        .max();
                    if let (Some(s), false) = (newest_cp, *dev == me) {
                        self.pull_checkpoint(backend.as_ref(), dev, pk, s)?;
                    }
                    for name in names {
                        let Some(file) = name.strip_prefix(&prefix) else {
                            continue;
                        };
                        let Some(ledger3::LedgerObject::Batch(seq)) =
                            ledger3::LedgerObject::parse(file)
                        else {
                            continue;
                        };
                        let head = self.f3.ledger.head(dev);
                        if !self.keep3(dev, seq)
                            || self.f3.ledger.get(dev, seq)?.is_some()
                            || (head.base.as_ref().is_some_and(|b| seq <= b.seq) && !head.forked)
                        {
                            continue;
                        }
                        let Some(bytes) =
                            backend.get_bounded(&name, crate::record::MAX_PART_READ)?
                        else {
                            continue;
                        };
                        let Ok(rec) = crate::record::SignedRecord::decode(&bytes) else {
                            // One storage holding a damaged or planted object
                            // does not stop the pull: another may hold the batch.
                            log::warn!(storage = backend.name(); "ledger: {name} is not a record");
                            if *dev != me {
                                malformed += 1;
                            }
                            continue;
                        };
                        if *dev == me && seq > head.seq {
                            if rec.verify(pk).is_ok() {
                                // Another copy of this identity published ahead of us.
                                forks.insert(DeviceId::from_bytes(dev));
                                self.forked_self = true;
                            }
                            continue;
                        }
                        let key = self.key_for3(&rec.key_id);
                        match self
                            .f3
                            .ledger
                            .ingest_named(&name, rec, pk, key.as_ref(), limit)
                        {
                            Ok(Ingest::Fork) => {
                                forks.insert(DeviceId::from_bytes(dev));
                            }
                            Ok(Ingest::Refused) => {
                                refused += 1;
                                log::warn!(storage = backend.name(), seq = seq; "ledger batch refused");
                            }
                            Ok(_) => {}
                            Err(e) => {
                                malformed += 1;
                                log::warn!(storage = backend.name(), seq = seq, error:% = e; "ledger batch skipped");
                            }
                        }
                    }
                }
                Ok(())
            })();
            let reachable = self.tolerate(spec.name(), pulled)?.is_some();
            let id = if reachable {
                let id = super::verify::storage_identity(backend.as_ref()).ok();
                if let Some(id) = &id {
                    self.health.remember_id(spec.name(), id);
                }
                id
            } else {
                self.health.known_id(spec.name())
            };
            if let Some(storage) = id
                .and_then(|id| crate::record::kinds::parse_id16(&id))
                .filter(|_| !spec.is_carrier())
            {
                views.push(crate::p2p::v3::heads::StorageView {
                    storage,
                    name: spec.name().to_string(),
                    reachable,
                    shown,
                });
            }
        }
        let view = self.view3()?;
        self.observe_clock(view.max_lamport)?;
        // A storage that shows less than a writer confirmed and a peer
        // proved, two pulls in a row: the rollback warning.
        match self.p2p_judge_rollback(pull_utc, Some(views)) {
            Ok(w) => {
                let mut devices: Vec<String> = w
                    .iter()
                    .map(|w| self.device_name(&DeviceId::from_bytes(&w.device)))
                    .collect();
                devices.sort();
                devices.dedup();
                self.ledger_alarm.watch.rollback_devices = devices;
                self.ledger_alarm.watch.rollback = w.into_iter().map(|w| w.text).collect();
            }
            Err(e) => log::debug!("rollback check failed: {e:#}"),
        }
        self.watch_freshness(&view, malformed, refused);
        Ok(forks.into_iter().collect())
    }

    /// Take the newest checkpoint of another device listed in `objects`
    /// when it is newer than the one held here: it stands in for the
    /// batches it covers, which may be gone from the storages.
    fn pull_checkpoint(
        &mut self,
        backend: &dyn Storage,
        dev: &Id16,
        pk: &crypto::VerifyingKey,
        seq: u64,
    ) -> Result<()> {
        let head = self.f3.ledger.head(dev);
        if head.base.as_ref().is_some_and(|b| b.seq >= seq) {
            return Ok(());
        }
        let name0 = ledger3::checkpoint::checkpoint_key(dev, seq, 0);
        let Some(b0) = backend.get_bounded(&name0, crate::record::MAX_PART_READ)? else {
            return Ok(());
        };
        let Ok(first) = crate::record::SignedRecord::decode(&b0) else {
            return Ok(());
        };
        let mut read = vec![(name0, b0)];
        for part in 1..first.parts.min(crate::record::MAX_PARTS) {
            let name = ledger3::checkpoint::checkpoint_key(dev, seq, part);
            match backend.get_bounded(&name, crate::record::MAX_PART_READ)? {
                Some(b) => read.push((name, b)),
                None => return Ok(()),
            }
        }
        if self.scope3(dev, &first.key_id) != Some(EventScope::Full) {
            return Ok(());
        }
        let Some(key) = self.key_for3(&first.key_id) else {
            return Ok(());
        };
        let vault = members3::bin(&self.vault.vault_id)?;
        let Ok((envs, cp)) = ledger3::Checkpoint::accept(&read, &vault, pk, &key) else {
            log::warn!(storage = backend.name(), seq = seq; "ledger checkpoint refused");
            return Ok(());
        };
        let floor = head.seq.max(head.base.as_ref().map_or(0, |b| b.seq));
        let anchor = if seq > floor.saturating_add(ledger3::MAX_AHEAD) {
            backend
                .get_bounded(
                    &ledger3::checkpoint::batch_key(dev, seq),
                    crate::record::MAX_PART_READ,
                )?
                .and_then(|b| crate::record::SignedRecord::decode(&b).ok())
                .filter(|b| b.verify(pk).is_ok())
        } else {
            None
        };
        self.f3
            .ledger
            .ingest_checkpoint(&envs, &cp, anchor.as_ref())?;
        Ok(())
    }

    /// The full devices whose acknowledgements let a checkpoint's batches
    /// go: every device of the registry that is not removed.
    fn ledger_readers(&self) -> Vec<Id16> {
        self.f3
            .members
            .devices
            .devices
            .keys()
            .filter(|d| !self.f3.members.revoked.contains(*d))
            .copied()
            .collect()
    }

    /// Keep the ledger small after a sync (design section 4, "Checkpoints",
    /// "Acknowledgements", "Pruning"): acknowledge the other devices'
    /// checkpoints, write a checkpoint of this device's own batches when
    /// enough have accumulated, and once every reader acknowledged a
    /// checkpoint delete the batches it covers (on the hot storages for
    /// this device's own, locally for everyone's). Cold storages are left
    /// as they are.
    /// Acknowledge, in an empty batch of this device's own, what waits for
    /// it: other devices' checkpoints and other writers' dead marks (they
    /// settle only once every current writer did). Run by the ledger
    /// upkeep after a sync and by the trash upkeep before it collects, so
    /// that a device whose last action was a trash upkeep (its own marks
    /// in a new batch) does not leave the other writers' marks waiting.
    /// Returns whether a batch was signed.
    pub(crate) fn sign_due_acks3(&mut self) -> Result<bool> {
        if self.vault.member
            || self.forked_self
            || self.removal.is_some()
            || self.ledger_alarm.needs_rebuild()
            || self.cycle.is_some()
        {
            return Ok(false);
        }
        let me = self.me3();
        let view = self.view3()?;
        let ack_due = self.f3.ledger.devices().iter().any(|d| {
            *d != me
                && self
                    .f3
                    .ledger
                    .head(d)
                    .base
                    .is_some_and(|b| view.acked(&me, d, None) < b.seq)
        }) || self.acks_due3(&view);
        if !ack_due {
            return Ok(false);
        }
        let (key_id, key) = self.ledger_key3()?;
        let lamport = self.tick()?;
        let seen = self.f3.ledger.vault_seen(&me);
        self.f3.ledger.append_own(
            &me,
            Vec::new(),
            seen,
            lamport,
            &key,
            &key_id,
            ledger3::NO_FOLDER,
            &self.keys.signer,
        )?;
        self.push_own_batches3()?;
        Ok(true)
    }

    pub(crate) fn ledger_upkeep3(&mut self) -> Result<()> {
        if self.vault.member
            || self.forked_self
            || self.removal.is_some()
            || self.ledger_alarm.needs_rebuild()
        {
            return Ok(());
        }
        let me = self.me3();
        // 1. Acknowledge other devices' checkpoints, and other writers'
        // dead marks (they settle only once every writer did), in a batch
        // of our own.
        self.sign_due_acks3()?;
        // 2. A checkpoint of our own batches.
        let head = self.f3.ledger.head(&me);
        let base = head.base.as_ref().map_or(0, |b| b.seq);
        if head.seq >= base + self.ledger_policy.checkpoint_every.max(1) {
            let (key_id, key) = self.ledger_key3()?;
            let own = self
                .f3
                .ledger
                .contribution(&me, head.seq, |id| self.key_for3(id))?;
            let parts = self.f3.ledger.seal_checkpoint(
                &me,
                head.seq,
                own,
                &key,
                &key_id,
                &self.keys.signer,
            )?;
            for (_, backend) in self.metadata_storages(false)? {
                for p in &parts {
                    backend.put_if_absent(
                        &ledger3::checkpoint::checkpoint_key(&me, p.seq, p.part),
                        &p.encode(),
                    )?;
                }
            }
        }
        // 3. What checkpoints cover goes once every reader has seen past it.
        let view = self.view3()?;
        let readers = self.ledger_readers();
        let keep = self.ledger_policy.keep_before;
        // A device that writes for a folder shared with other people keeps
        // its batches on the storages: members read the folder-scoped ones
        // (they cannot read the checkpoints that would stand in for them).
        let keep_all = !self.shared_folders().is_empty();
        if let Some(b) = self.f3.ledger.head(&me).base.filter(|_| !keep_all) {
            if view.vault_acked_by_all(readers.iter(), &me, b.seq) {
                let upto = b.seq.saturating_sub(keep);
                let prefix = format!("ledger/{}/", hex::encode(me));
                for (spec, backend) in self.metadata_storages(false)? {
                    if self.f3.ledger.pruned(spec.name()) >= upto
                        || !backend.exists(&ledger3::checkpoint::checkpoint_key(&me, b.seq, 0))?
                    {
                        continue;
                    }
                    for seq in self.f3.ledger.pruned(spec.name()) + 1..=upto {
                        backend.delete(&ledger3::checkpoint::batch_key(&me, seq))?;
                    }
                    for name in backend.list(&prefix)? {
                        if let Some(ledger3::LedgerObject::Checkpoint(s, _)) = name
                            .strip_prefix(&prefix)
                            .and_then(ledger3::LedgerObject::parse)
                        {
                            if s < b.seq {
                                backend.delete(&name)?;
                            }
                        }
                    }
                    self.f3.ledger.set_pruned(spec.name(), upto)?;
                }
                self.f3.ledger.drop_through(&me, upto)?;
            }
        }
        for d in self.f3.ledger.devices() {
            if d == me {
                continue;
            }
            if let Some(b) = self.f3.ledger.head(&d).base {
                if self.keep3(&d, b.seq) && view.vault_acked_by_all(readers.iter(), &d, b.seq) {
                    self.f3.ledger.drop_through(&d, b.seq)?;
                }
            }
        }
        Ok(())
    }
}
