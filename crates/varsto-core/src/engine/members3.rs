// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The membership of a format-3 vault as the engine keeps it
//! (`docs/spec/format-3-design.md` sections 5, 6 and 9): device records,
//! folder records, the folder keys granted to this device, member devices
//! of shared folders and revocations, read with `membership3::Membership`
//! and kept between operations ([`Members3`]), so that every record the
//! engine accepts is judged by the same trust ([`EngineTrust`]) and opened
//! with the same keys (`membership3::KeyRing`).
//!
//! What this device holds of a folder comes only from grants to it (and,
//! after `join --recovery-words`, from escrow): the local keyring keeps a
//! copy of those keys (`FolderRecord::key_hex`, `epoch_keys`, `k11_hex`),
//! never a key derived from the vault key.

use super::*;
use crate::membership3::{
    DeviceRegistry, FolderRegistry, GrantedKeys, KeyRing, MemberRegistry, Membership,
    RevocationRecord, Role, Trust, VaultKeys,
};
use crate::record::{Announced, Id16, KeyId, Kind, RecordTrust, RecordsRefused};

/// The folder setting that marks a backup: the JSON of its `BackupInfo`.
pub(super) const BACKUP_SETTING: &str = "backup";

/// What the engine knows of the vault's membership (a copy of what
/// `Membership` read last).
#[derive(Clone, Default)]
pub(crate) struct Members3 {
    pub devices: DeviceRegistry,
    pub registry: FolderRegistry,
    pub granted: GrantedKeys,
    pub members: MemberRegistry,
    pub revoked: BTreeSet<Id16>,
    pub revocations: BTreeMap<Id16, RevocationRecord>,
    pub refused: RecordsRefused,
    /// A revocation of this device (`Membership::own_revocation`).
    pub own_revocation: Option<RevocationRecord>,
    /// Vault epoch numbers two devices wrote.
    pub vault_forks: BTreeMap<u32, BTreeSet<Id16>>,
    /// Devices whose ledger batches count only up to a cut-off: removed
    /// from the vault (revocations), or member devices of other vaults
    /// removed from a folder (folder epoch records).
    pub cutoffs: BTreeMap<Id16, u64>,
    /// On a member device of another vault: what its grants say.
    pub member: Option<MemberInfo>,
    /// The newest key wraps of every Strongroom folder.
    pub strongrooms: BTreeMap<Id16, crate::membership3::strongrooms::StrongroomRecord>,
}

/// A member device's own standing in its shared folder.
#[derive(Clone, Debug, Default)]
pub(crate) struct MemberInfo {
    pub folder: Id16,
    pub access_lost: bool,
}

impl Members3 {
    fn of(m: &Membership<'_>) -> Members3 {
        let mut cutoffs: BTreeMap<Id16, u64> = BTreeMap::new();
        for (f, ep) in &m.registry.epochs {
            for r in ep.applied.values() {
                for x in &r.removed {
                    // Own devices removed from one folder still write for
                    // the others: only another person's device is cut off.
                    if m.devices.get(&x.device).is_none()
                        && m.members.folders_of(&x.device).iter().all(|g| g == f)
                    {
                        cutoffs.insert(x.device, x.cutoff);
                    }
                }
            }
        }
        for (d, r) in &m.revocations {
            cutoffs.insert(*d, r.cutoff_seq);
        }
        Members3 {
            devices: m.devices.clone(),
            registry: m.registry.clone(),
            granted: m.granted.clone(),
            members: m.members.clone(),
            revoked: m.revoked_set().clone(),
            revocations: m.revocations.clone(),
            refused: m.refused.clone(),
            own_revocation: m.own_revocation.clone(),
            vault_forks: m.vault_forks.clone(),
            cutoffs,
            member: None,
            strongrooms: m.strongrooms.clone(),
        }
    }

    /// What a member device knows, as the same registries.
    fn of_member(v: crate::membership3::MemberView) -> Members3 {
        Members3 {
            member: Some(MemberInfo {
                folder: v.folder,
                access_lost: v.access_lost,
            }),
            devices: v.devices,
            registry: v.registry,
            granted: v.granted,
            members: v.members,
            revoked: BTreeSet::new(),
            revocations: BTreeMap::new(),
            refused: v.refused,
            own_revocation: None,
            vault_forks: BTreeMap::new(),
            cutoffs: v.cutoffs,
            strongrooms: BTreeMap::new(),
        }
    }

    /// Whether `folder` is shared with other people's devices (once it is,
    /// it stays so: the owners' folder events go into folder-scoped
    /// batches the members can read).
    pub fn shared(&self, folder: &Id16) -> bool {
        self.registry
            .get(folder)
            .is_some_and(|st| !st.members.is_empty())
    }

    /// The trust of section 9 over these registries.
    pub fn trust(&self) -> Trust<'_> {
        Trust {
            devices: &self.devices,
            revoked: &self.revoked,
            folders: Some(&self.registry),
            members: Some(&self.members),
        }
    }

    /// The role of `device` in `folder` at the folder's current epoch.
    pub fn role(&self, device: &Id16, folder: &Id16) -> Option<Role> {
        let epoch = self
            .registry
            .epochs
            .get(folder)
            .map(|e| e.current())
            .unwrap_or(0);
        self.registry.role(device, folder, epoch)
    }
}

/// `record::RecordTrust` of the engine: section 9 over the membership, and
/// the announcements of the ledger view (step 5 of the acceptance rule).
pub(crate) struct EngineTrust<'a> {
    pub inner: Trust<'a>,
    pub view: &'a crate::ledger3::LedgerView,
}

impl RecordTrust for EngineTrust<'_> {
    fn signer_key(
        &self,
        device: &Id16,
        kind: Kind,
        scope: &Id16,
    ) -> Option<crate::crypto::VerifyingKey> {
        self.inner.signer_key(device, kind, scope)
    }
    fn may_write(&self, device: &Id16, kind: Kind, scope: &Id16, key_id: &KeyId) -> bool {
        self.inner.may_write(device, kind, scope, key_id)
    }
    fn announcement(&self, device: &Id16, kind: Kind, scope: &Id16, seq: u64) -> Option<Announced> {
        crate::manifest3::announcement(self.view, device, kind, scope, seq)
    }
    fn seq_allowed(
        &self,
        device: &Id16,
        kind: Kind,
        scope: &Id16,
        seq: u64,
        epoch: Option<u32>,
        recipient: Option<Id16>,
    ) -> bool {
        self.inner
            .seq_allowed(device, kind, scope, seq, epoch, recipient)
    }
}

/// A storage whose reads of membership records (`vault/`) are kept in a
/// local mirror as well. A read that fails because the storage cannot be
/// reached answers "nothing there" and is remembered (`down`): the
/// membership is read from the storages that answer, and only when none
/// does is the read an error (`all_down`).
struct Tee<'a> {
    inner: &'a dyn Storage,
    mirror: &'a crate::storage::LocalDirStorage,
    failed: std::sync::Mutex<Option<anyhow::Error>>,
}

impl<'a> Tee<'a> {
    fn new(inner: &'a dyn Storage, mirror: &'a crate::storage::LocalDirStorage) -> Tee<'a> {
        Tee {
            inner,
            mirror,
            failed: std::sync::Mutex::new(None),
        }
    }

    /// `r`, or `none` when the storage could not be reached.
    fn read<T>(&self, r: Result<T>, none: T) -> Result<T> {
        match r {
            Err(e) if is_network_error(&e) => {
                log::warn!(storage = self.inner.name(); "membership not read from this storage: {e:#}");
                let mut f = self.failed.lock().unwrap_or_else(|e| e.into_inner());
                f.get_or_insert(e);
                Ok(none)
            }
            other => other,
        }
    }

    fn down(&self) -> bool {
        self.failed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    fn take_error(&self) -> Option<anyhow::Error> {
        self.failed.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

/// The error of the first storage when no storage of `teed` could be
/// reached (nothing was read: the membership known here stays).
fn all_down(teed: &[Tee<'_>]) -> Option<anyhow::Error> {
    if teed.is_empty() || !teed.iter().all(|t| t.down()) {
        return None;
    }
    teed.iter().find_map(|t| t.take_error())
}

impl Tee<'_> {
    fn keep(&self, key: &str, got: &Option<Vec<u8>>) {
        if let Some(b) = got {
            if key.starts_with("vault/") && key.ends_with(".rec") {
                if let Err(e) = self.mirror.put_if_absent(key, b) {
                    log::debug!("membership record {key} not kept locally: {e:#}");
                }
            }
        }
    }
}

impl Storage for Tee<'_> {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn put_if_absent(&self, key: &str, data: &[u8]) -> Result<bool> {
        self.inner.put_if_absent(key, data)
    }
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let got = self.read(self.inner.get(key), None)?;
        self.keep(key, &got);
        Ok(got)
    }
    fn get_bounded(&self, key: &str, max: u64) -> Result<Option<Vec<u8>>> {
        let got = self.read(self.inner.get_bounded(key, max), None)?;
        self.keep(key, &got);
        Ok(got)
    }
    fn exists(&self, key: &str) -> Result<bool> {
        self.inner.exists(key)
    }
    fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.read(self.inner.list(prefix), Vec::new())
    }
    fn list_after(&self, prefix: &str, start_after: &str) -> Result<Vec<String>> {
        self.read(self.inner.list_after(prefix, start_after), Vec::new())
    }
    fn delete(&self, key: &str) -> Result<()> {
        self.inner.delete(key)
    }
}

/// `member3.json` of a member device.
pub(super) const MEMBER_FILE: &str = "member3.json";

/// The outbox of membership records, under `state/`.
const OUTBOX_DIR: &str = "outbox3";

/// How a membership operation reaches the records (`with_members3_at`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reach {
    /// The storages and this device's copy; an error when a storage cannot
    /// be read. Vault and folder epochs need this: a storage decides their
    /// number.
    Storages,
    /// As `Storages`; when they cannot be read, this device's copy alone,
    /// and every record written waits in the outbox.
    StoragesOrLocal,
    /// This device's copy alone, no network (falls back to
    /// `StoragesOrLocal` while the copy knows no device).
    Local,
}

#[derive(Serialize, Deserialize)]
struct MemberState3 {
    folder: String,
    anchor: String,
}

/// The binary form of an id (16 bytes) of this vault.
pub(crate) fn bin(id: &crate::ids::Id) -> Result<Id16> {
    crate::record::id16(id).ok_or_else(|| anyhow!("id {id} is not 16 bytes of hex"))
}

impl Engine {
    /// This device's id on the wire.
    pub(crate) fn me3(&self) -> Id16 {
        bin(&self.vault.device_id).expect("a device id is 16 bytes")
    }

    /// Administrators of the current organization manifest, if this vault
    /// has one. Epochs and revocations from anyone else are not adopted.
    fn org_admins3(&self) -> Option<BTreeSet<Id16>> {
        let manifest = self.org.as_ref()?.manifest()?;
        let mut out = BTreeSet::new();
        for a in &manifest.admins {
            if let Ok(id) = bin(&a.device) {
                out.insert(id);
            }
        }
        Some(out)
    }

    /// The vault keys this device holds, by epoch.
    pub(crate) fn vault_keys3(&self) -> VaultKeys {
        VaultKeys {
            keys: self.epochs.keys.clone(),
        }
    }

    /// The keys that open and seal records here: registry, ledger and
    /// epoch keys of every vault epoch held, the folder keys granted to
    /// this device, its K8.
    pub(crate) fn keys3<'a>(&'a self, vault_keys: &'a VaultKeys) -> KeyRing<'a> {
        let m = &self.f3.members;
        // A Strongroom's key is held only while it is unlocked here.
        let now = util::now_utc();
        let mut extra = Vec::new();
        for (fid, (k13, until)) in &self.unlocked {
            let Ok(f) = bin(fid) else { continue };
            if *until <= now {
                continue;
            }
            let keys = crate::membership3::FolderKeys {
                folder: f,
                epochs: BTreeMap::from([(0, k13.clone())]),
                k11: crate::membership3::grants::k11_of(&f, k13),
            };
            if let Some(k) = keys.k10(0) {
                extra.push((
                    KeyId::Meta {
                        folder: f,
                        epoch: 0,
                    },
                    k,
                ));
            }
            if let Some(k) = keys.share_ledger(0) {
                extra.push((
                    KeyId::ShareLedger {
                        folder: f,
                        epoch: 0,
                    },
                    k,
                ));
            }
        }
        KeyRing {
            me: self.me3(),
            vault: vault_keys,
            kem: self.epochs.kem.as_ref(),
            devices: Some(&m.devices),
            folders: Some(&m.granted),
            recovery: None,
            extra,
            members: Some(&m.members),
        }
    }

    /// The hot metadata storages membership records are read from and
    /// written to.
    /// Whether some storages that carry the membership records are not
    /// among the `opened` ones (down or resting in this run, `health`):
    /// what is written now must still reach them later (the outbox).
    fn member_storages_left_out(&self, opened: usize) -> bool {
        let drained = self.drained_storages();
        let all = self
            .config
            .storages
            .iter()
            .filter(|s| !s.is_cold() && !s.is_data_only() && !drained.contains(s.name()))
            .count();
        opened < all
    }

    fn member_storages(&self) -> Result<OpenStorages> {
        // Transferrers carry the records too (F-048).
        self.metadata_storages(false)
    }

    /// Run `f` over a `Membership` of this device opened on the hot
    /// metadata storages (it reads every membership record first); the
    /// engine keeps what it read afterwards. Stamps follow the engine's
    /// clock, so roles given now hold for the batches this device seals
    /// next. `None` without a storage.
    pub(crate) fn with_members3<R>(
        &mut self,
        f: impl FnOnce(&mut Membership<'_>) -> Result<R>,
    ) -> Result<Option<R>> {
        self.with_members3_as(true, f)
    }

    /// `with_members3`; without `guard` (tests: a modified client) a
    /// revocation of this device and an unresolved vault epoch stop
    /// nothing.
    pub(crate) fn with_members3_as<R>(
        &mut self,
        guard: bool,
        f: impl FnOnce(&mut Membership<'_>) -> Result<R>,
    ) -> Result<Option<R>> {
        self.with_members3_reach(Reach::Storages, guard, f)
    }

    /// `with_members3` read as `reach` says.
    pub(crate) fn with_members3_at<R>(
        &mut self,
        reach: Reach,
        f: impl FnOnce(&mut Membership<'_>) -> Result<R>,
    ) -> Result<Option<R>> {
        self.with_members3_reach(reach, true, f)
    }

    /// Run `f` over a `Membership` read as `reach` says. Records it writes
    /// are kept in this device's copy first and reach the storages that
    /// answer; what a storage lacks waits in the outbox (`state/outbox3/`)
    /// for `flush_records3`, which every refresh of the membership runs.
    /// Epochs this device started and did not finish are finished first
    /// when the storages were read (`Membership::resume_pending`).
    fn with_members3_reach<R>(
        &mut self,
        reach: Reach,
        guard: bool,
        f: impl FnOnce(&mut Membership<'_>) -> Result<R>,
    ) -> Result<Option<R>> {
        let open = self.member_storages()?;
        // Storages down or resting in this run are not opened; with every
        // one of them away the membership is still read (from this
        // device's copy, as `reach` allows). `None` only without a storage.
        let left_out = self.member_storages_left_out(open.len());
        if open.is_empty() && !left_out {
            return Ok(None);
        }
        let vault = bin(&self.vault.vault_id)?;
        // Every membership record read is kept in a local mirror, so that
        // a later process knows the membership without reading a storage.
        let mirror = self.records_mirror()?;
        let outbox = self.records_outbox()?;
        // A copy that knows no device yet cannot stand in for the storages.
        let reach = match reach {
            Reach::Local
                if mirror
                    .list("vault/devices/")
                    .map(|l| l.is_empty())
                    .unwrap_or(true) =>
            {
                Reach::StoragesOrLocal
            }
            r => r,
        };
        let teed: Vec<Tee> = open.iter().map(|(_, b)| Tee::new(&**b, &mirror)).collect();
        let refs: Vec<&dyn Storage> = teed.iter().map(|t| t as &dyn Storage).collect();
        // Reads: the storages and this device's copy (records it wrote
        // that a storage does not hold yet count at once).
        let mut with_local = refs.clone();
        with_local.push(&mirror);
        let only_local: Vec<&dyn Storage> = vec![&mirror];
        let no_storage: Vec<&dyn Storage> = Vec::new();
        let local = crate::membership3::Local {
            mirror: &mirror,
            outbox: &outbox,
            partial: left_out,
        };
        let lamport = self.clock.lamport;
        let kept = self.vault_kept3();
        // Spec 27: revocations are judged against the administrator list.
        // Read the organization first when a storage is in reach, then
        // again after a new vault key (below, in `refresh_members`).
        if reach != Reach::Local && !self.vault.member && self.removal.is_none() {
            if let Err(e) = self.sync_org() {
                log::warn!("organization not read before the membership: {e:#}");
            }
        }
        let admins = self.org_admins3();
        let recovered = self.keyring_keys()?;
        let held = self.org_held();
        let pending = membership::load_pending_keys(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )
        .unwrap_or_else(|e| {
            log::warn!("the keys of unfinished epochs could not be read: {e:#}");
            Vec::new()
        });
        let (home, keys_ref) = (&self.home, &self.keys);
        let (vault_id, device_id) = (&self.vault.vault_id, &self.vault.device_id);
        let keep_key = |k: &crate::membership3::PendingKey, keep: bool| -> Result<()> {
            membership::update_pending_keys(home, keys_ref, vault_id, device_id, k, keep)
        };
        let (out, snapshot, keys, stamped) = {
            let Some(kem) = self.epochs.kem.as_ref() else {
                bail!("this device has no KEM key (K8); it cannot take part in format-3 folders");
            };
            let mut offline = reach == Reach::Local;
            let mut m = if offline {
                Membership::open_with_admins(
                    vault,
                    &only_local,
                    &self.keys.signer,
                    kem,
                    self.vault_keys3(),
                    kept,
                    admins.clone(),
                )?
            } else {
                match Membership::open_with_admins(
                    vault,
                    &with_local,
                    &self.keys.signer,
                    kem,
                    self.vault_keys3(),
                    kept.clone(),
                    admins.clone(),
                ) {
                    // A storage that does not answer reads as empty (the
                    // tee); when none answered, nothing came from the
                    // storages.
                    Ok(m) => match all_down(&teed).or_else(|| {
                        teed.is_empty()
                            .then(|| anyhow!("every storage is down or resting in this run"))
                    }) {
                        None => m,
                        Some(e) if reach == Reach::StoragesOrLocal => {
                            log::warn!(
                                "no storage could be reached ({e:#}); working from this device's copy of the membership, changes wait to upload"
                            );
                            offline = true;
                            m
                        }
                        // An empty membership must not replace the one
                        // known here, and epochs need a storage.
                        Some(e) => {
                            return Err(
                                e.context("no storage could be reached to read the membership")
                            )
                        }
                    },
                    Err(e) if reach == Reach::StoragesOrLocal => {
                        log::warn!(
                            "the storages could not be read ({e:#}); working from this device's copy of the membership, changes wait to upload"
                        );
                        offline = true;
                        Membership::open_with_admins(
                            vault,
                            &only_local,
                            &self.keys.signer,
                            kem,
                            self.vault_keys3(),
                            kept,
                            admins.clone(),
                        )?
                    }
                    Err(e) => return Err(e),
                }
            };
            // Without the storages nothing is tried on them: the records
            // wait in the outbox for the next flush.
            m.write_through(if offline { &no_storage } else { &refs }, local);
            m.keep_keys_with(&keep_key);
            m.observe_lamport(lamport);
            m.hold_grants = held;
            for k in recovered {
                if m.granted.get(&k.folder).is_none() {
                    m.add_recovered(k);
                }
            }
            let ready = m.own_revocation.is_none() && m.unresolved_vault_forks().is_empty();
            if !offline && ready && !pending.is_empty() {
                match m.resume_pending(&pending) {
                    Ok(done) => {
                        for d in &done {
                            if let Err(e) = keep_key(d, false) {
                                log::warn!("a finished epoch stays listed as pending: {e:#}");
                            }
                        }
                    }
                    Err(e) => log::warn!("an unfinished key epoch was not completed yet: {e:#}"),
                }
            }
            // A removed device, or one that waits for the user's choice
            // between two vault epochs, writes nothing.
            let out = if !guard {
                f(&mut m)
            } else if m.own_revocation.is_some() {
                Err(anyhow!("this device was removed from the vault"))
            } else if let Some(e) = m.unresolved_vault_forks().first() {
                Err(anyhow!(
                    "two devices wrote key epoch {e} at once; keep one first (`varsto device resolve-epoch {e} --keep <device>`)"
                ))
            } else {
                f(&mut m)
            };
            (out, Members3::of(&m), m.vault_keys.clone(), m.lamport())
        };
        let own = snapshot.own_revocation.clone();
        let forks = snapshot.vault_forks.clone();
        self.adopt_members(snapshot, keys)?;
        self.observe_clock(stamped)?;
        if guard {
            self.after_members(own, forks)?;
        }
        out.map(Some)
    }

    /// The local mirror of the membership records (`state/records3/`).
    fn records_mirror(&self) -> Result<crate::storage::LocalDirStorage> {
        crate::storage::LocalDirStorage::new(
            "records3".into(),
            self.home.join("state").join("records3"),
        )
    }

    /// The outbox of membership records (`state/outbox3/`): records this
    /// device wrote that a storage does not hold yet.
    fn records_outbox(&self) -> Result<crate::storage::LocalDirStorage> {
        crate::storage::LocalDirStorage::new(
            "this device".into(),
            self.home.join("state").join(OUTBOX_DIR),
        )
    }

    /// Put the membership records that wait in the outbox on every hot
    /// metadata storage (put-if-absent). A storage that does not answer
    /// keeps its records waiting; that is never an error here.
    pub fn flush_records3(&self) -> Result<crate::membership3::Flushed> {
        if !self.home.join("state").join(OUTBOX_DIR).is_dir() {
            return Ok(Default::default());
        }
        let outbox = self.records_outbox()?;
        let open = self.member_storages()?;
        let refs: Vec<&dyn Storage> = open.iter().map(|(_, b)| &**b).collect();
        let partial = self.member_storages_left_out(open.len());
        let done = crate::membership3::flush_outbox_to(&outbox, &refs, partial)?;
        if done.sent > 0 {
            log::info!("{} membership changes uploaded", done.sent);
        }
        if done.conflicts > 0 {
            log::warn!(
                "{} membership changes could not be uploaded: a storage holds other records under their names",
                done.conflicts
            );
        }
        Ok(done)
    }

    /// How many membership changes of this device wait for a storage
    /// (`varsto status`: "N changes waiting to upload").
    pub fn records_waiting3(&self) -> usize {
        if !self.home.join("state").join(OUTBOX_DIR).is_dir() {
            return 0;
        }
        self.records_outbox()
            .and_then(|o| crate::membership3::outbox_waiting(&o))
            .unwrap_or(0)
    }

    /// Copy every membership record of the local mirror to `to` (a storage
    /// just added), put-if-absent.
    pub(crate) fn copy_records(&self, to: &dyn Storage) -> Result<()> {
        let dir = self.home.join("state").join("records3");
        if !dir.is_dir() {
            return Ok(());
        }
        let mirror = self.records_mirror()?;
        for key in mirror.list("vault/")? {
            if let Some(b) = mirror.get(&key)? {
                to.put_if_absent(&key, &b)?;
            }
        }
        Ok(())
    }

    /// The membership as the local mirror of its records gives it (an
    /// engine just opened knows its devices and folders without a storage).
    pub(crate) fn load_members3_local(&mut self) -> Result<()> {
        let dir = self.home.join("state").join("records3");
        if !dir.is_dir() {
            return Ok(());
        }
        if self.vault.member {
            let mirror = self.records_mirror()?;
            return self.read_member3(&[&mirror]);
        }
        let vault = bin(&self.vault.vault_id)?;
        let mirror = self.records_mirror()?;
        let refs: Vec<&dyn Storage> = vec![&mirror];
        let (snapshot, keys) = {
            let Some(kem) = self.epochs.kem.as_ref() else {
                return Ok(());
            };
            let m = Membership::open_with_admins(
                vault,
                &refs,
                &self.keys.signer,
                kem,
                self.vault_keys3(),
                self.vault_kept3(),
                self.org_admins3(),
            )?;
            (Members3::of(&m), m.vault_keys.clone())
        };
        self.adopt_members(snapshot, keys)
    }

    /// Read every membership record again (and publish this device's own
    /// device record when the registry lacks it).
    pub(crate) fn refresh_members(&mut self) -> Result<()> {
        if self.vault.member {
            let open = self.member_storages()?;
            if open.is_empty() {
                return Ok(());
            }
            let mirror = self.records_mirror()?;
            let teed: Vec<Tee> = open.iter().map(|(_, b)| Tee::new(&**b, &mirror)).collect();
            let refs: Vec<&dyn Storage> = teed.iter().map(|t| t as &dyn Storage).collect();
            return self.read_member3_checked(&refs, || all_down(&teed));
        }
        // What this device wrote while a storage was away goes out first.
        match self.flush_records3() {
            Ok(f) if f.waiting > 0 => {
                log::info!("{} membership changes still wait for a storage", f.waiting)
            }
            Ok(_) => {}
            Err(e) => log::warn!("membership changes not uploaded: {e:#}"),
        }
        self.with_enrolled(|m| {
            // Requests and recovery copies are read here once, so that the
            // pages and `status` answer from this device's copy.
            if let Err(e) = m.read_all_requests() {
                log::debug!("folder requests not read: {e:#}");
            }
            if let Err(e) = m.missing_escrows() {
                log::debug!("recovery copies not read: {e:#}");
            }
            Ok(())
        })?;
        // The organization's manifest, roster and log (`org_ops`), judged
        // with the devices just read; a device its policy allows again gets
        // the vault key it was held back from.
        self.sync_org()?;
        if self.org.is_some() && self.removal.is_none() {
            let held = self.org_held();
            self.with_members3(|m| {
                m.hold_grants = held;
                m.grant_missing_vault_keys()
            })?;
        }
        Ok(())
    }

    /// Devices of the registry that an organization's policy locks out:
    /// they get no new vault key until it allows them again.
    pub(crate) fn org_held(&self) -> BTreeSet<Id16> {
        self.f3
            .members
            .devices
            .devices
            .keys()
            .filter(|d| self.org_refuses_device(&DeviceId::from_bytes(*d)).is_some())
            .copied()
            .collect()
    }

    /// The shared folder of a member device (`member3.json`: the folder
    /// and the owner device its trust starts from).
    pub(crate) fn member_state(&self) -> Option<(Id16, Id16)> {
        let st: MemberState3 = util::read_json(&self.home.join(MEMBER_FILE)).ok()?;
        let f = hex::decode(&st.folder).ok()?.try_into().ok()?;
        let a = hex::decode(&st.anchor).ok()?.try_into().ok()?;
        Some((f, a))
    }

    pub(crate) fn save_member_state(&self, folder: &Id16, anchor: &Id16) -> Result<()> {
        util::write_json(
            &self.home.join(MEMBER_FILE),
            &MemberState3 {
                folder: hex::encode(folder),
                anchor: hex::encode(anchor),
            },
        )
    }

    /// A member device: read its grants and the folder epochs, and keep
    /// what they give as the engine's membership.
    fn read_member3(&mut self, storages: &[&dyn Storage]) -> Result<()> {
        self.read_member3_checked(storages, || None)
    }

    /// `read_member3`, adopting nothing when `none_read` says no storage
    /// could be reached.
    fn read_member3_checked(
        &mut self,
        storages: &[&dyn Storage],
        none_read: impl Fn() -> Option<anyhow::Error>,
    ) -> Result<()> {
        let Some((folder, anchor)) = self.member_state() else {
            return Ok(());
        };
        let vault = bin(&self.vault.vault_id)?;
        let view = {
            let Some(kem) = self.epochs.kem.as_ref() else {
                bail!("this member device has no KEM key (K8)");
            };
            crate::membership3::MemberView::read(storages, vault, self.me3(), kem, folder, anchor)?
        };
        if let Some(e) = none_read() {
            return Err(e.context("no storage could be reached to read the membership"));
        }
        self.adopt_members(Members3::of_member(view), VaultKeys::default())
    }

    /// `with_members3` after publishing this device's device record when
    /// the registry lacks it.
    pub(crate) fn with_enrolled<R>(
        &mut self,
        f: impl FnOnce(&mut Membership<'_>) -> Result<R>,
    ) -> Result<Option<R>> {
        self.with_enrolled_at(Reach::Storages, f)
    }

    /// `with_enrolled` read as `reach` says.
    pub(crate) fn with_enrolled_at<R>(
        &mut self,
        reach: Reach,
        f: impl FnOnce(&mut Membership<'_>) -> Result<R>,
    ) -> Result<Option<R>> {
        let name = self.vault.device_name.clone();
        self.with_members3_at(reach, |m| {
            if m.devices.get(&m.me).is_none() {
                m.enrol(&name)?;
            }
            f(m)
        })
    }

    /// Keep what a `Membership` read: the registries, newer vault keys,
    /// the folders of the vault in the local keyring (with the keys granted
    /// to this device), the device list.
    /// The folder keys the local keyring holds (from grants, or taken from
    /// escrow by `recover_folders`, which only the keyring keeps).
    fn keyring_keys(&self) -> Result<Vec<crate::membership3::FolderKeys>> {
        let mut out = Vec::new();
        for rec in self.keyring.folders.values() {
            let Ok(id) = bin(&rec.folder_id) else {
                continue;
            };
            if rec.k11_hex.is_empty() || rec.is_removed() {
                continue;
            }
            let mut epochs = BTreeMap::new();
            if !rec.key_hex.is_empty() {
                epochs.insert(0, SecretKey::from_hex(&rec.key_hex)?);
            }
            for (e, k) in &rec.epoch_keys {
                epochs.insert(*e, SecretKey::from_hex(k)?);
            }
            if epochs.is_empty() {
                continue;
            }
            out.push(crate::membership3::FolderKeys {
                folder: id,
                epochs,
                k11: SecretKey::from_hex(&rec.k11_hex)?,
            });
        }
        Ok(out)
    }

    fn adopt_members(&mut self, mut snapshot: Members3, keys: VaultKeys) -> Result<()> {
        // Keys this device took from escrow (`recover_folders3`) are kept
        // in the local keyring only: they count as held.
        for k in self.keyring_keys()? {
            if snapshot.granted.get(&k.folder).is_none() {
                snapshot.granted.add(k);
            }
        }
        let mut epochs_changed = false;
        for (e, k) in keys.keys {
            if let std::collections::btree_map::Entry::Vacant(v) = self.epochs.keys.entry(e) {
                v.insert(k);
                epochs_changed = true;
            }
        }
        if epochs_changed {
            self.save_epochs()?;
        }
        let mut lamport = 0;
        for st in snapshot.registry.folders.values() {
            lamport = lamport.max(st.max_lamport);
        }
        for (d, _) in snapshot.devices.devices.values() {
            lamport = lamport.max(d.stamp.lamport);
        }
        self.f3.members = snapshot;
        self.observe_clock(lamport)?;
        // A folder another device converted into a Strongroom (or gave a
        // new Strongroom key) takes the old one's place here before the
        // old one, now removed, is forgotten.
        self.adopt_conversions()?;
        self.sync_keyring()?;
        self.sync_devices()
    }

    /// The local keyring follows the folder records: every folder of the
    /// vault is listed (with its keys when a grant gave them here), removed
    /// folders are forgotten.
    fn sync_keyring(&mut self) -> Result<()> {
        let mut changed = false;
        let folders: Vec<(Id16, String, Id16, bool, bool, Option<String>)> = self
            .f3
            .members
            .registry
            .folders
            .values()
            .map(|st| {
                (
                    st.id,
                    st.shown.clone(),
                    st.creator,
                    st.is_removed(),
                    !st.members.is_empty(),
                    st.settings.get(BACKUP_SETTING).cloned(),
                )
            })
            .collect();
        let mut removed = Vec::new();
        for (id, name, creator, is_removed, shared, backup) in folders {
            let fid = FolderId::from_bytes(&id);
            if is_removed {
                if self
                    .keyring
                    .folders
                    .get(&fid)
                    .is_some_and(|r| !r.is_removed())
                {
                    removed.push(fid);
                }
                continue;
            }
            let keys = self.f3.members.granted.get(&id).cloned();
            changed |= !self.keyring.folders.contains_key(&fid);
            let rec = self
                .keyring
                .folders
                .entry(fid.clone())
                .or_insert_with(|| FolderRecord {
                    folder_id: fid.clone(),
                    name: name.clone(),
                    key_hex: String::new(),
                    k11_hex: String::new(),
                    created_by: DeviceId::from_bytes(&creator),
                    created_utc: util::now_utc(),
                    shared: false,
                    policy: None,
                    policy_updated_utc: 0,
                    placement: None,
                    placement_updated_utc: 0,
                    strongroom: None,
                    removed_utc: 0,
                    epoch_keys: BTreeMap::new(),
                    backup: None,
                });
            if rec.name != name {
                rec.name = name;
                changed = true;
            }
            if rec.shared != shared {
                rec.shared = shared;
                changed = true;
            }
            if let Some(info) = self
                .f3
                .members
                .strongrooms
                .get(&id)
                .and_then(|r| r.info().ok())
            {
                if rec.strongroom.as_ref() != Some(&info) {
                    rec.strongroom = Some(info);
                    changed = true;
                }
            }
            // A backup is a folder whose record says so (`backups`).
            if rec.backup.is_none() {
                if let Some(info) = backup.as_deref().and_then(|s| serde_json::from_str(s).ok()) {
                    rec.backup = Some(info);
                    changed = true;
                }
            }
            if let Some(k) = keys {
                for (e, k9) in &k.epochs {
                    let hex = k9.to_hex();
                    if *e == 0 {
                        if rec.key_hex != hex {
                            rec.key_hex = hex;
                            changed = true;
                        }
                    } else if rec.epoch_keys.get(e) != Some(&hex) {
                        rec.epoch_keys.insert(*e, hex);
                        changed = true;
                    }
                }
                let k11 = k.k11.to_hex();
                if rec.k11_hex != k11 {
                    rec.k11_hex = k11;
                    changed = true;
                }
            }
        }
        for fid in removed {
            self.forget_folder(&fid, util::now_utc())?;
            changed = true;
        }
        if changed {
            self.keyring.save(
                &self.home,
                &self.keys,
                &self.vault.vault_id,
                &self.vault.device_id,
            )?;
        }
        Ok(())
    }

    /// The device list (`devices.json`) follows the device records.
    fn sync_devices(&mut self) -> Result<()> {
        let m = &self.f3.members;
        let mut devices = BTreeMap::new();
        let mut epochs = BTreeMap::new();
        let mut details = BTreeMap::new();
        for (id, (rec, epoch)) in &m.devices.devices {
            let did = DeviceId::from_bytes(id);
            if let Some(d) = &rec.details {
                details.insert(
                    did.clone(),
                    super::devinfo::DeviceDetails::of_record(&did, d),
                );
            }
            devices.insert(
                did.clone(),
                DeviceRecord {
                    device_id: did.clone(),
                    name: rec.name.clone(),
                    pubkey_hex: hex::encode(&rec.sign_pub),
                    enrolled_utc: self
                        .devices
                        .devices
                        .get(&did)
                        .map(|r| r.enrolled_utc)
                        .unwrap_or_else(util::now_utc),
                },
            );
            if *epoch > 0 {
                epochs.insert(did, *epoch);
            }
        }
        let mut members = BTreeMap::new();
        for md in m.members.members.values() {
            let did = DeviceId::from_bytes(&md.device);
            members.insert(
                did.clone(),
                DeviceRecord {
                    device_id: did,
                    name: md.name.clone(),
                    pubkey_hex: hex::encode(&md.k6),
                    enrolled_utc: 0,
                },
            );
        }
        let mut revoked = BTreeMap::new();
        for (id, r) in &m.revocations {
            revoked.insert(
                DeviceId::from_bytes(id),
                membership::Revoked {
                    by: DeviceId::from_bytes(&r.issuer),
                    issued_utc: 0,
                    cutoff_seq: r.cutoff_seq,
                    wipe: r.wipe,
                },
            );
        }
        let changed = self.devices.devices.keys().ne(devices.keys())
            || self.devices.members.keys().ne(members.keys())
            || self.devices.revoked.keys().ne(revoked.keys())
            || self.devices.record_epochs != epochs
            || self.devices.details != details;
        self.devices.details = details;
        self.devices.devices = devices;
        self.devices.members = members;
        self.devices.revoked = revoked;
        self.devices.record_epochs = epochs;
        if changed {
            self.save_devices()?;
        }
        Ok(())
    }

    /// The keys of `folder` held here: from grants to this device (the
    /// local keyring keeps a copy), never derived from the vault key.
    pub(crate) fn folder_keys3(&self, rec: &FolderRecord) -> Result<FolderKeys> {
        if rec.key_hex.is_empty() && rec.epoch_keys.is_empty() {
            bail!(
                "this device holds no key of folder {}: ask for it with `varsto folder request {}` and approve it on a device that has the folder",
                rec.name,
                rec.name
            );
        }
        rec.keys()
    }

    /// The recovery key of this session (made by `init`, or given with
    /// `unlock --with-recovery-key`): folder epochs made now are escrowed
    /// under it at once.
    pub fn set_recovery_key(&mut self, k1: Option<crate::membership3::RecoveryKey>) {
        self.f3.recovery = k1;
    }

    /// `join --recovery-words`: every folder key the escrow holds, opened
    /// with the recovery key and this device's K3₀, is kept here (the
    /// vault words alone give no folder). Returns the names of the folders
    /// recovered.
    pub fn recover_folders(&mut self, k1: &crate::membership3::RecoveryKey) -> Result<Vec<String>> {
        let got = self
            .with_enrolled(|m| {
                let keys = m.recover_all_folders(k1)?;
                Ok(keys
                    .folders
                    .keys()
                    .filter_map(|f| m.registry.get(f).map(|s| s.name.clone()))
                    .collect::<Vec<_>>())
            })?
            .ok_or_else(|| anyhow!("no storage to read the recovery copies from"))?;
        self.f3.recovery = Some(k1.clone());
        Ok(got)
    }

    /// `add_folder` with the recovery key given for this folder's escrow
    /// (when the session holds none).
    pub fn add_folder_with_recovery(
        &mut self,
        name: &str,
        path: &Path,
        k1: Option<crate::membership3::RecoveryKey>,
    ) -> Result<FolderId> {
        if self.f3.recovery.is_some() || k1.is_none() {
            return self.add_folder(name, path);
        }
        self.f3.recovery = k1;
        let out = self.add_folder(name, path);
        self.f3.recovery = None;
        out
    }

    /// Whether this session holds the recovery key.
    pub fn has_recovery_key(&self) -> bool {
        self.f3.recovery.is_some()
    }

    /// The recovery kit with both word sets (the newest vault key and the
    /// recovery key of this session), as `init` prints it.
    pub fn recovery_kit_text(&self) -> Result<String> {
        let k1 = self.f3.recovery.as_ref().ok_or_else(|| {
            anyhow!("the recovery words are not at hand in this session (give them with --with-recovery-key)")
        })?;
        self.f3_kit_text(k1)
    }
}
