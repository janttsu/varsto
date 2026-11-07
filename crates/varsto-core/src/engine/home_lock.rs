// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! One writer of a device directory at a time.
//!
//! The background service keeps its engine open; the command line opens
//! another on the same directory. Each engine holds parts of the local state
//! in memory (the ledger heads, the folders' block map tables, the pack
//! context), and an operation of one rewrote files the other then
//! overwrote from its stale copy ("a kept row lost its pack").
//!
//! An operation that writes the local state (`sync`, `pull`, `push`,
//! `fsck`, `repair`, `scrub`, trash upkeep, folder attach and detach, a
//! backup snapshot, and the short ones that rewrite a folder's state or the
//! configuration: fetching, freeing, writing and moving a file, the folder
//! mode, selective sync, the deletion guard, confirming or discarding held
//! deletions, reverting, overriding) runs holding `state/home.lock` (an
//! exclusive file lock, waited for). Recording that a file was used takes
//! the lock only when it is free and is left out otherwise. Each holder
//! bumps the counter in `state/home.gen` when it is done; an engine that
//! finds the counter changed since its own last operation read the state
//! again from disk before going on.

use super::*;

const LOCK_FILE: &str = "home.lock";
const GEN_FILE: &str = "home.gen";

/// The counter another writer bumps: how often the state was written.
pub(super) fn read_generation(home: &Path) -> u64 {
    std::fs::read_to_string(home.join("state").join(GEN_FILE))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// The exclusive lock on `state/home.lock`, released when dropped.
struct HomeLock {
    _file: std::fs::File,
}

impl HomeLock {
    fn open(home: &Path) -> Result<(std::fs::File, PathBuf)> {
        let dir = home.join("state");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(LOCK_FILE);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        Ok((file, path))
    }

    fn take(home: &Path) -> Result<HomeLock> {
        let (file, path) = Self::open(home)?;
        if !try_lock(&file)? {
            log::info!("another process is using this device directory; waiting for it");
            lock(&file).with_context(|| format!("lock {}", path.display()))?;
        }
        Ok(HomeLock { _file: file })
    }

    /// The lock when nobody holds it, without waiting.
    fn take_if_free(home: &Path) -> Result<Option<HomeLock>> {
        let (file, _) = Self::open(home)?;
        Ok(try_lock(&file)?.then_some(HomeLock { _file: file }))
    }
}

#[cfg(unix)]
fn try_lock(file: &std::fs::File) -> Result<bool> {
    use std::os::unix::io::AsRawFd;
    let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if r == 0 {
        return Ok(true);
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(false)
    } else {
        Err(e.into())
    }
}

#[cfg(unix)]
fn lock(file: &std::fs::File) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    loop {
        let r = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if r == 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        if e.kind() != std::io::ErrorKind::Interrupted {
            return Err(e.into());
        }
    }
}

#[cfg(not(unix))]
#[allow(clippy::incompatible_msrv)]
fn try_lock(file: &std::fs::File) -> Result<bool> {
    match file.try_lock() {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

#[cfg(not(unix))]
#[allow(clippy::incompatible_msrv)]
fn lock(file: &std::fs::File) -> Result<()> {
    Ok(file.lock()?)
}

impl Engine {
    /// Run `f` as the only writer of this device directory: other engines
    /// on it (another process, or another engine of this one) wait, and
    /// what they wrote since this engine's last operation is read first.
    /// Nested calls run inside the outer one's lock.
    pub(crate) fn exclusive<T>(&mut self, f: impl FnOnce(&mut Engine) -> Result<T>) -> Result<T> {
        if self.home_held {
            return f(self);
        }
        let lock = HomeLock::take(&self.home)?;
        self.holding(lock, f)
    }

    /// [`Engine::exclusive`] for an update that may be left out (when a
    /// file was last used): while another engine holds the device
    /// directory, `f` is not run and `None` is returned instead of waiting
    /// for a sync to end.
    pub(crate) fn exclusive_if_free<T>(
        &mut self,
        f: impl FnOnce(&mut Engine) -> Result<T>,
    ) -> Result<Option<T>> {
        if self.home_held {
            return f(self).map(Some);
        }
        match HomeLock::take_if_free(&self.home)? {
            Some(lock) => self.holding(lock, f).map(Some),
            None => Ok(None),
        }
    }

    /// Run `f` with `lock` taken: read again what others wrote, then mark
    /// the directory written.
    fn holding<T>(
        &mut self,
        lock: HomeLock,
        f: impl FnOnce(&mut Engine) -> Result<T>,
    ) -> Result<T> {
        let found = read_generation(&self.home);
        if found != self.home_generation {
            log::debug!(
                generation = found;
                "the device directory was written by another engine; reading it again"
            );
            if let Err(e) = self.refresh_from_disk() {
                // Nothing is written with a state that could not be read.
                drop(lock);
                return Err(e.context("reading the device directory again"));
            }
        }
        self.home_held = true;
        let out = f(self);
        self.home_held = false;
        let next = found.wrapping_add(1);
        let state = self.home.join("state");
        // A wipe (this device was removed) leaves no state to mark.
        if state.is_dir() {
            let path = state.join(GEN_FILE);
            match util::write_atomic(&path, next.to_string().as_bytes()) {
                Ok(()) => self.home_generation = next,
                Err(e) => log::warn!("{}: {e:#}", path.display()),
            }
        }
        drop(lock);
        out
    }

    /// Read again what another engine may have written: the ledger, the
    /// membership, the block map tables, the pack context, the local
    /// configuration. Events not yet in a batch and the session's recovery
    /// key stay.
    fn refresh_from_disk(&mut self) -> Result<()> {
        let mut f3 = ledger3_ops::Core3::open(&self.home, &self.vault.vault_id)?;
        f3.recovery = self.f3.recovery.take();
        f3.pending = std::mem::take(&mut self.f3.pending);
        f3.replicas = std::mem::take(&mut self.f3.replicas);
        self.f3 = f3;
        self.forget_storages();
        self.pack_caches = Default::default();
        self.prefetched.clear();
        self.last_scan = None;
        self.reload_local_inner()?;
        self.epochs = membership::VaultEpochs::load(
            &self.home,
            &self.keys,
            &self.vault.vault_id,
            &self.vault.device_id,
        )?;
        self.removal = util::read_json(&self.home.join("removed.json")).ok();
        self.devices = util::read_json_or_default(&self.home.join("devices.json"))?;
        self.org = crate::org::OrgState::load(&self.home);
        if let Err(e) = self.load_members3_local() {
            log::warn!("membership records kept here could not be read: {e:#}");
        }
        Ok(())
    }
}
