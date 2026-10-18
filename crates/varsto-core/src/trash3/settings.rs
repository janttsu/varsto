// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The `settings` record (kind 18, `vault/settings/<device>/`, `registry@`,
//! not announced: the newest seq of a stream wins): the vault's trash and
//! history days, the days per folder, and the trash storage (sections 43
//! and 50). Only the trash and history fields exist here; the design's
//! table lists no other settings.
//!
//! The newest record of any accepted device wins, ordered by
//! (`updated_utc`, `lamport`, device). Members of shared folders cannot
//! read the registry key, so they never see these and keep the defaults
//! ([`Settings::default`]).

use super::Id16;
use crate::record::{Kind, RecordBody, RecordMeta, RecordStore, RecordsRefused, StreamRef};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Days an entry stays in the trash unless the vault or folder says otherwise.
pub const DEFAULT_TRASH_DAYS: u32 = 30;
/// Days replaced versions are kept unless the vault or folder says otherwise.
pub const DEFAULT_HISTORY_DAYS: u32 = 90;
/// Longest retention that can be set (ten years).
pub const MAX_DAYS: u32 = 3650;
/// Most per-folder overrides in one record.
pub const MAX_FOLDERS: usize = 65_536;
/// Longest storage name or identity, in bytes.
pub const MAX_NAME: usize = 1024;

/// The body of a `settings` record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettingsBody {
    pub device: Id16,
    pub seq: u64,
    pub lamport: u64,
    pub updated_utc: i64,
    /// 1 to 3650.
    pub trash_days: u32,
    /// 0 keeps no new versions; otherwise 1 to 3650.
    pub history_days: u32,
    /// Name of the trash storage on the writing device, and its identity so
    /// devices that name it differently find it.
    pub trash_storage: Option<String>,
    pub storage_id: Option<String>,
    /// Folders kept for another number of days (1 to 3650), sorted by id.
    pub folder_trash_days: Vec<(Id16, u32)>,
    /// Folders with their own history days (0: keeps no new versions).
    pub folder_history_days: Vec<(Id16, u32)>,
}

impl SettingsBody {
    /// The defaults of a vault that never set anything.
    pub fn defaults(device: Id16, seq: u64) -> SettingsBody {
        SettingsBody {
            device,
            seq,
            lamport: seq,
            updated_utc: 0,
            trash_days: DEFAULT_TRASH_DAYS,
            history_days: DEFAULT_HISTORY_DAYS,
            trash_storage: None,
            storage_id: None,
            folder_trash_days: Vec::new(),
            folder_history_days: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.seq == 0 {
            return Err("seq 0".into());
        }
        if self.trash_days == 0 || self.trash_days > MAX_DAYS {
            return Err(format!("trash days {}", self.trash_days));
        }
        if self.history_days > MAX_DAYS {
            return Err(format!("history days {}", self.history_days));
        }
        for list in [&self.folder_trash_days, &self.folder_history_days] {
            if list.len() > MAX_FOLDERS {
                return Err("too many folder overrides".into());
            }
            if list.windows(2).any(|w| w[0].0 >= w[1].0) {
                return Err("folder overrides are not sorted and unique".into());
            }
            if list.iter().any(|(_, d)| *d > MAX_DAYS) {
                return Err("a folder keeps more than the longest retention".into());
            }
        }
        // A folder's trash days run from 1; 0 means "follow the vault" and
        // is not written.
        if self.folder_trash_days.iter().any(|(_, d)| *d == 0) {
            return Err("a folder with 0 trash days".into());
        }
        for s in [&self.trash_storage, &self.storage_id]
            .into_iter()
            .flatten()
        {
            if s.len() > MAX_NAME {
                return Err("a storage name that long".into());
            }
        }
        Ok(())
    }

    fn order(&self) -> (i64, u64, Id16, u64) {
        (self.updated_utc, self.lamport, self.device, self.seq)
    }
}

impl RecordBody for SettingsBody {
    fn check(&self, meta: &RecordMeta) -> Result<(), String> {
        if meta.scope != [0; 16] {
            return Err("settings are vault-wide".into());
        }
        if self.device != meta.device {
            return Err("its device is not the record's writer".into());
        }
        if self.seq != meta.seq {
            return Err("its seq is not the record's".into());
        }
        self.validate()
    }
}

/// The stream of `device`'s settings.
pub fn settings_stream(device: Id16) -> StreamRef {
    StreamRef::new(Kind::Settings, [0; 16], device)
}

/// The settings in force.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub trash_days: u32,
    pub history_days: u32,
    pub trash_storage: Option<String>,
    pub storage_id: Option<String>,
    pub folder_trash_days: BTreeMap<Id16, u32>,
    pub folder_history_days: BTreeMap<Id16, u32>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings::from(&SettingsBody::defaults([0; 16], 1))
    }
}

impl From<&SettingsBody> for Settings {
    fn from(b: &SettingsBody) -> Self {
        Settings {
            trash_days: b.trash_days,
            history_days: b.history_days,
            trash_storage: b.trash_storage.clone(),
            storage_id: b.storage_id.clone(),
            folder_trash_days: b.folder_trash_days.iter().copied().collect(),
            folder_history_days: b.folder_history_days.iter().copied().collect(),
        }
    }
}

impl Settings {
    /// The newest of `bodies` (the newest record of each accepted device),
    /// or the defaults.
    pub fn newest<'a>(bodies: impl IntoIterator<Item = &'a SettingsBody>) -> Settings {
        bodies
            .into_iter()
            .max_by_key(|b| b.order())
            .map(Settings::from)
            .unwrap_or_default()
    }

    /// Days a folder's trash entries are kept.
    pub fn trash_days_for(&self, folder: &Id16) -> u32 {
        self.folder_trash_days
            .get(folder)
            .copied()
            .unwrap_or(self.trash_days)
            .clamp(1, MAX_DAYS)
    }

    /// Days a folder's history keeps new versions; `None` when it keeps no
    /// new ones.
    pub fn history_days_for(&self, folder: &Id16) -> Option<u32> {
        let d = self
            .folder_history_days
            .get(folder)
            .copied()
            .unwrap_or(self.history_days);
        (d > 0).then(|| d.min(MAX_DAYS))
    }

    /// Days the versions already kept stay (a folder turned off keeps its
    /// versions on the vault's schedule, 90 days when the vault is off too).
    pub fn history_keep_days(&self, folder: &Id16) -> u32 {
        self.history_days_for(folder)
            .unwrap_or(if self.history_days > 0 {
                self.history_days.min(MAX_DAYS)
            } else {
                DEFAULT_HISTORY_DAYS
            })
    }

    /// Read the newest settings record of each of `devices` from one
    /// storage and take the newest of them. Junk and refused records are
    /// counted in `counter` and ignored.
    pub fn read(
        store: &RecordStore,
        devices: &[Id16],
        counter: &mut RecordsRefused,
    ) -> Result<Settings> {
        let mut found: Vec<SettingsBody> = Vec::new();
        for d in devices {
            let s = settings_stream(*d);
            let high = store.highest_seq(&s)?;
            if high == 0 {
                continue;
            }
            // The newest accepted one; a refused newest falls back to the
            // one before it.
            let read = store.read_after::<SettingsBody>(&s, high.saturating_sub(8), counter)?;
            if let Some(rec) = read.accepted.into_iter().max_by_key(|r| r.meta.seq) {
                found.push(rec.body);
            }
        }
        Ok(Settings::newest(&found))
    }
}
