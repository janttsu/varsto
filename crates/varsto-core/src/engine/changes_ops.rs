// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Change history of files on the engine (`crate::changes`): recording the
//! versions of every manifest view a pull takes (`manifest3`: the paths a
//! writer's records changed) and of every manifest this device publishes,
//! starting the history from what a device already holds, and answering
//! `varsto changes` / `GET /api/changes`. The history is derived from the
//! manifests and stays local; it is not a record (design section 7).

use super::*;
use crate::changes::{Candidate, ChangeEvent, ChangeLimits, ChangeLog};
use crate::manifest3::{FolderManifests, WriterView};
use crate::record::Id16;

/// What `Engine::changes` looks for.
#[derive(Clone, Debug, Default)]
pub struct ChangesQuery {
    /// A file (its versions, following renames back) or a directory prefix.
    pub path: Option<String>,
    /// A device name or id (prefix of at least four characters).
    pub device: Option<String>,
    /// A person of the organization.
    pub user: Option<String>,
    /// Only changes published at or after this time (UTC seconds).
    pub since_utc: Option<i64>,
    /// At most this many, newest first (0: all).
    pub limit: usize,
}

/// One change as shown.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangeView {
    #[serde(flatten)]
    pub event: ChangeEvent,
    pub device_name: String,
    /// The person the device belongs to (organizations only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    pub source_name: String,
}

/// The answer to a query.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangesReport {
    pub folder: String,
    pub path: Option<String>,
    /// `path` is one file (its versions), not a directory.
    pub file: bool,
    /// Newest first.
    pub changes: Vec<ChangeView>,
    /// More changes matched than were returned.
    pub truncated: bool,
}

impl Engine {
    /// How much history this device keeps.
    pub fn change_limits(&self) -> ChangeLimits {
        self.config.changes
    }

    /// Keep more or less history (saved in `config.json`).
    pub fn set_change_limits(&mut self, limits: ChangeLimits) -> Result<()> {
        if limits.per_file == 0 || limits.per_folder == 0 {
            bail!("keep at least one version per file and one change per folder");
        }
        self.config.changes = limits;
        self.config.save(&self.home)
    }

    pub(super) fn open_history(&self, folder: &FolderId) -> ChangeLog {
        ChangeLog::open(&self.home, folder.as_str(), self.config.changes)
    }

    /// Record the versions of `view`, a writer's manifest as read (only the
    /// paths in `only` when given). Every record read was accepted against
    /// its announcement, so its versions count as verified.
    pub(super) fn history_from_view(
        &self,
        hist: &mut ChangeLog,
        device: &Id16,
        view: &WriterView,
        only: Option<&BTreeSet<String>>,
    ) -> Result<()> {
        let source = DeviceId::from_bytes(device);
        let states: Vec<FileState> = view
            .files
            .values()
            .filter(|e| only.is_none_or(|o| o.contains(&e.path)))
            .map(|e| e.to_state())
            .collect();
        let cands: Vec<Candidate> = states
            .iter()
            .map(|f| Candidate {
                state: f,
                source: &source,
                time_utc: view.created_utc,
                verified: true,
                backfilled: false,
            })
            .collect();
        hist.record(cands)?;
        Ok(())
    }

    /// Record this device's versions as it publishes its manifest.
    pub(super) fn history_from_own(
        &self,
        rec: &FolderRecord,
        state: &FolderState,
        utc: i64,
    ) -> Result<()> {
        let mut hist = self.open_history(&rec.folder_id);
        let me = self.vault.device_id.clone();
        let cands: Vec<Candidate> = state
            .files
            .values()
            .map(|f| Candidate {
                state: f,
                source: &me,
                time_utc: utc,
                verified: true,
                backfilled: false,
            })
            .collect();
        hist.record(cands)?;
        hist.save()
    }

    /// Start the history of a folder on this device: the newest manifest of
    /// every writer this device took records from, then the other devices'
    /// versions this device holds that none of them named, at the file's
    /// modification time. Runs once per folder.
    pub(super) fn history_backfill(
        &self,
        hist: &mut ChangeLog,
        state: &FolderState,
        manifests: &FolderManifests,
    ) -> Result<()> {
        if hist.index.backfilled {
            return Ok(());
        }
        for (dev, view) in &manifests.views {
            self.history_from_view(hist, dev, view, None)?;
        }
        let me = self.vault.device_id.clone();
        let now = util::now_utc();
        // Other devices' versions this device holds that no manifest names
        // any more. Its own come from its manifest above, or when it
        // publishes them.
        let cands: Vec<Candidate> = state
            .files
            .values()
            .filter(|f| f.modified_by != me)
            .map(|f| Candidate {
                state: f,
                source: &me,
                time_utc: if f.mtime > 0 {
                    f.mtime / 1_000_000_000
                } else {
                    now
                },
                verified: false,
                backfilled: true,
            })
            .collect();
        hist.record(cands)?;
        hist.set_backfilled();
        Ok(())
    }

    /// Start the history of a folder here if it has none yet (a device
    /// that has not pulled since history existed), without a whole pull.
    pub fn history_start(&mut self, folder: &str) -> Result<()> {
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let mut hist = self.open_history(&rec.folder_id);
        if hist.index.backfilled || rec.is_backup() || rec.is_strongroom() {
            return Ok(());
        }
        let rec = self.with_key(&rec)?;
        let state = self.load_state(&rec.folder_id)?;
        let manifests = self.load_manifests(&members3::bin(&rec.folder_id)?);
        self.history_backfill(&mut hist, &state, &manifests)?;
        hist.save()
    }

    /// The name of any device this one knows: its own, the vault's, a
    /// member of a shared folder.
    pub(super) fn any_device_name(&self, d: &DeviceId) -> String {
        if d == &self.vault.device_id {
            return self.vault.device_name.clone();
        }
        if let Some(r) = self.devices.devices.get(d) {
            return r.name.clone();
        }
        if let Some(r) = self.devices.members.get(d) {
            return r.name.clone();
        }
        d.short().to_string()
    }

    /// Who changed what and when in a folder: for one file its versions
    /// (renames followed back to where it came from), or the recent changes
    /// under a directory or the whole folder, newest first.
    pub fn changes(&self, folder: &str, q: &ChangesQuery) -> Result<ChangesReport> {
        let rec = self
            .keyring
            .find(folder)
            .cloned()
            .ok_or_else(|| anyhow!("unknown folder {folder}"))?;
        let all = self.open_history(&rec.folder_id).events();
        let path = q
            .path
            .as_deref()
            .map(|p| p.trim().trim_start_matches('/').to_string())
            .filter(|p| !p.is_empty());
        let mut file = false;
        let mut selected: Vec<&ChangeEvent> = match &path {
            Some(p) if all.iter().any(|e| &e.path == p) => {
                file = true;
                // The file's own versions, then where a rename brought it
                // from: (path, versions up to this clock, the path it moved to).
                let mut paths: Vec<(String, u64, Option<String>)> =
                    vec![(p.clone(), u64::MAX, None)];
                let mut i = 0;
                while i < paths.len() && paths.len() < 16 {
                    let (cur, until, _) = paths[i].clone();
                    for e in all.iter().filter(|e| e.path == cur && e.clock <= until) {
                        if let (crate::changes::Action::Renamed, Some(from)) = (e.action, &e.from) {
                            if !paths.iter().any(|(x, _, _)| x == from) {
                                paths.push((from.clone(), e.clock, Some(cur.clone())));
                            }
                        }
                    }
                    i += 1;
                }
                // The old name's side of a move is the same change as the
                // new name's "renamed from": shown once.
                all.iter()
                    .filter(|e| {
                        paths.iter().any(|(x, until, to)| {
                            &e.path == x
                                && e.clock <= *until
                                && (to.is_none() || e.to.is_none() || e.to != *to)
                        })
                    })
                    .collect()
            }
            Some(p) => {
                let dir = format!("{}/", p.trim_end_matches('/'));
                all.iter().filter(|e| e.path.starts_with(&dir)).collect()
            }
            None => all.iter().collect(),
        };
        if let Some(d) = q.device.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
            selected.retain(|e| {
                (d.len() >= 4 && e.device.as_str().starts_with(&d.to_ascii_lowercase()))
                    || self.any_device_name(&e.device).eq_ignore_ascii_case(d)
            });
        }
        let user_of = |dev: &DeviceId| self.org.as_ref().and_then(|o| o.user_of(dev));
        if let Some(u) = q.user.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            selected.retain(|e| user_of(&e.device).is_some_and(|x| x.eq_ignore_ascii_case(u)));
        }
        if let Some(since) = q.since_utc {
            selected.retain(|e| e.time_utc >= since);
        }
        // Newest first.
        selected.sort_by_key(|e| std::cmp::Reverse((e.time_utc, e.clock)));
        let truncated = q.limit > 0 && selected.len() > q.limit;
        if q.limit > 0 {
            selected.truncate(q.limit);
        }
        Ok(ChangesReport {
            folder: rec.name.clone(),
            path,
            file,
            changes: selected
                .into_iter()
                .map(|e| ChangeView {
                    event: e.clone(),
                    device_name: self.any_device_name(&e.device),
                    user: user_of(&e.device),
                    source_name: self.any_device_name(&e.source),
                })
                .collect(),
            truncated,
        })
    }
}
