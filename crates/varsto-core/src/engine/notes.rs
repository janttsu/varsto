// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! File analyses: a text per file saying what the file contains, with tags,
//! kept by Varsto and readable on every device of the folder
//! (`docs/spec/alpha-0-format.md`, section "File analyses").
//!
//! An assistant (typically a local LLM reading synced plain files from their
//! `local_path`) records what it saw through MCP (`varsto_set_analysis`);
//! the user can write or clear one by hand. Later the assistant searches
//! them (`varsto_search_analyses`) to reorganise files without reading
//! everything again.
//!
//! Storage: every device keeps the merged map of the folder in
//! `state/notes/<folder>.json` and publishes it as one *notes record* per
//! folder, `vault/notes/<folder>/<device>/<written utc, 20 digits>.enc`, zstd
//! JSON sealed with XChaCha20-Poly1305 under a key derived from the folder's
//! current metadata key (associated data: vault, folder, device, time), the
//! same pattern as the access records (`access_sync`). Each entry carries
//! the time it was last written (`updated_utc`) and the device that wrote
//! it; readers merge entries newest-wins per path (ties: the larger device
//! id). A cleared analysis is a tombstone that wins over the older text and
//! is forgotten after [`TOMBSTONE_KEEP_SECS`]. Because every device
//! republishes what it merged, an analysis outlives the device that wrote it.
//!
//! Why not ledger events: analyses can be many and long (up to 16 KiB
//! each), they are rewritten as often as an assistant likes, and signed
//! ledger batches are replicated to every device forever. One replaceable
//! object per device and folder costs O(analyses) bytes however often they
//! change.
//!
//! Following files: an analysis whose file was deleted moves to the live
//! files with the content hash it was written for and no analysis of their
//! own (a rename or move seen by a scan); `move_file` moves it directly.
//! When no such file is left the analysis is dropped. An analysis whose file
//! changed since is reported `stale`.

use super::*;
use crate::record::{Id16, KeyId};
use crate::records3::{self, NoteWire, NotesBody};

/// Largest analysis text, in bytes of UTF-8.
pub const ANALYSIS_MAX_BYTES: usize = 16 * 1024;
/// Most tags per file.
pub const TAGS_MAX: usize = 32;
/// Longest tag, in characters.
pub const TAG_MAX_CHARS: usize = 64;
/// Longest "by" label (the model or tool that wrote the analysis).
pub const BY_MAX_CHARS: usize = 128;
/// Characters of an analysis shown in file listings.
pub const LISTING_CHARS: usize = 500;
/// Least time between two reads of the other devices' notes records
/// started by a sync (publishing happens on every sync that changed them).
pub const NOTES_READ_INTERVAL_SECS: i64 = 300;
/// A cleared analysis is remembered this long, so that a device that still
/// publishes the older text does not bring it back.
pub const TOMBSTONE_KEEP_SECS: i64 = 180 * 86_400;

/// One file's analysis as kept and published.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub(super) struct NoteEntry {
    #[serde(default)]
    analysis: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    /// The file's content hash when it was analysed.
    #[serde(default)]
    content_hash: String,
    /// The device whose user or assistant wrote the analysis, and its name then.
    #[serde(default)]
    device: DeviceId,
    #[serde(default)]
    device_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    by: Option<String>,
    #[serde(default)]
    analysed_utc: i64,
    /// When this entry was last written (set, cleared or moved), and by
    /// which device: the merge order.
    updated_utc: i64,
    #[serde(default)]
    updated_by: DeviceId,
    /// Cleared: a tombstone.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    cleared: bool,
}

impl NoteEntry {
    fn newer_than(&self, other: &NoteEntry) -> bool {
        (self.updated_utc, self.updated_by.as_str())
            > (other.updated_utc, other.updated_by.as_str())
    }
}

/// `state/notes/<folder>.json`: the merged map, what this device published
/// last and the newest record read from every other device.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct NotesState {
    #[serde(default)]
    entries: BTreeMap<String, NoteEntry>,
    #[serde(default)]
    published_utc: i64,
    #[serde(default)]
    published_hash: String,
    #[serde(default)]
    read_utc: i64,
    #[serde(default)]
    seen: BTreeMap<DeviceId, i64>,
}

/// A file's analysis as reported to the interface, the command line and MCP.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileAnalysis {
    pub path: String,
    pub analysis: String,
    pub tags: Vec<String>,
    /// Content hash of the file when it was analysed.
    pub content_hash: String,
    /// The file changed since it was analysed.
    pub stale: bool,
    /// Name of the device it was written on.
    pub author: String,
    /// The model or tool that wrote it, as it said (optional).
    pub by: Option<String>,
    pub analysed_utc: i64,
}

/// One search result.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisHit {
    pub folder: String,
    pub path: String,
    /// "local", "placeholder" or "missing" (as in `list_files`).
    pub state: String,
    /// Where the file is (or would be) on this device's disk.
    pub disk: PathBuf,
    /// Part of the analysis around the first match (or its beginning).
    pub snippet: String,
    pub tags: Vec<String>,
    pub stale: bool,
    pub analysed_utc: Option<i64>,
    pub by: Option<String>,
    /// Higher is a better match.
    pub score: u32,
}

/// What one exchange of notes records did.
#[derive(Clone, Debug, Serialize, Default)]
pub struct NotesExchangeReport {
    /// Folders whose record this device published now.
    pub published: usize,
    /// Records of other devices read now.
    pub received: usize,
    /// Analyses moved to a renamed file or dropped with a deleted one.
    pub followed: usize,
}

/// The storage prefix of a folder's notes records.
pub(super) fn folder_prefix(folder: &FolderId) -> String {
    format!("notes/{folder}/")
}

fn no_control(s: &str) -> bool {
    !s.chars().any(|c| c.is_control())
}

/// Check and normalise the parts of an analysis: the text (trailing white
/// space trimmed, not empty, at most [`ANALYSIS_MAX_BYTES`]), tags (trimmed,
/// empty ones and repeats dropped, at most [`TAGS_MAX`] of
/// [`TAG_MAX_CHARS`]) and the "by" label.
pub fn check_analysis(
    text: &str,
    tags: &[String],
    by: Option<&str>,
) -> Result<(String, Vec<String>, Option<String>)> {
    let text = text.trim_end().to_string();
    if text.trim().is_empty() {
        bail!("the analysis is empty");
    }
    if text.len() > ANALYSIS_MAX_BYTES {
        bail!(
            "the analysis is {} bytes; at most {ANALYSIS_MAX_BYTES} are kept per file: shorten it",
            text.len()
        );
    }
    let mut out: Vec<String> = Vec::new();
    for t in tags {
        let t = t.trim();
        if t.is_empty() {
            continue;
        }
        if t.chars().count() > TAG_MAX_CHARS || !no_control(t) {
            bail!("tag {t:?} is longer than {TAG_MAX_CHARS} characters or contains control characters");
        }
        if !out.iter().any(|o| o.to_lowercase() == t.to_lowercase()) {
            out.push(t.to_string());
        }
    }
    if out.len() > TAGS_MAX {
        bail!("{} tags; at most {TAGS_MAX} are kept per file", out.len());
    }
    let by = match by.map(str::trim).filter(|b| !b.is_empty()) {
        Some(b) if b.chars().count() > BY_MAX_CHARS || !no_control(b) => {
            bail!("the \"by\" label is longer than {BY_MAX_CHARS} characters or contains control characters")
        }
        Some(b) => Some(b.to_string()),
        None => None,
    };
    Ok((text, out, by))
}

/// Lower-case one character at a time, so that positions in the result are
/// positions in the original.
fn fold(s: &str) -> Vec<char> {
    s.chars()
        .map(|c| c.to_lowercase().next().unwrap_or(c))
        .collect()
}

fn find(hay: &[char], needle: &[char]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| hay[i..i + needle.len()] == *needle)
}

fn count(hay: &[char], needle: &[char]) -> u32 {
    if needle.is_empty() || needle.len() > hay.len() {
        return 0;
    }
    (0..=hay.len() - needle.len())
        .filter(|&i| hay[i..i + needle.len()] == *needle)
        .count() as u32
}

/// About 200 characters of `text` around character `at`.
fn snippet(text: &str, at: Option<usize>) -> String {
    let chars: Vec<char> = text.chars().collect();
    let start = at.map(|a| a.saturating_sub(60)).unwrap_or(0);
    let end = (start + 200).min(chars.len());
    let mut s: String = chars[start..end].iter().collect();
    s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if start > 0 {
        s = format!("…{s}");
    }
    if end < chars.len() {
        s.push('…');
    }
    s
}

impl Engine {
    fn notes_path(&self, folder: &FolderId) -> PathBuf {
        self.home
            .join("state")
            .join("notes")
            .join(format!("{folder}.json"))
    }

    fn load_notes(&self, folder: &FolderId) -> NotesState {
        util::read_json_or_default(&self.notes_path(folder)).unwrap_or_default()
    }

    fn save_notes(&self, folder: &FolderId, notes: &NotesState) -> Result<()> {
        let path = self.notes_path(folder);
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        util::write_json(&path, notes)
    }

    /// Forget a removed folder's analyses on this device.
    pub(super) fn forget_notes(&self, folder: &FolderId) {
        let _ = fs::remove_file(self.notes_path(folder));
    }

    /// The live entry of `path`, if any.
    fn live<'a>(notes: &'a NotesState, path: &str) -> Option<&'a NoteEntry> {
        notes.entries.get(path).filter(|e| !e.cleared)
    }

    fn report(path: &str, e: &NoteEntry, current_hash: Option<&str>) -> FileAnalysis {
        FileAnalysis {
            path: path.to_string(),
            analysis: e.analysis.clone(),
            tags: e.tags.clone(),
            content_hash: e.content_hash.clone(),
            stale: current_hash.is_some_and(|h| h != e.content_hash),
            author: e.device_name.clone(),
            by: e.by.clone(),
            analysed_utc: e.analysed_utc,
        }
    }

    /// Write an entry for `path`, later than whatever is there.
    fn put_note(&self, notes: &mut NotesState, path: &str, mut e: NoteEntry) {
        let now = util::now_utc();
        let floor = notes
            .entries
            .get(path)
            .map(|o| o.updated_utc + 1)
            .unwrap_or(0);
        e.updated_utc = now.max(floor);
        e.updated_by = self.vault.device_id.clone();
        notes.entries.insert(path.to_string(), e);
    }

    fn tombstone(&self, notes: &mut NotesState, path: &str) {
        self.put_note(
            notes,
            path,
            NoteEntry {
                cleared: true,
                ..Default::default()
            },
        );
    }

    /// Record what `path` contains: `text` (at most 16 KiB), `tags` and,
    /// optionally, the model or tool that wrote it. Replaces the file's
    /// earlier analysis; published to the other devices with the next sync.
    pub fn set_analysis(
        &mut self,
        folder: &str,
        path: &str,
        text: &str,
        tags: &[String],
        by: Option<&str>,
    ) -> Result<FileAnalysis> {
        let (rec, _) = self.resolve_folder(folder)?;
        let (text, tags, by) = check_analysis(text, tags, by)?;
        let state = self.load_state(&rec.folder_id)?;
        let file = state
            .files
            .get(path)
            .filter(|f| !f.deleted)
            .ok_or_else(|| anyhow!("unknown file {path} in {folder}"))?;
        let mut notes = self.load_notes(&rec.folder_id);
        let entry = NoteEntry {
            analysis: text,
            tags,
            content_hash: file.content_hash.clone(),
            device: self.vault.device_id.clone(),
            device_name: self.vault.device_name.clone(),
            by,
            analysed_utc: util::now_utc(),
            ..Default::default()
        };
        self.put_note(&mut notes, path, entry);
        self.save_notes(&rec.folder_id, &notes)?;
        let e = &notes.entries[path];
        Ok(Self::report(path, e, Some(&file.content_hash)))
    }

    /// Clear a file's analysis on every device. False when it had none.
    pub fn clear_analysis(&mut self, folder: &str, path: &str) -> Result<bool> {
        let (rec, _) = self.resolve_folder(folder)?;
        let mut notes = self.load_notes(&rec.folder_id);
        if Self::live(&notes, path).is_none() {
            return Ok(false);
        }
        self.tombstone(&mut notes, path);
        self.save_notes(&rec.folder_id, &notes)?;
        Ok(true)
    }

    /// A file's analysis, in full.
    pub fn analysis(&self, folder: &str, path: &str) -> Result<Option<FileAnalysis>> {
        let (rec, _) = self.resolve_folder(folder)?;
        let state = self.load_state(&rec.folder_id)?;
        let Some(file) = state.files.get(path).filter(|f| !f.deleted) else {
            bail!("unknown file {path} in {folder}");
        };
        let notes = self.load_notes(&rec.folder_id);
        Ok(Self::live(&notes, path).map(|e| Self::report(path, e, Some(&file.content_hash))))
    }

    /// The analyses of a folder's files, in full, by path.
    pub fn analyses(&self, folder: &str) -> Result<Vec<FileAnalysis>> {
        let (rec, _) = self.resolve_folder(folder)?;
        let state = self.load_state(&rec.folder_id)?;
        let notes = self.load_notes(&rec.folder_id);
        Ok(Self::live_analyses(&state, &notes).into_values().collect())
    }

    /// Analyses of the folder's live files (analyses of files this device
    /// does not know yet, or that are gone, are not reported).
    fn live_analyses(state: &FolderState, notes: &NotesState) -> BTreeMap<String, FileAnalysis> {
        notes
            .entries
            .iter()
            .filter(|(_, e)| !e.cleared)
            .filter_map(|(p, e)| {
                let f = state.files.get(p).filter(|f| !f.deleted)?;
                Some((p.clone(), Self::report(p, e, Some(&f.content_hash))))
            })
            .collect()
    }

    /// For `list_files`: the analyses of the folder's live files.
    pub(super) fn analyses_for_listing(
        &self,
        folder: &FolderId,
        state: &FolderState,
    ) -> BTreeMap<String, FileAnalysis> {
        Self::live_analyses(state, &self.load_notes(folder))
    }

    /// Search a folder's files by their analysis, tags and path. Every word
    /// of `query` must occur (case-insensitively) in one of them, and the
    /// file must carry every tag of `tags`. Best matches first.
    pub fn search_analyses(
        &self,
        folder: &str,
        query: &str,
        tags: &[String],
    ) -> Result<Vec<AnalysisHit>> {
        let (rec, root) = self.resolve_folder(folder)?;
        let state = self.load_state(&rec.folder_id)?;
        let notes = self.load_notes(&rec.folder_id);
        let words: Vec<Vec<char>> = query.split_whitespace().map(fold).collect();
        let want: Vec<String> = tags
            .iter()
            .map(|t| t.trim().to_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        if words.is_empty() && want.is_empty() {
            bail!("give words to search for, tags, or both");
        }
        let entries = self.list_files(folder)?;
        let mut hits = Vec::new();
        for f in entries {
            let note = Self::live(&notes, &f.path);
            let have: Vec<String> = note
                .map(|n| n.tags.iter().map(|t| t.to_lowercase()).collect())
                .unwrap_or_default();
            if !want.iter().all(|t| have.contains(t)) {
                continue;
            }
            let path = fold(&f.path);
            let text = note.map(|n| fold(&n.analysis)).unwrap_or_default();
            let tag_chars: Vec<Vec<char>> = have.iter().map(|t| t.chars().collect()).collect();
            let mut score = want.len() as u32 * 3;
            let mut first: Option<usize> = None;
            let mut all = true;
            for w in &words {
                let in_tags = tag_chars.iter().filter(|t| find(t, w).is_some()).count() as u32;
                let in_path = count(&path, w);
                let in_text = count(&text, w);
                if in_tags + in_path + in_text == 0 {
                    all = false;
                    break;
                }
                score += in_tags * 3 + in_path * 2 + in_text.min(20);
                if first.is_none() {
                    first = find(&text, w);
                }
            }
            if !all {
                continue;
            }
            let disk = self.disk_of(&root, &state, &f.path);
            let current = state.files.get(&f.path).map(|s| s.content_hash.as_str());
            hits.push(AnalysisHit {
                folder: rec.name.clone(),
                path: f.path.clone(),
                state: f.state.clone(),
                disk,
                snippet: note
                    .map(|n| snippet(&n.analysis, first))
                    .unwrap_or_default(),
                tags: note.map(|n| n.tags.clone()).unwrap_or_default(),
                stale: note.is_some_and(|n| current.is_some_and(|h| h != n.content_hash)),
                analysed_utc: note.map(|n| n.analysed_utc),
                by: note.and_then(|n| n.by.clone()),
                score,
            });
        }
        hits.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.path.cmp(&b.path)));
        Ok(hits)
    }

    /// A folder converted into a Strongroom (new id, new key): its analyses
    /// move to the new folder, with the content hashes under the new key
    /// for files that had not changed since they were analysed.
    pub(super) fn notes_rekeyed(
        &self,
        old: &FolderId,
        new: &FolderId,
        old_state: &FolderState,
        new_state: &FolderState,
    ) {
        let mut notes = self.load_notes(old);
        if notes.entries.is_empty() {
            return;
        }
        for (path, e) in notes.entries.iter_mut() {
            let was = old_state.files.get(path).map(|f| f.content_hash.as_str());
            if let (Some(was), Some(now)) = (was, new_state.files.get(path)) {
                if was == e.content_hash {
                    e.content_hash = now.content_hash.clone();
                }
            }
        }
        notes.published_hash = String::new();
        notes.published_utc = 0;
        notes.seen.clear();
        notes.read_utc = 0;
        if self.save_notes(new, &notes).is_ok() {
            self.forget_notes(old);
        }
    }

    /// `move_file` moved `from` to `to`: its analysis goes along.
    pub(super) fn notes_follow_move(&self, folder: &FolderId, from: &str, to: &str) -> Result<()> {
        let mut notes = self.load_notes(folder);
        let Some(e) = Self::live(&notes, from).cloned() else {
            return Ok(());
        };
        self.put_note(&mut notes, to, e);
        self.tombstone(&mut notes, from);
        self.save_notes(folder, &notes)
    }

    /// Analyses of deleted files move to the live files with the same
    /// content and no analysis (a rename or a move), or are dropped; old
    /// tombstones are forgotten. Returns how many analyses were moved or
    /// dropped.
    fn follow_files(&self, notes: &mut NotesState, state: &FolderState, now: i64) -> usize {
        let mut followed = 0;
        let gone: Vec<(String, NoteEntry)> = notes
            .entries
            .iter()
            .filter(|(p, e)| !e.cleared && state.files.get(p.as_str()).is_some_and(|f| f.deleted))
            .map(|(p, e)| (p.clone(), e.clone()))
            .collect();
        for (path, e) in gone {
            let targets: Vec<String> = if e.content_hash.is_empty() {
                Vec::new()
            } else {
                state
                    .files
                    .values()
                    .filter(|f| !f.deleted && f.content_hash == e.content_hash)
                    .filter(|f| Self::live(notes, &f.path).is_none())
                    .map(|f| f.path.clone())
                    .collect()
            };
            for t in targets {
                self.put_note(notes, &t, e.clone());
            }
            self.tombstone(notes, &path);
            followed += 1;
        }
        notes
            .entries
            .retain(|_, e| !e.cleared || now - e.updated_utc < TOMBSTONE_KEEP_SECS);
        followed
    }

    /// Follow renames and deletions in every attached folder, publish this
    /// device's notes record of every folder whose analyses changed, and
    /// read the other devices' records when the last read is older than
    /// [`NOTES_READ_INTERVAL_SECS`] (or always with `force`). Called after
    /// every sync.
    pub(super) fn notes_upkeep(&mut self, force: bool) -> Result<NotesExchangeReport> {
        let mut report = NotesExchangeReport::default();
        if self.removal.is_some() {
            return Ok(report);
        }
        let storages = self.metadata_storages(false)?;
        let now = util::now_utc();
        let mounted: Vec<FolderId> = self
            .config
            .folders
            .iter()
            .map(|m| m.folder_id.clone())
            .collect();
        for fid in mounted {
            let Some(rec) = self.keyring.folders.get(&fid).filter(|r| !r.is_removed()) else {
                continue;
            };
            if rec.is_backup() {
                continue;
            }
            // A locked Strongroom is left alone.
            let Ok(rec) = self.with_key(rec) else {
                continue;
            };
            let state = self.load_state(&fid)?;
            let mut notes = self.load_notes(&fid);
            if notes.entries.is_empty()
                && !force
                && notes.read_utc > 0
                && now - notes.read_utc < NOTES_READ_INTERVAL_SECS
            {
                continue;
            }
            let before = notes.clone();
            if !storages.is_empty() && (force || now - notes.read_utc >= NOTES_READ_INTERVAL_SECS) {
                let fk = self.folder_keys(&rec)?;
                report.received += self.read_notes(&storages, &fk, &mut notes)?;
                notes.read_utc = now;
            }
            report.followed += self.follow_files(&mut notes, &state, now);
            if !storages.is_empty() {
                let fk = self.folder_keys(&rec)?;
                if self.publish_notes(&storages, &fk, &mut notes, now)? {
                    report.published += 1;
                }
            }
            if notes.entries != before.entries
                || notes.read_utc != before.read_utc
                || notes.published_hash != before.published_hash
                || notes.seen != before.seen
            {
                self.save_notes(&fid, &notes)?;
            }
        }
        Ok(report)
    }

    /// Exchange notes records now, whatever the schedule says.
    pub fn exchange_notes(&mut self) -> Result<NotesExchangeReport> {
        self.notes_upkeep(true)
    }

    fn publish_notes(
        &self,
        storages: &OpenStorages,
        fk: &FolderKeys,
        notes: &mut NotesState,
        now: i64,
    ) -> Result<bool> {
        let me_dev = &self.vault.device_id;
        // What this device wrote: sets, clears and moves.
        let mine: Vec<(String, NoteWire)> = notes
            .entries
            .iter()
            .filter(|(p, e)| &e.updated_by == me_dev && crate::names::check_synced_path(p).is_ok())
            .map(|(p, e)| {
                (
                    p.clone(),
                    NoteWire {
                        analysis: if e.cleared {
                            String::new()
                        } else {
                            e.analysis.clone()
                        },
                        tags: e.tags.clone(),
                        content_hash: e.content_hash.clone(),
                        by: e.by.clone(),
                        // The merge order of the wire: a clear or a move
                        // counts from the time it was made.
                        analysed_utc: if e.cleared || e.updated_utc > e.analysed_utc {
                            e.updated_utc
                        } else {
                            e.analysed_utc
                        },
                    },
                )
            })
            .collect();
        if mine.is_empty() && notes.published_utc == 0 {
            return Ok(false);
        }
        let json = serde_json::to_vec(&mine)?;
        let hash = hex::encode(crypto::hash(&json));
        if hash == notes.published_hash {
            return Ok(false);
        }
        let folder = members3::bin(&fk.folder)?;
        let me = self.me3();
        let stream = records3::notes_stream(folder, me);
        let key = KeyId::Meta {
            folder,
            epoch: fk.epoch,
        };
        let written = now.max(notes.published_utc + 1);
        let published = self.write_record3(storages, &stream, &key, |seq| NotesBody {
            folder,
            device: me,
            seq,
            updated_utc: written,
            notes: mine.clone(),
        })?;
        // Only the newest record of a device is ever read.
        let view = self.view3()?;
        self.each_store3(storages, &view, |_, store, _| {
            for l in store.list_after(&stream, 0)? {
                if l.seq < published.seq {
                    for n in &l.names {
                        store.storage.delete(n)?;
                    }
                }
            }
            Ok(())
        })?;
        notes.published_utc = written;
        notes.published_hash = hash;
        Ok(true)
    }

    /// Read the newest record of every other device that is newer than the
    /// one read before, and merge its entries newest-wins.
    fn read_notes(
        &self,
        storages: &OpenStorages,
        fk: &FolderKeys,
        notes: &mut NotesState,
    ) -> Result<usize> {
        let folder = members3::bin(&fk.folder)?;
        let me = self.me3();
        let streams: Vec<crate::record::StreamRef> = self
            .stream_writers3()
            .into_iter()
            .filter(|d| *d != me && !self.is_revoked(&DeviceId::from_bytes(d)))
            .map(|d| records3::notes_stream(folder, d))
            .collect();
        let view = self.view3()?;
        let mut newest: BTreeMap<Id16, NotesBody> = BTreeMap::new();
        self.each_store3(storages, &view, |_, store, counter| {
            for b in records3::read_newest::<NotesBody>(store, &streams, counter)? {
                if newest.get(&b.device).is_none_or(|n| n.seq < b.seq) {
                    newest.insert(b.device, b);
                }
            }
            Ok(())
        })?;
        let mut read = 0;
        for (dev3, body) in newest {
            let dev = DeviceId::from_bytes(&dev3);
            if notes.seen.get(&dev).is_some_and(|s| *s >= body.updated_utc) {
                continue;
            }
            let name = self.any_device_name(&dev);
            for (path, w) in body.notes {
                // Entries over the limits (another implementation, or a
                // tampering device) are not taken.
                if w.analysis.len() > ANALYSIS_MAX_BYTES || w.tags.len() > TAGS_MAX {
                    continue;
                }
                let e = NoteEntry {
                    cleared: w.analysis.is_empty(),
                    analysis: w.analysis,
                    tags: w.tags,
                    content_hash: w.content_hash,
                    device: dev.clone(),
                    device_name: name.clone(),
                    by: w.by,
                    analysed_utc: w.analysed_utc,
                    updated_utc: w.analysed_utc,
                    updated_by: dev.clone(),
                };
                if notes.entries.get(&path).is_none_or(|o| e.newer_than(o)) {
                    notes.entries.insert(path, e);
                }
            }
            notes.seen.insert(dev, body.updated_utc);
            read += 1;
        }
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_checked() {
        assert!(check_analysis("   ", &[], None).is_err());
        let long = "x".repeat(ANALYSIS_MAX_BYTES + 1);
        assert!(check_analysis(&long, &[], None).is_err());
        assert!(check_analysis(&"x".repeat(ANALYSIS_MAX_BYTES), &[], None).is_ok());
        let many: Vec<String> = (0..=TAGS_MAX).map(|i| format!("t{i}")).collect();
        assert!(check_analysis("ok", &many, None).is_err());
        assert!(check_analysis("ok", &["y".repeat(TAG_MAX_CHARS + 1)], None).is_err());
        let (text, tags, by) = check_analysis(
            "receipt \n",
            &[" Tax ".into(), "tax".into(), "".into(), "2026".into()],
            Some(" qwen3 "),
        )
        .unwrap();
        assert_eq!(text, "receipt");
        assert_eq!(tags, vec!["Tax".to_string(), "2026".to_string()]);
        assert_eq!(by.as_deref(), Some("qwen3"));
        assert!(check_analysis("ok", &[], Some(&"b".repeat(BY_MAX_CHARS + 1))).is_err());
    }

    #[test]
    fn search_helpers_fold_case_and_cut_snippets() {
        let hay = fold("Kuitti ÄÄNIKIRJASTA");
        assert_eq!(find(&hay, &fold("äänikirja")), Some(7));
        assert_eq!(count(&fold("aa aa aa"), &fold("AA")), 3);
        let text = format!("{}needle{}", "a ".repeat(100), "b ".repeat(100));
        let s = snippet(&text, find(&fold(&text), &fold("needle")));
        assert!(s.starts_with('…') && s.ends_with('…') && s.contains("needle"));
    }

    #[test]
    fn newest_entry_wins() {
        let a = DeviceId::from_bytes(&[1; 16]);
        let b = DeviceId::from_bytes(&[2; 16]);
        let old = NoteEntry {
            updated_utc: 10,
            updated_by: b.clone(),
            ..Default::default()
        };
        let new = NoteEntry {
            updated_utc: 11,
            updated_by: a.clone(),
            ..Default::default()
        };
        assert!(new.newer_than(&old) && !old.newer_than(&new));
        let tie = NoteEntry {
            updated_utc: 10,
            updated_by: a,
            ..Default::default()
        };
        assert!(old.newer_than(&tie));
    }
}
