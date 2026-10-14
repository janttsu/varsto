// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Importing git-annex repositories, cloud drives (rclone) and local
//! directories into Varsto folders (`crate::import`, and
//! `docs/spec/alpha-0-format.md` section "Importing git-annex repositories,
//! cloud drives and local directories").
//!
//! A run: find (or create) the folder whose import book names the source,
//! attach it here (selective, or with a full local copy), pull it, list the
//! source, then read every content id that is not in the vault yet exactly
//! once: it is chunked, encrypted and written to the storages while its
//! hash is checked, and becomes a file of the folder only when the hash
//! matches. Paths whose content is elsewhere stay *awaiting import* in the
//! book. Every few seconds the ledger events, the folder state and the book
//! are saved, so an interrupted run carries on where it stopped.
//!
//! The book is kept per folder in `state/imports/<folder>.json` and
//! published as one replaceable record per device,
//! `vault/imports/<folder>/<device>/<written utc, 20 digits>.enc`: zstd JSON
//! sealed with XChaCha20-Poly1305 under a key derived from the folder's
//! metadata key (associated data: vault, folder, device, time), like the
//! access records (`access_sync`). Readers merge the newest record of every
//! device.

use super::data_moves::WriteTargets;
use super::*;
use crate::import::{
    self, hashes::Hasher, Check, Damage, Delivery, Holder, ImportBook, ImportSource, Imported,
    ListedItem, Note, Removal, RunRecord, SourceInfo, TreeEntry, Verdict, Wanted,
};
use sha2::Digest;
use std::io::Read;

const PREFIX: &str = "vault/imports/";
/// Save state, ledger events and book at least this often during a run.
const SAVE_EVERY_SECS: u64 = 20;
const SAVE_EVERY_ITEMS: u64 = 500;
/// Publish the folder's manifest and the book at least this often.
const PUBLISH_EVERY_SECS: u64 = 600;
/// Uploads in flight per imported file.
const IMPORT_UPLOADERS: usize = 4;
/// How many examples of each kind a report names.
const EXAMPLES: usize = 25;

#[derive(Clone, Debug, Default)]
pub struct ImportOptions {
    /// The folder to create or continue (default: from the source).
    pub folder: Option<String>,
    /// Where the folder is attached on this device when it is not yet.
    pub dest: Option<PathBuf>,
    /// Attach selectively: imported files are placeholders here.
    pub selective: bool,
    /// List and plan only; nothing is written anywhere.
    pub dry_run: bool,
    /// The source's files will be removed afterwards (local directories):
    /// the source is checked for being safe to empty before anything starts.
    pub remove_source: bool,
    /// Do not check content against the source's hashes (faster; the
    /// import then says nothing about damage at the source).
    pub no_verify: bool,
    /// Without `dest`: a folder that is not attached here goes to
    /// `default_parent/<folder name>`.
    pub default_parent: Option<PathBuf>,
    /// Where a source that downloads (rclone) keeps the files of a batch
    /// until they are in the folder. Default: `.varsto-import-staging` in
    /// the folder's directory, so that the downloads land on the same
    /// filesystem as the folder (and not on the system disk).
    pub staging: Option<PathBuf>,
}

/// The staging directory in a folder's directory (hidden from scans like
/// every `.varsto` name).
pub const STAGING_DIR: &str = ".varsto-import-staging";

/// Removes a staging directory when the import ends, however it ends.
struct StagingGuard {
    dir: PathBuf,
    /// Created by the import (the default place): removed whole. A
    /// directory named with `--staging` is emptied of what the source put
    /// there, and removed only when the import made it.
    own: bool,
    existed: bool,
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.own {
            let _ = fs::remove_dir_all(&self.dir);
        } else if !self.existed {
            let _ = fs::remove_dir(&self.dir);
        }
    }
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct ImportReport {
    pub folder: String,
    pub kind: String,
    pub source: String,
    /// This copy of the source (git-annex: the repository's description).
    pub source_name: String,
    pub created_folder: bool,
    pub dry_run: bool,
    pub tree_ref: String,
    pub files_listed: u64,
    pub ids_total: u64,
    /// Read now and put into the vault.
    pub imported_ids: u64,
    pub imported_files: u64,
    pub imported_bytes: u64,
    /// Of those, without a hash to check them against (WORM and URL keys,
    /// remotes without hashes).
    pub unverified_ids: u64,
    /// In the vault before this run.
    pub already_ids: u64,
    /// New paths for content that was in the vault: no reading needed.
    pub linked_files: u64,
    /// Would be read (dry run) or were left to read (stopped).
    pub to_read_ids: u64,
    pub to_read_bytes: u64,
    pub damaged: Vec<DamagedItem>,
    pub failed: Vec<Note>,
    pub failed_count: u64,
    /// Awaiting import: content not readable here.
    pub missing_ids: u64,
    pub missing_files: u64,
    pub missing_bytes: u64,
    /// Other copies of the source said to hold missing content, the most
    /// useful first (git-annex location logs; they may be out of date).
    pub holders: Vec<Holder>,
    /// Missing content no other copy claims to hold.
    pub unclaimed_ids: u64,
    pub skipped: Vec<Note>,
    pub skipped_count: u64,
    pub warnings: Vec<Note>,
    /// Paths imported with their original names that a Windows device
    /// writes under a mapped local name (`:`, `?`, `CON.txt`, ...: see
    /// `crate::names`). For information only: nothing is renamed.
    pub mapped_on_windows: u64,
    /// Paths changed or deleted in Varsto since they were imported: kept.
    pub kept_in_varsto: Vec<Note>,
    pub kept_in_varsto_count: u64,
    /// Paths that were listed before and are gone from the source now
    /// (never deleted in Varsto).
    pub gone_at_source: u64,
    pub gone_examples: Vec<String>,
    /// Local directories: what removing the source files would do / did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<ImportCleanupReport>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DamagedItem {
    pub id: String,
    pub path: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ImportStatus {
    pub folder: String,
    pub kind: String,
    pub source: String,
    pub identity: Vec<String>,
    pub tree_ref: String,
    pub tree_utc: i64,
    pub files_total: u64,
    pub files_awaiting: u64,
    pub ids_total: u64,
    pub ids_imported: u64,
    pub ids_missing: u64,
    pub bytes_total: u64,
    pub bytes_missing: u64,
    /// Content seen damaged on some copy and not imported from another yet.
    pub ids_damaged: u64,
    pub damaged_copies: u64,
    pub gone_at_source: u64,
    pub runs: Vec<(String, RunRecord)>,
    pub holders: Vec<Holder>,
    pub removed_files: u64,
    pub removed_bytes: u64,
    pub source_path: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MissingFile {
    pub path: String,
    pub id: String,
    pub size: u64,
    /// Copies of the source said to hold it (names).
    pub holders: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ImportVerify {
    pub folder: String,
    /// Every file of the source's list is in the folder with the imported
    /// content, every block is on a storage, and the policy is met.
    pub complete: bool,
    pub files_total: u64,
    pub files_ok: u64,
    pub files_awaiting: u64,
    pub files_changed_in_varsto: u64,
    pub blocks_without_storage_copy: u64,
    pub policy: Option<PolicyReport>,
    /// Per copy of the source (disk): (name, location, everything it held is imported).
    pub copies: Vec<(String, String, bool)>,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct ImportCleanupReport {
    pub folder: String,
    pub source: String,
    pub applied: bool,
    pub removed: Vec<CleanupFile>,
    pub removed_bytes: u64,
    pub eligible: u64,
    pub eligible_bytes: u64,
    pub waiting: Vec<CleanupFile>,
    pub waiting_count: u64,
    pub dirs_removed: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CleanupFile {
    pub path: String,
    pub size: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

#[derive(Serialize, Deserialize)]
struct BookRecord {
    device: DeviceId,
    folder: FolderId,
    written_utc: i64,
    book: ImportBook,
}

fn record_key(meta: &SecretKey, folder: &FolderId) -> SecretKey {
    meta.derive("import-book", &[folder.as_str().as_bytes()])
}

fn record_aad(vault: &VaultId, folder: &FolderId, device: &DeviceId, written: i64) -> Vec<u8> {
    crypto::aad(
        "import-book",
        &[
            vault.as_str().as_bytes(),
            folder.as_str().as_bytes(),
            device.as_str().as_bytes(),
            &written.to_le_bytes(),
        ],
    )
}

/// One group of paths sharing a content id.
struct Group {
    id: String,
    paths: Vec<usize>,
    size: Option<u64>,
    check: Option<Check>,
}

/// Everything one read of one content id needs, apart from the engine.
struct IngestCtx {
    folder: FolderId,
    vault: VaultId,
    fk: FolderKeys,
    storages: OpenStorages,
    targets: WriteTargets,
    view: LedgerView,
    /// Storages left out for the rest of the run (a pool with no disk).
    unavailable: BTreeSet<String>,
    /// (object, storage) written or found during this run.
    stored: HashSet<(ObjectName, String)>,
    /// Chunks the folder references, with their object and key epoch.
    known: HashMap<ChunkId, ChunkRef>,
    chunker: ChunkerParams,
    small_chunker: Option<ChunkerParams>,
    /// A full copy is kept here: the device holds the plain content.
    full: bool,
}

enum IngestOutcome {
    Ok(Ingested),
    Mismatch(String),
    ReadFailed(String),
}

struct Ingested {
    hash: String,
    size: u64,
    chunks: Vec<ChunkRef>,
    sha256: Option<String>,
    verified: bool,
    events: Vec<Event>,
}

/// Reads through, feeding the hashes and an optional copy.
struct Tap<'a> {
    inner: &'a mut dyn Read,
    check: Option<Hasher>,
    sha: Option<sha2::Sha256>,
    copy: Option<std::io::BufWriter<fs::File>>,
    count: u64,
    copy_error: Option<std::io::Error>,
}

impl Read for Tap<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        let data = &buf[..n];
        if let Some(h) = self.check.as_mut() {
            h.update(data);
        }
        if let Some(h) = self.sha.as_mut() {
            Digest::update(h, data);
        }
        if let Some(c) = self.copy.as_mut() {
            if let Err(e) = c.write_all(data) {
                self.copy_error.get_or_insert(e);
            }
        }
        self.count += n as u64;
        Ok(n)
    }
}

struct Job {
    index: usize,
    object: ObjectName,
    ct: Vec<u8>,
    targets: Vec<usize>,
}

/// Chunk, encrypt and store one content, checking its hash. Nothing of it
/// counts (no events, no file) unless the whole content matched.
fn ingest(
    ctx: &mut IngestCtx,
    reader: &mut dyn Read,
    size_hint: Option<u64>,
    check: Option<&Check>,
    want_sha256: bool,
    copy_to: Option<&Path>,
) -> Result<IngestOutcome> {
    let mut tap = Tap {
        inner: reader,
        check: check.and_then(|c| Hasher::new(&c.algo)),
        sha: want_sha256.then(sha2::Sha256::new),
        copy: match copy_to {
            Some(p) => {
                // Exclusive and private: a leftover of ours is cleared first,
                // anything else under that unguessable name is an error.
                let _ = fs::remove_file(p);
                Some(std::io::BufWriter::new(util::create_new_private(p)?))
            }
            None => None,
        },
        count: 0,
        copy_error: None,
    };
    let verified = tap.check.is_some();
    let params = match (size_hint, ctx.small_chunker) {
        (_, Some(p)) => p,
        (Some(s), None) => ChunkerParams::for_size(s),
        (None, None) => ctx.chunker,
    };
    let mut hasher = KeyedHasher::new(&ctx.fk.hash);
    let mut chunks: Vec<ChunkRef> = Vec::new();
    let mut read_error: Option<String> = None;
    // (chunk index, storage index, outcome)
    let mut results: Vec<(usize, usize, Result<bool>)> = Vec::new();
    {
        let ctx_ref = &*ctx;
        let storages = &ctx_ref.storages;
        let (job_tx, job_rx) = std::sync::mpsc::sync_channel::<Job>(IMPORT_UPLOADERS * 2);
        let job_rx = std::sync::Mutex::new(job_rx);
        let (done_tx, done_rx) = std::sync::mpsc::channel::<(usize, usize, Result<bool>)>();
        std::thread::scope(|s| -> Result<()> {
            let job_tx = job_tx;
            for _ in 0..IMPORT_UPLOADERS {
                let (job_rx, done_tx) = (&job_rx, done_tx.clone());
                s.spawn(move || loop {
                    let job = match job_rx.lock().unwrap().recv() {
                        Ok(j) => j,
                        Err(_) => break,
                    };
                    for t in &job.targets {
                        let r = storages[*t]
                            .1
                            .put_if_absent(&chunk_storage_key(&job.object), &job.ct);
                        let _ = done_tx.send((job.index, *t, r));
                    }
                });
            }
            drop(done_tx);
            let chunker =
                Chunker::new(std::io::BufReader::with_capacity(1 << 20, &mut tap), params)?;
            for chunk in chunker {
                let chunk = match chunk {
                    Ok(c) => c,
                    Err(e) => {
                        read_error = Some(format!("read error: {e}"));
                        break;
                    }
                };
                hasher.update(&chunk);
                let chunk_id = ChunkId::from_bytes(&crypto::keyed_hash(&ctx_ref.fk.hash, &chunk));
                let mut ct: Option<Vec<u8>> = None;
                let (object, epoch) = match ctx_ref.known.get(&chunk_id) {
                    Some(c) if c.size == chunk.len() as u64 => (c.object.clone(), c.epoch),
                    _ => {
                        let e = ctx_ref.fk.epoch;
                        let sealed = crate::chunk_seal::seal_chunk(
                            &ctx_ref.fk,
                            &ctx_ref.vault,
                            &chunk_id,
                            e,
                            &chunk,
                        )?;
                        let o = ObjectName::from_bytes(&crypto::hash(&sealed));
                        ct = Some(sealed);
                        (o, e)
                    }
                };
                let record = ctx_ref
                    .view
                    .locate(&ctx_ref.folder, &chunk_id)
                    .filter(|r| r.object == object);
                let targets: Vec<usize> = storages
                    .iter()
                    .enumerate()
                    .filter(|(_, (spec, _))| {
                        !spec.is_carrier()
                            && !ctx_ref.unavailable.contains(spec.name())
                            && ctx_ref.targets.wants(spec.name(), record)
                            && !record.is_some_and(|r| {
                                r.storages
                                    .get(spec.name())
                                    .is_some_and(|l| !l.claimed_by.is_empty())
                            })
                            && !ctx_ref
                                .stored
                                .contains(&(object.clone(), spec.name().to_string()))
                    })
                    .map(|(i, _)| i)
                    .collect();
                let index = chunks.len();
                chunks.push(ChunkRef {
                    chunk: chunk_id.clone(),
                    object: object.clone(),
                    size: chunk.len() as u64,
                    epoch,
                });
                if !targets.is_empty() {
                    let ct = match ct {
                        Some(c) => c,
                        None => crate::chunk_seal::seal_chunk(
                            &ctx_ref.fk,
                            &ctx_ref.vault,
                            &chunk_id,
                            epoch,
                            &chunk,
                        )?,
                    };
                    if job_tx
                        .send(Job {
                            index,
                            object,
                            ct,
                            targets,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            }
            drop(job_tx);
            results.extend(done_rx.iter());
            Ok(())
        })?;
    }
    let count = tap.count;
    let check_hex = tap.check.take().map(|h| h.finish_hex());
    let sha = tap.sha.take().map(|h| hex::encode(h.finalize()));
    let copy_error = tap.copy_error.take();
    if let Some(mut c) = tap.copy.take() {
        c.flush()?;
        c.get_ref().sync_all()?;
    }
    if let Some(e) = copy_error {
        return Err(anyhow!("write the local copy: {e}"));
    }
    // What the storages said.
    let mut storage_error: Option<anyhow::Error> = None;
    let mut written: Vec<(usize, usize)> = Vec::new();
    let mut ok: Vec<(usize, usize)> = Vec::new();
    for (index, t, r) in results {
        match r {
            Ok(new) => {
                if new {
                    written.push((index, t));
                }
                ok.push((index, t));
            }
            Err(e)
                if matches!(
                    pool::pool_error(&e),
                    Some(PoolError::NoDiskAttached { .. } | PoolError::NoRoom { .. })
                ) =>
            {
                ctx.unavailable.insert(ctx.storages[t].0.name().to_string());
            }
            Err(e) => {
                storage_error.get_or_insert(e);
            }
        }
    }
    let wrong = if let Some(e) = read_error {
        Some(IngestOutcome::ReadFailed(e))
    } else if let Some(want) = size_hint.filter(|s| *s != count) {
        Some(IngestOutcome::Mismatch(format!(
            "{count} bytes where {want} were expected"
        )))
    } else {
        match (check, check_hex) {
            (Some(c), Some(got)) if got != c.hex => Some(IngestOutcome::Mismatch(format!(
                "{} is {got}, expected {}",
                c.algo, c.hex
            ))),
            _ => None,
        }
    };
    if let Some(w) = wrong {
        // Objects this content alone put on the storages go again.
        for (index, t) in written {
            let _ = ctx.storages[t]
                .1
                .delete(&chunk_storage_key(&chunks[index].object));
        }
        if let Some(e) = storage_error {
            return Err(e);
        }
        return Ok(w);
    }
    if let Some(e) = storage_error {
        return Err(e);
    }
    let mut events = Vec::new();
    let mut held: HashSet<usize> = HashSet::new();
    for (index, t) in ok {
        let c = &chunks[index];
        let name = ctx.storages[t].0.name().to_string();
        ctx.stored.insert((c.object.clone(), name.clone()));
        held.insert(index);
        events.push(Event::ChunkStored {
            folder: ctx.folder.clone(),
            chunk: c.chunk.clone(),
            object: c.object.clone(),
            storage: name,
            size: c.size,
        });
    }
    for (index, c) in chunks.iter().enumerate() {
        let elsewhere = held.contains(&index)
            || ctx
                .view
                .locate(&ctx.folder, &c.chunk)
                .filter(|r| r.object == c.object)
                .is_some_and(|r| r.storages.values().any(|l| !l.claimed_by.is_empty()))
            || ctx.storages.iter().any(|(s, _)| {
                ctx.stored
                    .contains(&(c.object.clone(), s.name().to_string()))
            });
        if ctx.full {
            events.push(Event::ChunkOnDevice {
                folder: ctx.folder.clone(),
                chunk: c.chunk.clone(),
                object: c.object.clone(),
                size: c.size,
            });
        } else if !elsewhere {
            bail!("no storage took the blocks: check that a storage is reachable (and that a pool has a disk attached)");
        }
        ctx.known
            .entry(c.chunk.clone())
            .or_insert_with(|| c.clone());
    }
    Ok(IngestOutcome::Ok(Ingested {
        hash: hex::encode(hasher.finalize()),
        size: count,
        chunks,
        sha256: sha,
        verified,
        events,
    }))
}

fn push_example(list: &mut Vec<Note>, count: &mut u64, note: Note) {
    *count += 1;
    if list.len() < EXAMPLES {
        list.push(note);
    }
}

impl Engine {
    // ----- the book --------------------------------------------------------------

    fn book_path(&self, folder: &FolderId) -> PathBuf {
        self.home
            .join("state")
            .join("imports")
            .join(format!("{folder}.json"))
    }

    fn load_book(&self, folder: &FolderId) -> Option<ImportBook> {
        util::read_json::<ImportBook>(&self.book_path(folder)).ok()
    }

    fn save_book(&self, folder: &FolderId, book: &ImportBook) -> Result<()> {
        let p = self.book_path(folder);
        if let Some(d) = p.parent() {
            fs::create_dir_all(d)?;
        }
        util::write_json(&p, book)
    }

    /// Publish this device's book of a folder, replacing its older record.
    fn publish_book(&self, rec: &FolderRecord, book: &ImportBook) -> Result<()> {
        let storages = self.metadata_storages(false)?;
        if storages.is_empty() {
            return Ok(());
        }
        let fk = self.folder_keys(rec)?;
        let me = &self.vault.device_id;
        let marker = self
            .home
            .join("state")
            .join("imports")
            .join(format!("{}.published", rec.folder_id));
        let last: i64 = util::read_json_or_default(&marker).unwrap_or(0);
        let written = util::now_utc().max(last + 1);
        let body = BookRecord {
            device: me.clone(),
            folder: rec.folder_id.clone(),
            written_utc: written,
            book: book.clone(),
        };
        let packed = zstd::bulk::compress(&serde_json::to_vec(&body)?, 3)?;
        let blob = crypto::encrypt(
            &record_key(&fk.meta, &rec.folder_id),
            &record_aad(&self.vault.vault_id, &rec.folder_id, me, written),
            &packed,
        )?;
        let key = format!("{PREFIX}{}/{me}/{written:020}.enc", rec.folder_id);
        let own = format!("{PREFIX}{}/{me}/", rec.folder_id);
        for (_, b) in &storages {
            b.put_if_absent(&key, &blob)?;
            for old in b.list(&own)? {
                if old != key {
                    let _ = b.delete(&old);
                }
            }
        }
        util::write_json(&marker, &written)
    }

    /// Read the other devices' books of every folder and merge them into
    /// this device's.
    fn refresh_books(&mut self) -> Result<()> {
        let storages = self.metadata_storages(false)?;
        // (folder, device) -> (written, storage index, key)
        let mut newest: BTreeMap<(String, DeviceId), (i64, usize, String)> = BTreeMap::new();
        for (i, (_, b)) in storages.iter().enumerate() {
            let Ok(keys) = b.list(PREFIX) else {
                continue;
            };
            for key in keys {
                let Some(rest) = key.strip_prefix(PREFIX) else {
                    continue;
                };
                let mut parts = rest.split('/');
                let (Some(folder), Some(dev), Some(file)) =
                    (parts.next(), parts.next(), parts.next())
                else {
                    continue;
                };
                let (Ok(dev), Some(t)) = (
                    DeviceId::from_hex(dev),
                    file.strip_suffix(".enc")
                        .and_then(|t| t.parse::<i64>().ok()),
                ) else {
                    continue;
                };
                if dev == self.vault.device_id || self.is_revoked(&dev) {
                    continue;
                }
                let k = (folder.to_string(), dev);
                if newest.get(&k).is_none_or(|(n, _, _)| t > *n) {
                    newest.insert(k, (t, i, key));
                }
            }
        }
        for ((folder, dev), (t, i, key)) in newest {
            let Some(rec) = self
                .keyring
                .folders
                .values()
                .find(|r| r.folder_id.as_str() == folder && !r.is_removed())
                .cloned()
            else {
                continue;
            };
            let Ok(rec) = self.with_key(&rec) else {
                continue;
            };
            let fk = self.folder_keys(&rec)?;
            let Some(blob) = storages[i].1.get(&key)? else {
                continue;
            };
            let aad = record_aad(&self.vault.vault_id, &rec.folder_id, &dev, t);
            let Some(packed) = fk
                .meta_keys()
                .iter()
                .find_map(|m| crypto::decrypt(&record_key(m, &rec.folder_id), &aad, &blob).ok())
            else {
                continue;
            };
            let Ok(json) = zstd::bulk::decompress(&packed, 1 << 30) else {
                continue;
            };
            let Ok(body) = serde_json::from_slice::<BookRecord>(&json) else {
                continue;
            };
            if body.device != dev || body.folder != rec.folder_id || body.written_utc != t {
                continue;
            }
            let mut mine = self.load_book(&rec.folder_id).unwrap_or_default();
            let before = mine.clone();
            mine.merge(&body.book);
            if mine != before {
                self.save_book(&rec.folder_id, &mine)?;
            }
        }
        Ok(())
    }

    /// The live folder whose book names this source.
    fn folder_of_source(&self, info: &SourceInfo) -> Option<FolderRecord> {
        self.keyring
            .folders
            .values()
            .filter(|r| !r.is_removed() && !r.is_backup())
            .find(|r| {
                self.load_book(&r.folder_id)
                    .is_some_and(|b| b.matches(info))
            })
            .cloned()
    }

    /// Refuse sources that must not be imported or emptied: Varsto's own
    /// folders and directories.
    fn check_source_path(&self, src: &Path, remove: bool) -> Result<()> {
        let inside = |a: &Path, b: &Path| a.starts_with(b) || b.starts_with(a);
        if let Ok(home) = canonical(&self.home) {
            if src.starts_with(&home) || home.starts_with(src) {
                bail!(
                    "{} holds this device's Varsto home ({}); it cannot be imported",
                    src.display(),
                    home.display()
                );
            }
        }
        for m in &self.config.folders {
            if inside(src, &m.path) {
                let name = self
                    .keyring
                    .folders
                    .get(&m.folder_id)
                    .map(|r| r.name.clone())
                    .unwrap_or_default();
                bail!(
                    "{} overlaps the Varsto folder {name} attached at {}; it is already in Varsto",
                    src.display(),
                    m.path.display()
                );
            }
        }
        if remove
            && (src.join(".git").join("annex").exists()
                || src.join("annex").join("objects").is_dir())
        {
            bail!(
                "{} is a git-annex repository: import it with `varsto import git-annex` (which never removes anything) instead",
                src.display()
            );
        }
        Ok(())
    }

    // ----- a run -------------------------------------------------------------------

    /// Import `source` into its folder (see the module documentation).
    pub fn import_run(
        &mut self,
        source: &mut dyn ImportSource,
        opts: &ImportOptions,
    ) -> Result<ImportReport> {
        self.ensure_active()?;
        if self.vault.member {
            bail!("a member device cannot create or fill folders of the owner's vault");
        }
        let info = source.info().clone();
        let _ = self.pull_registry();
        let _ = self.refresh_books();
        let existing = self.folder_of_source(&info);
        if let Some(src) = &info.local_path {
            if info.kind == import::KIND_DIR || opts.remove_source {
                self.check_source_path(src, opts.remove_source)?;
            }
            if let Some(dest) = &opts.dest {
                // Resolved like the source (macOS: /var is /private/var),
                // through the part of the path that exists already.
                let d = resolve_existing(&std::path::absolute(dest)?);
                if d.starts_with(src) || src.starts_with(&d) {
                    bail!(
                        "the destination {} and the source {} overlap",
                        d.display(),
                        src.display()
                    );
                }
            }
        }
        if opts.remove_source && info.kind != import::KIND_DIR {
            bail!("only local directories can be removed after an import");
        }
        let name = match (&existing, &opts.folder) {
            (Some(rec), Some(want)) if rec.name.to_lowercase() != want.trim().to_lowercase() => bail!(
                "this source was imported into folder {} before; leave out --folder to continue there",
                rec.name
            ),
            (Some(rec), _) => rec.name.clone(),
            (None, want) => {
                let name = want
                    .clone()
                    .unwrap_or_else(|| info.default_folder.clone())
                    .trim()
                    .to_string();
                if let Some(f) = self.keyring.folders.values().find(|f| {
                    !f.is_removed() && f.name.to_lowercase() == name.to_lowercase()
                }) {
                    bail!(
                        "the vault already has a folder named {} that holds other data; choose a name with --folder",
                        f.name
                    );
                }
                name
            }
        };
        let mut report = ImportReport {
            folder: name.clone(),
            kind: info.kind.to_string(),
            source: info.display.clone(),
            source_name: info.instance_name.clone(),
            created_folder: existing.is_none(),
            dry_run: opts.dry_run,
            ..Default::default()
        };
        let task = activity::start(activity::IMPORT, &name, 0, activity::Unit::Items);
        // Attach (or create) the folder here, and bring it up to date.
        let mut rec_root: Option<(FolderRecord, PathBuf)> = None;
        if !opts.dry_run {
            let attached = existing.as_ref().and_then(|r| {
                self.config
                    .folders
                    .iter()
                    .find(|m| m.folder_id == r.folder_id)
                    .map(|m| m.path.clone())
            });
            match (&existing, attached) {
                (Some(_), Some(_)) => {
                    self.pull(&name)?;
                }
                (Some(rec), None) => {
                    let dest = dest_for(opts, &rec.name).ok_or_else(|| {
                        anyhow!("folder {} is not attached here: give --dest (and --selective for placeholders only)", rec.name)
                    })?;
                    self.attach_folder(&rec.name, &dest, opts.selective)?;
                    self.pull(&name)?;
                }
                (None, _) => {
                    let dest = dest_for(opts, &name).ok_or_else(|| {
                        anyhow!("give --dest for the new folder (and --selective for placeholders only)")
                    })?;
                    // (A staging directory left by an import that was
                    // stopped does not count.)
                    if dest.exists()
                        && fs::read_dir(&dest)?
                            .flatten()
                            .any(|e| !e.file_name().to_string_lossy().starts_with(".varsto"))
                    {
                        bail!(
                            "{} is not empty; the new folder needs an empty directory",
                            dest.display()
                        );
                    }
                    self.add_folder(&name, &dest)?;
                    if opts.selective {
                        self.set_selective(&name, true)?;
                    }
                }
            }
            let (rec, root) = self.resolve_folder(&name)?;
            if self.mount_is_encrypted(&rec.folder_id) {
                bail!("folder {name} is kept encrypted on this device; import on a device where it is a plain folder");
            }
            rec_root = Some((rec, root));
        }
        // Downloads are staged on the folder's filesystem (or where
        // --staging says), and the staging directory goes afterwards.
        let _staging = match &rec_root {
            Some((_, root)) => {
                let (dir, own) = match &opts.staging {
                    Some(s) => (std::path::absolute(s)?, false),
                    None => (root.join(STAGING_DIR), true),
                };
                source.stage_in(&dir)?;
                let existed = dir.exists();
                Some(StagingGuard { dir, own, existed })
            }
            None => None,
        };
        let folder_id = rec_root
            .as_ref()
            .map(|(r, _)| r.folder_id.clone())
            .or_else(|| existing.as_ref().map(|r| r.folder_id.clone()));
        let mut state = match &folder_id {
            Some(f) => self.load_state(f)?,
            None => FolderState::default(),
        };
        let mut book = folder_id
            .as_ref()
            .and_then(|f| self.load_book(f))
            .unwrap_or_default();
        if book.kind.is_empty() {
            book.kind = info.kind.to_string();
            book.display = info.display.clone();
        }
        book.identity.extend(info.identity.iter().cloned());
        for (u, d) in &info.repositories {
            book.repositories.insert(u.clone(), d.clone());
        }
        book.dead.extend(info.dead.iter().cloned());
        if info.kind == import::KIND_DIR {
            book.source_path = info.local_path.as_ref().map(|p| p.display().to_string());
        }

        // ----- list ------------------------------------------------------------
        task.step("list", 0, activity::Unit::Items);
        let listing = source.list()?;
        report.tree_ref = listing.tree_ref.clone();
        report.files_listed = listing.items.len() as u64;
        report.skipped_count = listing.skipped.len() as u64;
        report.skipped = listing.skipped.iter().take(EXAMPLES).cloned().collect();
        report.warnings = listing.warnings.iter().take(EXAMPLES).cloned().collect();
        report.mapped_on_windows = listing
            .items
            .iter()
            .filter(|i| crate::names::mapped_on_windows(&i.path))
            .count() as u64;
        let items: Vec<ListedItem> = listing.items;
        let selective = folder_id
            .as_ref()
            .map(|f| self.mount_is_selective(f))
            .unwrap_or(opts.selective);
        let root = rec_root.as_ref().map(|(_, r)| r.clone());

        // ----- plan ------------------------------------------------------------
        let old_tree = book.tree.clone();
        let mut by_hash: HashMap<String, String> = HashMap::new();
        for f in state.files.values().filter(|f| !f.deleted && f.size > 0) {
            by_hash
                .entry(f.content_hash.clone())
                .or_insert_with(|| f.path.clone());
        }
        let mut groups: BTreeMap<String, Group> = BTreeMap::new();
        let mut links: Vec<(usize, String)> = Vec::new(); // (item, path holding the content)
        let mut missing: BTreeMap<String, (u64, Vec<usize>)> = BTreeMap::new();
        let mut already: BTreeSet<String> = BTreeSet::new();
        let mut ids: BTreeSet<&str> = BTreeSet::new();
        for (i, item) in items.iter().enumerate() {
            ids.insert(&item.id);
            let imported = book.imported.get(&item.id);
            let prev_hash = old_tree
                .get(&item.path)
                .and_then(|p| book.imported.get(&p.id))
                .map(|x| x.hash.as_str());
            if let Some(sf) = state.files.get(&item.path) {
                if !sf.deleted {
                    if imported.is_some_and(|x| x.hash == sf.content_hash) {
                        already.insert(item.id.clone());
                        continue;
                    }
                    if prev_hash != Some(sf.content_hash.as_str()) {
                        push_example(
                            &mut report.kept_in_varsto,
                            &mut report.kept_in_varsto_count,
                            Note {
                                path: item.path.clone(),
                                reason: "a different file is at this path in Varsto (changed since the import, or there before it); left as is".into(),
                            },
                        );
                        continue;
                    }
                } else if old_tree.get(&item.path).is_some_and(|p| p.id == item.id) {
                    push_example(
                        &mut report.kept_in_varsto,
                        &mut report.kept_in_varsto_count,
                        Note {
                            path: item.path.clone(),
                            reason: "deleted in Varsto after it was imported; not imported again"
                                .into(),
                        },
                    );
                    continue;
                }
            } else if let Some(r) = &root {
                let disk = self.disk_of(r, &state, &item.path);
                if disk.exists() || placeholder_path(&disk).exists() {
                    push_example(
                        &mut report.kept_in_varsto,
                        &mut report.kept_in_varsto_count,
                        Note {
                            path: item.path.clone(),
                            reason: "a file Varsto does not know yet is in the way in the folder here; left as is".into(),
                        },
                    );
                    continue;
                }
            }
            if let Some(x) = imported {
                if let Some(holder) = by_hash.get(&x.hash) {
                    already.insert(item.id.clone());
                    links.push((i, holder.clone()));
                    continue;
                }
            }
            if item.present {
                let g = groups.entry(item.id.clone()).or_insert_with(|| Group {
                    id: item.id.clone(),
                    paths: Vec::new(),
                    size: item.size,
                    check: if opts.no_verify {
                        None
                    } else {
                        item.check.clone()
                    },
                });
                g.paths.push(i);
            } else {
                let m = missing
                    .entry(item.id.clone())
                    .or_insert((item.size.unwrap_or(0), Vec::new()));
                m.1.push(i);
            }
        }
        report.ids_total = ids.len() as u64;
        report.already_ids = already.len() as u64;
        report.to_read_ids = groups.len() as u64;
        report.to_read_bytes = groups.values().map(|g| g.size.unwrap_or(0)).sum();
        // The new file list, and what left the source.
        let mut new_tree: BTreeMap<String, TreeEntry> = BTreeMap::new();
        for item in &items {
            new_tree.insert(
                item.path.clone(),
                TreeEntry {
                    id: item.id.clone(),
                    size: item.size.unwrap_or(0),
                    mtime_ns: item.mtime_ns.unwrap_or(0),
                },
            );
        }
        let mut gone: BTreeSet<String> = book
            .gone_at_source
            .iter()
            .chain(old_tree.keys())
            .filter(|p| !new_tree.contains_key(*p))
            .cloned()
            .collect();
        report.gone_at_source = gone.len() as u64;
        report.gone_examples = gone.iter().take(EXAMPLES).cloned().collect();

        let finish_missing =
            |report: &mut ImportReport, missing: &BTreeMap<String, (u64, Vec<usize>)>| {
                report.missing_ids = missing.len() as u64;
                report.missing_files = missing.values().map(|m| m.1.len() as u64).sum();
                report.missing_bytes = missing.values().map(|m| m.0).sum();
            };
        if opts.dry_run {
            report.linked_files = links.len() as u64;
            finish_missing(&mut report, &missing);
            return Ok(report);
        }
        let (rec, root) = rec_root.expect("attached above");
        let root_path = root.clone();
        book.tree = new_tree;
        book.tree_ref = listing.tree_ref;
        book.tree_utc = util::now_utc();
        book.gone_at_source = std::mem::take(&mut gone);
        self.save_book(&rec.folder_id, &book)?;

        // ----- links: content already in the vault ------------------------
        for (i, holder) in &links {
            let item = &items[*i];
            let Some(template) = state.files.get(holder).cloned() else {
                continue;
            };
            let mtime = item.mtime_ns.unwrap_or(template.mtime);
            let local_source =
                Some(self.disk_of(&root_path, &state, holder)).filter(|p| p.is_file());
            let disk = self.place(&root_path, &mut state, &item.path, None)?;
            let mut local_entry = None;
            if !selective {
                if let Some(src) = local_source {
                    crate::freespace::check(
                        &crate::freespace::Place::folder(&rec.name),
                        &root_path,
                        self.folder_min_free(&rec.folder_id),
                        template.size,
                    )?;
                    if let Some(p) = disk.parent() {
                        fs::create_dir_all(p)?;
                    }
                    fs::copy(&src, &disk)?;
                    set_mtime(&disk, mtime)?;
                    local_entry = Some(index_entry(&disk, &template.content_hash)?);
                }
            }
            let fs_state = self.put_imported(
                &mut state,
                &item.path,
                template.size,
                mtime,
                &template.content_hash,
                template.chunks.clone(),
            )?;
            match local_entry {
                Some(e) => {
                    state.local_index.insert(item.path.clone(), e);
                }
                None => Self::write_placeholder(&disk, &fs_state)?,
            }
            report.linked_files += 1;
        }

        // ----- read ------------------------------------------------------------
        let wanted: Vec<Wanted> = groups
            .values()
            .map(|g| Wanted {
                id: g.id.clone(),
                path: items[g.paths[0]].path.clone(),
                size: g.size,
            })
            .collect();
        let group_list: Vec<&Group> = groups.values().collect();
        task.step("read", report.to_read_bytes, activity::Unit::Bytes);
        let fk = self.folder_keys(&rec)?;
        // File metadata as a scan would record it (`crate::fsmeta`).
        let meta_settings = self.meta_settings(&rec.folder_id);
        let mut known: HashMap<ChunkId, ChunkRef> = HashMap::new();
        for f in state.files.values().chain(state.pending_remote.values()) {
            for c in &f.chunks {
                known.insert(c.chunk.clone(), c.clone());
            }
        }
        let mut ctx = IngestCtx {
            folder: rec.folder_id.clone(),
            vault: self.vault.vault_id.clone(),
            fk,
            storages: self.open_storages(false)?,
            targets: self.write_targets(&rec),
            view: self.view()?,
            unavailable: BTreeSet::new(),
            stored: HashSet::new(),
            known,
            chunker: self.chunker,
            small_chunker: (self.chunker != ChunkerParams::DEFAULT).then_some(self.chunker),
            full: !selective,
        };
        let want_sha = source.wants_source_hash();
        let instance = info.instance.clone();
        let mut run = RunRecord {
            name: info.instance_name.clone(),
            location: info.display.clone(),
            device: self.vault.device_id.as_str().to_string(),
            last_utc: util::now_utc(),
            present: items
                .iter()
                .filter(|i| i.present)
                .map(|i| i.id.as_str())
                .collect::<BTreeSet<_>>()
                .len() as u64,
            ..Default::default()
        };
        let mut last_save = std::time::Instant::now();
        let mut last_publish = std::time::Instant::now();
        let mut since_save = 0u64;
        let tmp_copy = root_path.join(format!(
            ".varsto-import-{}-{}",
            std::process::id(),
            util::random_suffix()
        ));
        let min_free = self.folder_min_free(&rec.folder_id);
        let mut stop_error: Option<anyhow::Error> = None;
        let delivered = {
            let mut sink = |i: usize, d: Delivery| -> Result<Verdict> {
                let g = group_list[i];
                let first = &items[g.paths[0]];
                match d {
                    Delivery::Missing => {
                        let m = missing
                            .entry(g.id.clone())
                            .or_insert((g.size.unwrap_or(0), Vec::new()));
                        m.1.extend(g.paths.iter().copied());
                        Ok(Verdict::Imported)
                    }
                    Delivery::Failed(reason) => {
                        run.failed += 1;
                        push_example(
                            &mut report.failed,
                            &mut report.failed_count,
                            Note {
                                path: first.path.clone(),
                                reason,
                            },
                        );
                        Ok(Verdict::Imported)
                    }
                    Delivery::Content {
                        reader,
                        mtime_ns,
                        retry,
                    } => {
                        // A full local copy is written into the folder: the
                        // run stops (and carries on later) before its disk
                        // keeps less than its limit free.
                        if !selective {
                            if let Err(low) = crate::freespace::check(
                                &crate::freespace::Place::folder(&rec.name),
                                &root_path,
                                min_free,
                                g.size.unwrap_or(0),
                            ) {
                                stop_error = Some(low);
                                return Ok(Verdict::Stop);
                            }
                        }
                        let copy = (!selective).then_some(tmp_copy.as_path());
                        let outcome =
                            ingest(&mut ctx, reader, g.size, g.check.as_ref(), want_sha, copy);
                        let outcome = match outcome {
                            Ok(o) => o,
                            Err(e) => {
                                let _ = fs::remove_file(&tmp_copy);
                                stop_error = Some(e.context(format!("import {}", first.path)));
                                return Ok(Verdict::Stop);
                            }
                        };
                        match outcome {
                            IngestOutcome::Mismatch(detail) => {
                                let _ = fs::remove_file(&tmp_copy);
                                if !retry {
                                    run.damaged += 1;
                                    let d = Damage {
                                        from: instance.clone(),
                                        path: first.path.clone(),
                                        utc: util::now_utc(),
                                        detail: detail.clone(),
                                    };
                                    let list = book.damaged.entry(g.id.clone()).or_default();
                                    if !list
                                        .iter()
                                        .any(|x| x.from == d.from && x.detail == d.detail)
                                    {
                                        list.push(d);
                                    }
                                    if report.damaged.len() < EXAMPLES {
                                        report.damaged.push(DamagedItem {
                                            id: g.id.clone(),
                                            path: first.path.clone(),
                                            detail,
                                        });
                                    }
                                    let m = missing
                                        .entry(g.id.clone())
                                        .or_insert((g.size.unwrap_or(0), Vec::new()));
                                    m.1.extend(g.paths.iter().copied());
                                }
                                Ok(Verdict::Mismatch)
                            }
                            IngestOutcome::ReadFailed(reason) => {
                                let _ = fs::remove_file(&tmp_copy);
                                run.failed += 1;
                                push_example(
                                    &mut report.failed,
                                    &mut report.failed_count,
                                    Note {
                                        path: first.path.clone(),
                                        reason,
                                    },
                                );
                                let m = missing
                                    .entry(g.id.clone())
                                    .or_insert((g.size.unwrap_or(0), Vec::new()));
                                m.1.extend(g.paths.iter().copied());
                                Ok(Verdict::Imported)
                            }
                            IngestOutcome::Ok(done) => {
                                self.pending.extend(done.events.iter().cloned());
                                let applied = self.apply_ingested(
                                    &mut state,
                                    &root_path,
                                    selective,
                                    &tmp_copy,
                                    &items,
                                    &g.paths,
                                    &done,
                                    mtime_ns,
                                    meta_settings,
                                );
                                if let Err(e) = applied {
                                    let _ = fs::remove_file(&tmp_copy);
                                    stop_error = Some(e);
                                    return Ok(Verdict::Stop);
                                }
                                book.imported.insert(
                                    g.id.clone(),
                                    Imported {
                                        hash: done.hash.clone(),
                                        size: done.size,
                                        utc: util::now_utc(),
                                        from: instance.clone(),
                                        verified: done.verified,
                                        sha256: done.sha256.clone(),
                                    },
                                );
                                book.missing_holders.remove(&g.id);
                                report.imported_ids += 1;
                                report.imported_files += g.paths.len() as u64;
                                report.imported_bytes += done.size;
                                if !done.verified {
                                    report.unverified_ids += 1;
                                }
                                run.imported += 1;
                                run.imported_bytes += done.size;
                                task.advance(done.size);
                                since_save += 1;
                                if since_save >= SAVE_EVERY_ITEMS
                                    || last_save.elapsed().as_secs() >= SAVE_EVERY_SECS
                                {
                                    let publish =
                                        last_publish.elapsed().as_secs() >= PUBLISH_EVERY_SECS;
                                    if let Err(e) =
                                        self.import_checkpoint(&rec, &mut state, &book, publish)
                                    {
                                        stop_error = Some(e);
                                        return Ok(Verdict::Stop);
                                    }
                                    if publish {
                                        last_publish = std::time::Instant::now();
                                    }
                                    since_save = 0;
                                    last_save = std::time::Instant::now();
                                }
                                Ok(Verdict::Imported)
                            }
                        }
                    }
                }
            };
            source.deliver(&wanted, &mut sink)
        };
        let _ = fs::remove_file(&tmp_copy);
        // Whatever happened, keep what was done.
        let unread: Vec<&Group> = group_list
            .iter()
            .filter(|g| !book.imported.contains_key(&g.id) && !missing.contains_key(&g.id))
            .copied()
            .collect();
        report.to_read_ids = unread.len() as u64;
        report.to_read_bytes = unread.iter().map(|g| g.size.unwrap_or(0)).sum();
        finish_missing(&mut report, &missing);
        // Who holds what is missing (git-annex location logs).
        let missing_list: Vec<(String, u64)> = missing
            .iter()
            .map(|(id, (size, _))| (id.clone(), *size))
            .collect();
        let holders = source.holders(&missing_list).unwrap_or_default();
        let mut per: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for (id, size) in &missing_list {
            match holders.get(id) {
                Some(who) if !who.is_empty() => {
                    for u in who {
                        let e = per.entry(u.clone()).or_default();
                        e.0 += 1;
                        e.1 += size;
                    }
                }
                _ => report.unclaimed_ids += 1,
            }
        }
        book.missing_holders = holders.into_iter().filter(|(_, v)| !v.is_empty()).collect();
        report.holders = holder_list(&per, &book.repositories);
        run.complete = items
            .iter()
            .filter(|i| i.present)
            .all(|i| book.imported.contains_key(&i.id));
        run.last_utc = util::now_utc();
        book.runs.insert(instance, run);
        let saved = self.import_checkpoint(&rec, &mut state, &book, true);
        drop(task);
        if let Some(e) = stop_error {
            saved?;
            return Err(e);
        }
        delivered?;
        saved?;
        Ok(report)
    }

    /// Make the paths of one imported content files of the folder.
    #[allow(clippy::too_many_arguments)]
    fn apply_ingested(
        &mut self,
        state: &mut FolderState,
        root: &Path,
        selective: bool,
        tmp_copy: &Path,
        items: &[ListedItem],
        paths: &[usize],
        done: &Ingested,
        mtime_ns: Option<i64>,
        meta_settings: crate::fsmeta::MetaSettings,
    ) -> Result<()> {
        let mut first_disk: Option<PathBuf> = None;
        for &i in paths {
            let item = &items[i];
            let mtime = item
                .mtime_ns
                .or(mtime_ns)
                .unwrap_or_else(|| util::now_utc() * 1_000_000_000);
            // The original name, mapped where this filesystem needs it.
            let disk = self.place(root, state, &item.path, None)?;
            if let Some(p) = disk.parent() {
                fs::create_dir_all(p)?;
            }
            let fs_state = self.put_imported(
                state,
                &item.path,
                done.size,
                mtime,
                &done.hash,
                done.chunks.clone(),
            )?;
            if selective {
                Self::write_placeholder(&disk, &fs_state)?;
                continue;
            }
            match &first_disk {
                None => {
                    #[cfg(unix)]
                    if let Ok(f) = fs::File::open(tmp_copy) {
                        util::set_final_mode(&f, None);
                    }
                    fs::rename(tmp_copy, &disk)
                        .with_context(|| format!("write {}", disk.display()))?
                }
                Some(src) => {
                    fs::copy(src, &disk).with_context(|| format!("write {}", disk.display()))?;
                }
            }
            set_mtime(&disk, mtime)?;
            let mut entry = index_entry(&disk, &done.hash)?;
            // The file's metadata, as the next scan sees it: recorded with
            // the new version, so that scan finds nothing changed.
            if let Ok(md) = fs::symlink_metadata(&disk) {
                let caps = self.meta_caps;
                let obs = crate::fsmeta::observe(
                    &disk,
                    &md,
                    &caps,
                    &meta_settings,
                    &mut crate::fsmeta::Names::default(),
                );
                if let Some(f) = state.files.get_mut(&item.path).filter(|f| f.meta.is_none()) {
                    f.meta = crate::fsmeta::combine(&obs, None, None, &caps);
                }
                entry.meta_seen = Some(obs);
            }
            state.local_index.insert(item.path.clone(), entry);
            first_disk.get_or_insert(disk);
        }
        Ok(())
    }

    /// A new version of `path` with this content (none when it is already).
    fn put_imported(
        &mut self,
        state: &mut FolderState,
        path: &str,
        size: u64,
        mtime: i64,
        hash: &str,
        chunks: Vec<ChunkRef>,
    ) -> Result<FileState> {
        if let Some(prev) = state.files.get(path) {
            if !prev.deleted && prev.content_hash == hash {
                return Ok(prev.clone());
            }
        }
        let me = self.vault.device_id.clone();
        let clock = self.tick()?;
        let mut version = state
            .files
            .get(path)
            .map(|p| p.version.clone())
            .unwrap_or_default();
        version.insert(me.clone(), clock);
        let f = FileState {
            path: path.to_string(),
            version,
            deleted: false,
            size,
            mtime,
            content_hash: hash.to_string(),
            chunks,
            modified_by: me,
            modified_clock: clock,
            meta: None,
        };
        state.files.insert(path.to_string(), f.clone());
        state.pending_remote.remove(path);
        Ok(f)
    }

    /// Save what a run did so far: ledger events first, then the folder
    /// state, then the book (so the book never names content the state
    /// lacks). With `publish`, the folder's manifest and the book go to
    /// the storages too.
    fn import_checkpoint(
        &mut self,
        rec: &FolderRecord,
        state: &mut FolderState,
        book: &ImportBook,
        publish: bool,
    ) -> Result<()> {
        if publish {
            self.publish_manifest(rec, state)?;
            self.ensure_manifest_everywhere(rec, state)?;
        }
        self.commit_batch()?;
        self.save_state(&rec.folder_id, state)?;
        self.save_book(&rec.folder_id, book)?;
        if publish {
            self.publish_book(rec, book)?;
        }
        Ok(())
    }

    // ----- what an import left ------------------------------------------------------

    fn import_books(&self, folder: Option<&str>) -> Result<Vec<(FolderRecord, ImportBook)>> {
        let mut out = Vec::new();
        for rec in self
            .keyring
            .folders
            .values()
            .filter(|r| !r.is_removed() && !r.is_backup())
        {
            if let Some(f) = folder {
                if rec.name.to_lowercase() != f.to_lowercase() && rec.folder_id.as_str() != f {
                    continue;
                }
            }
            if let Some(b) = self.load_book(&rec.folder_id) {
                out.push((rec.clone(), b));
            }
        }
        if let Some(f) = folder {
            if out.is_empty() {
                bail!("folder {f} was not imported (or this device has not seen its import yet)");
            }
        }
        Ok(out)
    }

    /// Imported folders and how far each import is.
    pub fn import_status(&mut self, folder: Option<&str>) -> Result<Vec<ImportStatus>> {
        let _ = self.pull_registry();
        let _ = self.refresh_books();
        let mut out = Vec::new();
        for (rec, b) in self.import_books(folder)? {
            let state = self.load_state(&rec.folder_id)?;
            let missing = b.missing_ids();
            let mut ids: BTreeMap<&str, u64> = BTreeMap::new();
            for e in b.tree.values() {
                ids.insert(&e.id, e.size);
            }
            let awaiting = b
                .tree
                .iter()
                .filter(|(p, e)| {
                    !b.imported.contains_key(&e.id)
                        && !state.files.get(*p).is_some_and(|f| !f.deleted)
                })
                .count() as u64;
            let mut per: BTreeMap<String, (u64, u64)> = BTreeMap::new();
            for (id, who) in &b.missing_holders {
                if let Some(size) = missing.get(id.as_str()) {
                    for u in who {
                        let e = per.entry(u.clone()).or_default();
                        e.0 += 1;
                        e.1 += size;
                    }
                }
            }
            out.push(ImportStatus {
                folder: rec.name.clone(),
                kind: b.kind.clone(),
                source: b.display.clone(),
                identity: b.identity.iter().cloned().collect(),
                tree_ref: b.tree_ref.clone(),
                tree_utc: b.tree_utc,
                files_total: b.tree.len() as u64,
                files_awaiting: awaiting,
                ids_total: ids.len() as u64,
                ids_imported: ids.keys().filter(|i| b.imported.contains_key(**i)).count() as u64,
                ids_missing: missing.len() as u64,
                bytes_total: ids.values().sum(),
                bytes_missing: missing.values().sum(),
                ids_damaged: b
                    .damaged
                    .keys()
                    .filter(|k| !b.imported.contains_key(*k) && ids.contains_key(k.as_str()))
                    .count() as u64,
                damaged_copies: b.damaged.values().map(|v| v.len() as u64).sum(),
                gone_at_source: b.gone_at_source.len() as u64,
                runs: b.runs.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                holders: holder_list(&per, &b.repositories),
                removed_files: b.removals.len() as u64,
                removed_bytes: b.removals.iter().map(|r| r.size).sum(),
                source_path: b.source_path.clone(),
            });
        }
        Ok(out)
    }

    /// The paths of an imported folder still awaiting their content.
    pub fn import_missing(&mut self, folder: &str) -> Result<Vec<MissingFile>> {
        let _ = self.refresh_books();
        let (rec, b) = self
            .import_books(Some(folder))?
            .into_iter()
            .next()
            .expect("one folder");
        let state = self.load_state(&rec.folder_id)?;
        Ok(b.tree
            .iter()
            .filter(|(p, e)| {
                !b.imported.contains_key(&e.id) && !state.files.get(*p).is_some_and(|f| !f.deleted)
            })
            .map(|(p, e)| MissingFile {
                path: p.clone(),
                id: e.id.clone(),
                size: e.size,
                holders: b
                    .missing_holders
                    .get(&e.id)
                    .map(|v| {
                        v.iter()
                            .map(|u| b.repositories.get(u).cloned().unwrap_or_else(|| u.clone()))
                            .collect()
                    })
                    .unwrap_or_default(),
            })
            .collect())
    }

    /// The files of a folder with the paths still awaiting import (state
    /// `awaiting_import`, size as listed by the source).
    pub fn list_files_with_pending(&self, folder: &str) -> Result<Vec<FileEntry>> {
        let mut out = self.list_files(folder)?;
        let (rec, root) = self.resolve_folder(folder)?;
        let Some(b) = self.load_book(&rec.folder_id) else {
            return Ok(out);
        };
        let have: HashSet<String> = out.iter().map(|f| f.path.clone()).collect();
        let selective = self.mount_is_selective(&rec.folder_id);
        let state = self.load_state(&rec.folder_id)?;
        for (p, e) in &b.tree {
            if have.contains(p) || b.imported.contains_key(&e.id) {
                continue;
            }
            out.push(FileEntry {
                path: p.clone(),
                size: e.size,
                state: "awaiting_import".to_string(),
                pinned: false,
                content_hash: String::new(),
                selective,
                disk: self.disk_of(&root, &state, p),
                media: thumbs::is_image(p) || thumbs::is_video(p),
                modified_utc: e.mtime_ns / 1_000_000_000,
                last_accessed_utc: None,
                analysis: None,
                analysis_truncated: false,
                analysis_tags: Vec::new(),
                analysis_utc: None,
                analysis_stale: false,
                analysis_by: None,
                analysis_author: None,
                ..Default::default()
            });
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    /// Whether an imported folder holds everything of its source's list,
    /// safely: every block on a storage, the durability policy met. Nothing
    /// is changed (and nothing at the source is ever touched).
    pub fn import_verify(&mut self, folder: &str) -> Result<ImportVerify> {
        let _ = self.refresh_books();
        let (rec, b) = self
            .import_books(Some(folder))?
            .into_iter()
            .next()
            .expect("one folder");
        let state = self.load_state(&rec.folder_id)?;
        let view = self.view()?;
        let carriers: BTreeSet<String> = self
            .config
            .storages
            .iter()
            .filter(|s| s.is_carrier())
            .map(|s| s.name().to_string())
            .collect();
        let mut v = ImportVerify {
            folder: rec.name.clone(),
            complete: false,
            files_total: b.tree.len() as u64,
            files_ok: 0,
            files_awaiting: 0,
            files_changed_in_varsto: 0,
            blocks_without_storage_copy: 0,
            policy: None,
            copies: Vec::new(),
            reasons: Vec::new(),
        };
        let mut seen = HashSet::new();
        for (p, e) in &b.tree {
            let Some(x) = b.imported.get(&e.id) else {
                v.files_awaiting += 1;
                continue;
            };
            match state.files.get(p) {
                Some(f) if !f.deleted && f.content_hash == x.hash => {
                    v.files_ok += 1;
                    for c in &f.chunks {
                        if !seen.insert(c.chunk.clone()) {
                            continue;
                        }
                        let on_storage = view.locate(&rec.folder_id, &c.chunk).is_some_and(|r| {
                            r.storages
                                .iter()
                                .any(|(n, l)| !l.claimed_by.is_empty() && !carriers.contains(n))
                        });
                        if !on_storage {
                            v.blocks_without_storage_copy += 1;
                        }
                    }
                }
                Some(_) => v.files_changed_in_varsto += 1,
                None => v.files_awaiting += 1,
            }
        }
        if v.files_awaiting > 0 {
            v.reasons.push(format!(
                "{} file(s) still await their content: insert a disk that has them and import again",
                v.files_awaiting
            ));
        }
        if v.files_changed_in_varsto > 0 {
            v.reasons.push(format!(
                "{} file(s) were changed or deleted in Varsto since the import (not counted as imported)",
                v.files_changed_in_varsto
            ));
        }
        if v.blocks_without_storage_copy > 0 {
            v.reasons.push(format!(
                "{} block(s) are on no storage yet (run a sync)",
                v.blocks_without_storage_copy
            ));
        }
        let policy = self
            .policy_check()?
            .into_iter()
            .find(|r| r.folder == rec.name);
        if let Some(p) = &policy {
            if p.state != crate::policy::PolicyState::Ok {
                v.reasons.push(format!(
                    "the folder's durability policy is not met yet ({}): {}",
                    p.policy.describe(),
                    p.reasons.join("; ")
                ));
            }
        }
        v.policy = policy;
        for (inst, r) in &b.runs {
            let name = b
                .repositories
                .get(inst)
                .cloned()
                .unwrap_or_else(|| r.name.clone());
            v.copies.push((name, r.location.clone(), r.complete));
        }
        v.complete = v.reasons.is_empty();
        Ok(v)
    }

    // ----- emptying a local source ----------------------------------------------------

    /// Remove the files of a local source that are safely in the vault
    /// (`apply`), or say which would be removed and which wait and why.
    pub fn import_cleanup(&mut self, folder: &str, apply: bool) -> Result<ImportCleanupReport> {
        self.ensure_active()?;
        let _ = self.refresh_books();
        let (rec, mut b) = self
            .import_books(Some(folder))?
            .into_iter()
            .next()
            .expect("one folder");
        if b.kind != import::KIND_DIR {
            bail!("only imports of local directories can remove their source files");
        }
        let src = PathBuf::from(
            b.source_path
                .clone()
                .ok_or_else(|| anyhow!("the import of {} names no source directory", rec.name))?,
        );
        let src = src
            .canonicalize()
            .with_context(|| format!("the source {} is not here", src.display()))?;
        if b.identity
            .iter()
            .all(|i| i != &format!("dir:{}", src.display()))
        {
            bail!(
                "{} is not the directory this folder was imported from",
                src.display()
            );
        }
        self.check_source_path(&src, true)?;
        let mut report = ImportCleanupReport {
            folder: rec.name.clone(),
            source: src.display().to_string(),
            applied: apply,
            ..Default::default()
        };
        let task = activity::start(
            activity::IMPORT,
            &rec.name,
            b.tree.len() as u64,
            activity::Unit::Items,
        );
        task.set_phase("cleanup");
        let state = self.load_state(&rec.folder_id)?;
        let view = self.view()?;
        let mut pctx = self.policy_ctx();
        let policy = rec.effective_policy();
        let storages = self.open_storages(false)?;
        let mut read_back: HashSet<ObjectName> = HashSet::new();
        let now = util::now_utc();
        let wait = |report: &mut ImportCleanupReport, path: &str, size: u64, reason: String| {
            report.waiting_count += 1;
            if report.waiting.len() < 200 {
                report.waiting.push(CleanupFile {
                    path: path.to_string(),
                    size,
                    reason,
                });
            }
        };
        let tree: Vec<(String, TreeEntry)> =
            b.tree.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        for (path, e) in tree {
            task.advance(1);
            let Some(x) = b.imported.get(&e.id).cloned() else {
                wait(&mut report, &path, e.size, "not imported yet".into());
                continue;
            };
            let Some(sha) = x.sha256.clone() else {
                wait(
                    &mut report,
                    &path,
                    e.size,
                    "no checksum of the imported content".into(),
                );
                continue;
            };
            // (1) The source file is the one imported.
            let (file, md) = match import::dir::open_inside(&src, &path) {
                Ok(Some(x)) => x,
                Ok(None) => continue, // gone already
                Err(err) => {
                    wait(
                        &mut report,
                        &path,
                        e.size,
                        format!("cannot be checked: {err:#}"),
                    );
                    continue;
                }
            };
            if md.len() != e.size || import::dir::mtime_ns(&md) != e.mtime_ns {
                wait(
                    &mut report,
                    &path,
                    e.size,
                    "changed since it was imported".into(),
                );
                continue;
            }
            // (2) The vault still has it.
            let Some(f) = state
                .files
                .get(&path)
                .filter(|f| !f.deleted && f.content_hash == x.hash)
            else {
                wait(
                    &mut report,
                    &path,
                    e.size,
                    "changed or deleted in Varsto since the import".into(),
                );
                continue;
            };
            // (3, 4) Every block on a storage (not a transferrer), read back
            // from one, and the policy met for these blocks now.
            let mut problem: Option<String> = None;
            let mut facts = Vec::new();
            for c in &f.chunks {
                let rec_c = view
                    .locate(&rec.folder_id, &c.chunk)
                    .filter(|r| r.object == c.object);
                let holders: Vec<&String> = rec_c
                    .map(|r| {
                        r.storages
                            .iter()
                            .filter(|(n, l)| {
                                !l.claimed_by.is_empty() && !pctx.carriers.contains(*n)
                            })
                            .map(|(n, _)| n)
                            .collect()
                    })
                    .unwrap_or_default();
                if holders.is_empty() {
                    problem =
                        Some("not on a storage yet (only on devices or a transferrer)".into());
                    break;
                }
                if !read_back.contains(&c.object) {
                    let key = chunk_storage_key(&c.object);
                    let ok = storages
                        .iter()
                        .filter(|(s, _)| holders.contains(&&s.name().to_string()))
                        .any(|(_, b)| {
                            b.get(&key).ok().flatten().is_some_and(|ct| {
                                ObjectName::from_bytes(&crypto::hash(&ct)) == c.object
                            })
                        });
                    if !ok {
                        problem = Some("no storage copy could be read back intact".into());
                        break;
                    }
                    read_back.insert(c.object.clone());
                }
                facts.push(self.chunk_facts(&mut pctx, &view, &rec.folder_id, &c.chunk));
            }
            if problem.is_none() {
                if let Some(p) = &policy {
                    let r = crate::policy::evaluate(
                        &rec.name,
                        p,
                        &facts,
                        &pctx.unreadable_places,
                        &pctx.unknown,
                        now,
                    );
                    if r.state != crate::policy::PolicyState::Ok {
                        problem = Some(format!(
                            "waiting for the policy ({}): {}",
                            p.describe(),
                            if r.reasons.is_empty() {
                                r.warnings.join("; ")
                            } else {
                                r.reasons.join("; ")
                            }
                        ));
                    }
                }
            }
            if let Some(p) = problem {
                wait(&mut report, &path, e.size, p);
                continue;
            }
            report.eligible += 1;
            report.eligible_bytes += e.size;
            if !apply {
                continue;
            }
            // (1 again) The content now is what was imported.
            let mut h = sha2::Sha256::new();
            let mut r = std::io::BufReader::with_capacity(1 << 20, file);
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = r.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                Digest::update(&mut h, &buf[..n]);
            }
            if hex::encode(h.finalize()) != sha {
                report.eligible -= 1;
                report.eligible_bytes -= e.size;
                wait(
                    &mut report,
                    &path,
                    e.size,
                    "its content differs from what was imported".into(),
                );
                continue;
            }
            let disk = util::safe_join(&src, &path)?;
            fs::remove_file(&disk).with_context(|| format!("remove {}", disk.display()))?;
            report.removed_bytes += e.size;
            report.removed.push(CleanupFile {
                path: path.clone(),
                size: e.size,
                reason: String::new(),
            });
            b.removals.push(Removal {
                path: path.clone(),
                size: e.size,
                sha256: sha,
                removed_utc: util::now_utc(),
            });
            // Directories left empty go too; never the source itself.
            let mut dir = disk.parent().map(Path::to_path_buf);
            while let Some(d) = dir {
                if d == src || !d.starts_with(&src) {
                    break;
                }
                let empty = fs::read_dir(&d)
                    .map(|mut it| it.next().is_none())
                    .unwrap_or(false);
                if !empty || fs::remove_dir(&d).is_err() {
                    break;
                }
                report.dirs_removed += 1;
                dir = d.parent().map(Path::to_path_buf);
            }
        }
        drop(task);
        if apply && !report.removed.is_empty() {
            self.save_book(&rec.folder_id, &b)?;
            let rec = self.with_key(&rec)?;
            self.publish_book(&rec, &b)?;
        }
        Ok(report)
    }
}

fn dest_for(opts: &ImportOptions, name: &str) -> Option<PathBuf> {
    opts.dest
        .clone()
        .or_else(|| opts.default_parent.as_ref().map(|p| p.join(name)))
}

fn set_mtime(path: &Path, mtime_ns: i64) -> Result<()> {
    if mtime_ns <= 0 {
        return Ok(());
    }
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_nanos(mtime_ns as u64);
    let f = fs::OpenOptions::new().write(true).open(path)?;
    f.set_modified(t)?;
    Ok(())
}

fn index_entry(disk: &Path, hash: &str) -> Result<LocalIndexEntry> {
    let md = fs::metadata(disk)?;
    Ok(LocalIndexEntry {
        size: md.len(),
        mtime: import::dir::mtime_ns(&md),
        content_hash: hash.to_string(),
        ..Default::default()
    })
}

/// Holders by how much they would bring, names from the repository list.
fn holder_list(
    per: &BTreeMap<String, (u64, u64)>,
    names: &BTreeMap<String, String>,
) -> Vec<Holder> {
    let mut v: Vec<Holder> = per
        .iter()
        .map(|(u, (n, bytes))| Holder {
            instance: u.clone(),
            name: names.get(u).cloned().unwrap_or_else(|| u.clone()),
            items: *n,
            bytes: *bytes,
        })
        .collect();
    v.sort_by(|a, b| {
        b.bytes
            .cmp(&a.bytes)
            .then(b.items.cmp(&a.items))
            .then(a.name.cmp(&b.name))
    });
    v
}

/// `p` with its longest existing ancestor resolved (links, `..`), the rest
/// appended as given.
pub(super) fn resolve_existing(p: &Path) -> PathBuf {
    let mut base = p.to_path_buf();
    let mut rest = Vec::new();
    loop {
        if let Ok(c) = fs::canonicalize(&base) {
            return rest.iter().rev().fold(c, |acc: PathBuf, n| acc.join(n));
        }
        match (base.file_name().map(|n| n.to_os_string()), base.parent()) {
            (Some(n), Some(parent)) => {
                rest.push(n);
                base = parent.to_path_buf();
            }
            _ => return p.to_path_buf(),
        }
    }
}
