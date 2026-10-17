// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The local map table of one folder (section 3, "Reader"):
//! `state/maps/<folder hex>.tbl`.
//!
//! The union of every accepted writer's newest base and the deltas after
//! it, as fixed-width rows sorted by object name, a second array of row
//! numbers sorted by (chunk id, epoch), and the marks in a side table
//! sorted by place. Lookups are binary searches with positioned reads:
//! memory is O(1) in the number of blocks (the stream markers and the pack
//! table, O(writers + packs), are held in memory).
//!
//! File layout (all integers little-endian; local state, not a wire
//! format):
//!
//! ```text
//! streams  n_streams x 72  device [16], base u64, applied u64, applied body_hash [32], 0 u64
//! packs    n_packs   x 36  id [32], class u8, 0 [3]                 (sorted by id)
//! rows     n_rows    x 88  object [32], chunk [32], pack u32, offset u32, len u32,
//!                          plain_len u32, epoch u32, writer u16, flags u8, 0 u8
//!                          (sorted by object, pack, offset, writer)
//! chunks   n_rows    x 4   row number u32       (sorted by chunk, epoch, row)
//! marks    n_marks   x 88  pack [32], offset u32, object [32], kind u8, 0 u8,
//!                          marker u16, lamport u64, map seq u64
//!                          (sorted by pack, offset, lamport, marker)
//! footer   64              "VBMT", version u16, 0 u16, folder [16], n_streams u32,
//!                          n_packs u32, n_rows u64, n_marks u64, 0 [8]
//! hash     32              BLAKE3 of every byte before it
//! ```
//!
//! Every change writes a whole new file beside the old one
//! (`<folder>.tbl.tmp`, flushed to disk) and renames it over the old one,
//! so a crash leaves the old table or the new one, never a mix. The
//! applied (writer, seq) of every stream is in the same file. A table that
//! fails its hash or its sizes is treated as empty: the next update reads
//! every stream from its base again (a rebuild).
//!
//! Building sorts with bounded memory: rows are sorted in runs of
//! `run_rows` and merged from files; the previous table's rows are one
//! more sorted run, so an update reads the old table once and the new
//! records once.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};

use super::record::{BlockMap, MarkKind, PackRef, FLAG_DEAD};
use crate::ledger3::events::class_bytes;
use crate::ledger3::{DeviceBin, FolderBin, Hash32, ObjectBin, PackId, Place};

pub const TABLE_MAGIC: &[u8; 4] = b"VBMT";
pub const TABLE_VERSION: u16 = 1;
const STREAM_W: usize = 72;
const PACK_W: usize = 36;
/// Bytes of one row (one place) and one mark on disk.
pub const ROW_W: usize = 88;
pub const MARK_W: usize = 88;
const CHUNK_W: usize = 4;
const CHUNK_KEY_W: usize = 40;
const FOOTER: usize = 64;
const HASH: usize = 32;
/// Rows sorted in memory before a run goes to a file (~88 MiB).
pub const DEFAULT_RUN_ROWS: usize = 1 << 20;
/// Most writer streams a table numbers (row writer field is u16).
pub const MAX_STREAMS: usize = u16::MAX as usize;

/// What the table applied of one writer's stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamMarker {
    pub device: DeviceBin,
    /// The base the rows of this writer come from.
    pub base: u64,
    /// The newest record applied, and its `body_hash` (the next delta's
    /// `prev` must name it).
    pub applied: u64,
    pub applied_hash: Hash32,
}

/// One place of a block as the table holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MapRow {
    pub object: ObjectBin,
    pub chunk: [u8; 32],
    pub place: Place,
    pub class: u8,
    pub plain_len: u32,
    pub epoch: u32,
    pub flags: u8,
    /// The device whose map lists the place.
    pub writer: DeviceBin,
}

impl MapRow {
    pub fn flagged_dead(&self) -> bool {
        self.flags & FLAG_DEAD != 0
    }
    /// The length of the pack the place is in.
    pub fn pack_len(&self) -> u64 {
        class_bytes(self.class).unwrap_or(0)
    }
}

/// One mark on a place, with the stamp of the record that made it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MarkRow {
    pub pack: PackId,
    pub offset: u32,
    pub object: ObjectBin,
    pub kind: MarkKind,
    pub marker: DeviceBin,
    /// The Lamport time of the marker's record: (lamport, marker) orders
    /// marks of one place.
    pub lamport: u64,
    /// The marker's map record that made the mark (its announcing batch
    /// is what settling waits for).
    pub map_seq: u64,
}

impl MarkRow {
    pub fn stamp(&self) -> (u64, DeviceBin) {
        (self.lamport, self.marker)
    }
}

/// What the marks on one place add up to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MarkState {
    /// Some `lost` mark is on the place.
    pub lost: bool,
    /// The newest (by stamp) of the place's dead and undead marks.
    pub newest: Option<MarkKind>,
}

impl MarkState {
    /// The kind `is_marked` reports: lost wins; else the newest of dead
    /// and undead; `None` without marks.
    pub fn kind(&self) -> Option<MarkKind> {
        if self.lost {
            Some(MarkKind::Lost)
        } else {
            self.newest
        }
    }
    /// Dead or lost: the place does not count as a copy.
    pub fn is_dead(&self) -> bool {
        matches!(self.kind(), Some(MarkKind::Dead | MarkKind::Lost))
    }
}

/// The records of one writer to apply: its accepted records in seq order,
/// each with its `body_hash` (the announced `record_hash`).
#[derive(Clone, Debug)]
pub struct MapUpdate {
    pub device: DeviceBin,
    pub records: Vec<(BlockMap, Hash32)>,
}

/// What an update did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApplyReport {
    pub records: u64,
    pub rows: u64,
    pub marks: u64,
    /// Marks on a place outside the folder's packs: ignored, and to be
    /// counted in the view (`LedgerView::count_marks_refused`).
    pub marks_refused: u64,
    /// Records not applied: (writer, seq, why). The writer's later records
    /// wait for them.
    pub skipped: Vec<(DeviceBin, u64, String)>,
}

/// The table of one folder.
pub struct MapTable {
    path: PathBuf,
    folder: FolderBin,
    file: Option<File>,
    streams: Vec<StreamMarker>,
    packs: Vec<PackRef>,
    n_rows: u64,
    n_marks: u64,
    corrupt: bool,
    /// Rows per sorted run while building.
    pub run_rows: usize,
    #[cfg(test)]
    pub(crate) crash_after_rows: Option<u64>,
}

/// The table path of a folder under a device's state directory.
pub fn table_path(state_dir: &Path, folder: &FolderBin) -> PathBuf {
    state_dir
        .join("maps")
        .join(format!("{}.tbl", hex::encode(folder)))
}

// ---- positioned reads ------------------------------------------------------

#[cfg(unix)]
fn read_at(f: &File, buf: &mut [u8], off: u64) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.read_exact_at(buf, off)
}

#[cfg(windows)]
fn read_at(f: &File, buf: &mut [u8], mut off: u64) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut done = 0;
    while done < buf.len() {
        let n = f.seek_read(&mut buf[done..], off)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        done += n;
        off += n as u64;
    }
    Ok(())
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().expect("2 bytes"))
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}
fn arr32(b: &[u8], at: usize) -> [u8; 32] {
    b[at..at + 32].try_into().expect("32 bytes")
}

// ---- raw rows ----------------------------------------------------------------

type RawRow = [u8; ROW_W];
type RawMark = [u8; MARK_W];
type RawChunkKey = [u8; CHUNK_KEY_W];

struct RowFields {
    object: ObjectBin,
    chunk: [u8; 32],
    pack: u32,
    offset: u32,
    len: u32,
    plain_len: u32,
    epoch: u32,
    writer: u16,
    flags: u8,
}

fn encode_row(r: &RowFields) -> RawRow {
    let mut b = [0u8; ROW_W];
    b[0..32].copy_from_slice(&r.object);
    b[32..64].copy_from_slice(&r.chunk);
    b[64..68].copy_from_slice(&r.pack.to_le_bytes());
    b[68..72].copy_from_slice(&r.offset.to_le_bytes());
    b[72..76].copy_from_slice(&r.len.to_le_bytes());
    b[76..80].copy_from_slice(&r.plain_len.to_le_bytes());
    b[80..84].copy_from_slice(&r.epoch.to_le_bytes());
    b[84..86].copy_from_slice(&r.writer.to_le_bytes());
    b[86] = r.flags;
    b
}

fn row_pack(b: &[u8]) -> u32 {
    u32_at(b, 64)
}
fn row_writer(b: &[u8]) -> u16 {
    u16_at(b, 84)
}

fn cmp_row(a: &RawRow, b: &RawRow) -> Ordering {
    a[0..32]
        .cmp(&b[0..32])
        .then(row_pack(a).cmp(&row_pack(b)))
        .then(u32_at(a, 68).cmp(&u32_at(b, 68)))
        .then(row_writer(a).cmp(&row_writer(b)))
        .then(a.cmp(b))
}

fn chunk_key(row: &RawRow, n: u32) -> RawChunkKey {
    let mut k = [0u8; CHUNK_KEY_W];
    k[0..32].copy_from_slice(&row[32..64]);
    k[32..36].copy_from_slice(&row[80..84]);
    k[36..40].copy_from_slice(&n.to_le_bytes());
    k
}

fn cmp_chunk_key(a: &RawChunkKey, b: &RawChunkKey) -> Ordering {
    a[0..32]
        .cmp(&b[0..32])
        .then(u32_at(a, 32).cmp(&u32_at(b, 32)))
        .then(u32_at(a, 36).cmp(&u32_at(b, 36)))
}

struct MarkFields {
    pack: PackId,
    offset: u32,
    object: ObjectBin,
    kind: u8,
    marker: u16,
    lamport: u64,
    map_seq: u64,
}

fn encode_mark(m: &MarkFields) -> RawMark {
    let mut b = [0u8; MARK_W];
    b[0..32].copy_from_slice(&m.pack);
    b[32..36].copy_from_slice(&m.offset.to_le_bytes());
    b[36..68].copy_from_slice(&m.object);
    b[68] = m.kind;
    b[70..72].copy_from_slice(&m.marker.to_le_bytes());
    b[72..80].copy_from_slice(&m.lamport.to_le_bytes());
    b[80..88].copy_from_slice(&m.map_seq.to_le_bytes());
    b
}

fn mark_marker(b: &[u8]) -> u16 {
    u16_at(b, 70)
}

fn cmp_mark(a: &RawMark, b: &RawMark) -> Ordering {
    a[0..32]
        .cmp(&b[0..32])
        .then(u32_at(a, 32).cmp(&u32_at(b, 32)))
        .then(u64_at(a, 72).cmp(&u64_at(b, 72)))
        .then(mark_marker(a).cmp(&mark_marker(b)))
        .then(a.cmp(b))
}

// ---- external sort -------------------------------------------------------------

type Source<const W: usize> = Box<dyn Iterator<Item = Result<[u8; W]>>>;

/// Sorts fixed-width records with at most `run` of them in memory.
struct Sorter<const W: usize> {
    cmp: fn(&[u8; W], &[u8; W]) -> Ordering,
    buf: Vec<[u8; W]>,
    run: usize,
    runs: Vec<PathBuf>,
    stem: PathBuf,
}

impl<const W: usize> Sorter<W> {
    fn new(cmp: fn(&[u8; W], &[u8; W]) -> Ordering, run: usize, stem: PathBuf) -> Self {
        Sorter {
            cmp,
            buf: Vec::new(),
            run: run.max(1),
            runs: Vec::new(),
            stem,
        }
    }

    fn push(&mut self, r: [u8; W]) -> Result<()> {
        self.buf.push(r);
        if self.buf.len() >= self.run {
            self.spill()?;
        }
        Ok(())
    }

    fn spill(&mut self) -> Result<()> {
        let cmp = self.cmp;
        self.buf.sort_unstable_by(cmp);
        let path = PathBuf::from(format!(
            "{}.run{}.tmp",
            self.stem.display(),
            self.runs.len()
        ));
        let mut w = BufWriter::new(
            File::create(&path).with_context(|| format!("create {}", path.display()))?,
        );
        for r in &self.buf {
            w.write_all(r)?;
        }
        w.flush()?;
        self.runs.push(path);
        self.buf.clear();
        Ok(())
    }

    /// Merge the runs, the rows in memory and `extra` (already sorted).
    fn merge(mut self, extra: Option<Source<W>>) -> Result<Merged<W>> {
        let cmp = self.cmp;
        self.buf.sort_unstable_by(cmp);
        let mut sources: Vec<Source<W>> = Vec::new();
        for p in &self.runs {
            let f = File::open(p).with_context(|| format!("open {}", p.display()))?;
            sources.push(Box::new(FixedReader::<W>(BufReader::new(f))));
        }
        sources.push(Box::new(std::mem::take(&mut self.buf).into_iter().map(Ok)));
        if let Some(e) = extra {
            sources.push(e);
        }
        let mut heads = Vec::with_capacity(sources.len());
        for mut s in sources {
            let h = s.next().transpose()?;
            heads.push((h, s));
        }
        Ok(Merged {
            cmp,
            heads,
            last: None,
            runs: std::mem::take(&mut self.runs),
        })
    }
}

impl<const W: usize> Drop for Sorter<W> {
    fn drop(&mut self) {
        for p in &self.runs {
            let _ = fs::remove_file(p);
        }
    }
}

struct FixedReader<const W: usize>(BufReader<File>);

impl<const W: usize> Iterator for FixedReader<W> {
    type Item = Result<[u8; W]>;
    fn next(&mut self) -> Option<Self::Item> {
        let mut b = [0u8; W];
        match self.0.read_exact(&mut b) {
            Ok(()) => Some(Ok(b)),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => None,
            Err(e) => Some(Err(e.into())),
        }
    }
}

/// The merged, sorted output; equal records come out once.
struct Merged<const W: usize> {
    cmp: fn(&[u8; W], &[u8; W]) -> Ordering,
    heads: Vec<(Option<[u8; W]>, Source<W>)>,
    last: Option<[u8; W]>,
    runs: Vec<PathBuf>,
}

impl<const W: usize> Merged<W> {
    fn next_record(&mut self) -> Result<Option<[u8; W]>> {
        loop {
            let mut best: Option<usize> = None;
            for (i, (h, _)) in self.heads.iter().enumerate() {
                if let Some(h) = h {
                    let better = match best {
                        None => true,
                        Some(b) => (self.cmp)(h, self.heads[b].0.as_ref().expect("a head")).is_lt(),
                    };
                    if better {
                        best = Some(i);
                    }
                }
            }
            let Some(i) = best else {
                return Ok(None);
            };
            let (h, src) = &mut self.heads[i];
            let out = h.take().expect("a head");
            *h = src.next().transpose()?;
            if self.last.as_ref() == Some(&out) {
                continue;
            }
            self.last = Some(out);
            return Ok(Some(out));
        }
    }
}

impl<const W: usize> Drop for Merged<W> {
    fn drop(&mut self) {
        for p in &self.runs {
            let _ = fs::remove_file(p);
        }
    }
}

// ---- writing ---------------------------------------------------------------------

/// A writer that hashes what it writes.
struct Hashing<W: Write> {
    inner: W,
    hasher: blake3::Hasher,
}

impl<W: Write> Write for Hashing<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

impl MapTable {
    // ---- opening -------------------------------------------------------------

    /// Open the table at `path` (none yet: an empty table). A table that
    /// fails its checks opens empty with `was_corrupt()`: the next update
    /// rebuilds it from the records.
    pub fn open(path: &Path, folder: FolderBin) -> Result<MapTable> {
        let mut t = MapTable {
            path: path.to_path_buf(),
            folder,
            file: None,
            streams: Vec::new(),
            packs: Vec::new(),
            n_rows: 0,
            n_marks: 0,
            corrupt: false,
            run_rows: DEFAULT_RUN_ROWS,
            #[cfg(test)]
            crash_after_rows: None,
        };
        let f = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(t),
            Err(e) => return Err(e).with_context(|| format!("open {}", path.display())),
        };
        match t.load(f) {
            Ok(()) => {}
            Err(e) => {
                log::warn!(
                    "block map table {} is unusable, rebuilding: {e:#}",
                    path.display()
                );
                t.file = None;
                t.streams.clear();
                t.packs.clear();
                t.n_rows = 0;
                t.n_marks = 0;
                t.corrupt = true;
            }
        }
        Ok(t)
    }

    fn load(&mut self, f: File) -> Result<()> {
        let len = f.metadata()?.len();
        if len < (FOOTER + HASH) as u64 {
            bail!("{len} bytes, shorter than a footer");
        }
        let mut foot = [0u8; FOOTER + HASH];
        read_at(&f, &mut foot, len - (FOOTER + HASH) as u64)?;
        if &foot[0..4] != TABLE_MAGIC || u16_at(&foot, 4) != TABLE_VERSION {
            bail!("not a block map table of version {TABLE_VERSION}");
        }
        if foot[8..24] != self.folder {
            bail!("a table of another folder");
        }
        let n_streams = u32_at(&foot, 24) as u64;
        let n_packs = u32_at(&foot, 28) as u64;
        let n_rows = u64_at(&foot, 32);
        let n_marks = u64_at(&foot, 40);
        let want = n_streams
            .checked_mul(STREAM_W as u64)
            .and_then(|a| a.checked_add(n_packs.checked_mul(PACK_W as u64)?))
            .and_then(|a| a.checked_add(n_rows.checked_mul((ROW_W + CHUNK_W) as u64)?))
            .and_then(|a| a.checked_add(n_marks.checked_mul(MARK_W as u64)?))
            .and_then(|a| a.checked_add((FOOTER + HASH) as u64));
        if want != Some(len) || n_rows > u32::MAX as u64 || n_streams > MAX_STREAMS as u64 {
            bail!("sizes in the footer do not match the file");
        }
        // The whole file against its hash, read in pieces.
        let mut h = blake3::Hasher::new();
        let mut buf = vec![0u8; 1 << 20];
        let body = len - HASH as u64;
        let mut at = 0u64;
        while at < body {
            let n = (body - at).min(buf.len() as u64) as usize;
            read_at(&f, &mut buf[..n], at)?;
            h.update(&buf[..n]);
            at += n as u64;
        }
        if h.finalize().as_bytes()[..] != foot[FOOTER..] {
            bail!("hash does not match");
        }
        let mut sb = vec![0u8; n_streams as usize * STREAM_W];
        read_at(&f, &mut sb, 0)?;
        self.streams = sb
            .chunks_exact(STREAM_W)
            .map(|b| StreamMarker {
                device: b[0..16].try_into().expect("16"),
                base: u64_at(b, 16),
                applied: u64_at(b, 24),
                applied_hash: arr32(b, 32),
            })
            .collect();
        let mut pb = vec![0u8; n_packs as usize * PACK_W];
        read_at(&f, &mut pb, sb.len() as u64)?;
        self.packs = pb
            .chunks_exact(PACK_W)
            .map(|b| PackRef {
                id: arr32(b, 0),
                class: b[32],
            })
            .collect();
        if self.packs.windows(2).any(|w| w[0].id >= w[1].id) {
            bail!("pack table not sorted");
        }
        self.n_rows = n_rows;
        self.n_marks = n_marks;
        self.file = Some(f);
        Ok(())
    }

    /// The table was unusable when opened (it is rebuilt by the next
    /// update, which reads every stream from its base).
    pub fn was_corrupt(&self) -> bool {
        self.corrupt
    }

    pub fn folder(&self) -> &FolderBin {
        &self.folder
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn rows(&self) -> u64 {
        self.n_rows
    }
    pub fn mark_count(&self) -> u64 {
        self.n_marks
    }
    pub fn packs(&self) -> &[PackRef] {
        &self.packs
    }
    pub fn streams(&self) -> &[StreamMarker] {
        &self.streams
    }
    pub fn marker(&self, device: &DeviceBin) -> Option<&StreamMarker> {
        self.streams.iter().find(|s| s.device == *device)
    }

    // ---- offsets and raw reads -----------------------------------------------

    fn packs_off(&self) -> u64 {
        (self.streams.len() * STREAM_W) as u64
    }
    fn rows_off(&self) -> u64 {
        self.packs_off() + (self.packs.len() * PACK_W) as u64
    }
    fn chunks_off(&self) -> u64 {
        self.rows_off() + self.n_rows * ROW_W as u64
    }
    fn marks_off(&self) -> u64 {
        self.chunks_off() + self.n_rows * CHUNK_W as u64
    }

    fn file(&self) -> Result<&File> {
        self.file.as_ref().ok_or_else(|| anyhow!("empty table"))
    }

    fn raw_row(&self, i: u64) -> Result<RawRow> {
        let mut b = [0u8; ROW_W];
        read_at(self.file()?, &mut b, self.rows_off() + i * ROW_W as u64)?;
        Ok(b)
    }

    fn chunk_row(&self, i: u64) -> Result<u64> {
        let mut b = [0u8; CHUNK_W];
        read_at(self.file()?, &mut b, self.chunks_off() + i * CHUNK_W as u64)?;
        Ok(u32::from_le_bytes(b) as u64)
    }

    fn raw_mark(&self, i: u64) -> Result<RawMark> {
        let mut b = [0u8; MARK_W];
        read_at(self.file()?, &mut b, self.marks_off() + i * MARK_W as u64)?;
        Ok(b)
    }

    fn decode_row(&self, b: &RawRow) -> Result<MapRow> {
        let p = self
            .packs
            .get(row_pack(b) as usize)
            .ok_or_else(|| anyhow!("a row names pack {} of {}", row_pack(b), self.packs.len()))?;
        let w = self
            .streams
            .get(row_writer(b) as usize)
            .ok_or_else(|| anyhow!("a row names writer {}", row_writer(b)))?;
        Ok(MapRow {
            object: arr32(b, 0),
            chunk: arr32(b, 32),
            place: Place {
                pack: p.id,
                offset: u32_at(b, 68),
                len: u32_at(b, 72),
            },
            class: p.class,
            plain_len: u32_at(b, 76),
            epoch: u32_at(b, 80),
            flags: b[86],
            writer: w.device,
        })
    }

    fn decode_mark(&self, b: &RawMark) -> Result<MarkRow> {
        let w = self
            .streams
            .get(mark_marker(b) as usize)
            .ok_or_else(|| anyhow!("a mark names writer {}", mark_marker(b)))?;
        Ok(MarkRow {
            pack: arr32(b, 0),
            offset: u32_at(b, 32),
            object: arr32(b, 36),
            kind: MarkKind::from_code(b[68]).ok_or_else(|| anyhow!("mark kind {}", b[68]))?,
            marker: w.device,
            lamport: u64_at(b, 72),
            map_seq: u64_at(b, 80),
        })
    }

    /// The first index in `0..n` whose key is not less than the target.
    fn lower_bound(n: u64, mut less: impl FnMut(u64) -> Result<bool>) -> Result<u64> {
        let (mut lo, mut hi) = (0u64, n);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if less(mid)? {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(lo)
    }

    // ---- lookups -------------------------------------------------------------

    /// Every place the table lists for `object`.
    pub fn rows_of(&self, object: &ObjectBin) -> Result<Vec<MapRow>> {
        if self.n_rows == 0 {
            return Ok(Vec::new());
        }
        let mut i = Self::lower_bound(self.n_rows, |i| Ok(self.raw_row(i)?[0..32] < object[..]))?;
        let mut out = Vec::new();
        while i < self.n_rows {
            let b = self.raw_row(i)?;
            if b[0..32] != object[..] {
                break;
            }
            out.push(self.decode_row(&b)?);
            i += 1;
        }
        Ok(out)
    }

    /// Every place of chunk `chunk` under any epoch, by epoch.
    pub fn rows_of_chunk(&self, chunk: &[u8; 32]) -> Result<Vec<MapRow>> {
        if self.n_rows == 0 {
            return Ok(Vec::new());
        }
        let mut i = Self::lower_bound(self.n_rows, |i| {
            Ok(self.raw_row(self.chunk_row(i)?)?[32..64] < chunk[..])
        })?;
        let mut out = Vec::new();
        while i < self.n_rows {
            let b = self.raw_row(self.chunk_row(i)?)?;
            if b[32..64] != chunk[..] {
                break;
            }
            out.push(self.decode_row(&b)?);
            i += 1;
        }
        Ok(out)
    }

    /// The marks on a place, oldest stamp first.
    pub fn marks_at(&self, pack: &PackId, offset: u32) -> Result<Vec<MarkRow>> {
        if self.n_marks == 0 {
            return Ok(Vec::new());
        }
        let key = |b: &RawMark| (arr32(b, 0), u32_at(b, 32));
        let mut i = Self::lower_bound(self.n_marks, |i| {
            Ok(key(&self.raw_mark(i)?) < (*pack, offset))
        })?;
        let mut out = Vec::new();
        while i < self.n_marks {
            let b = self.raw_mark(i)?;
            if key(&b) != (*pack, offset) {
                break;
            }
            out.push(self.decode_mark(&b)?);
            i += 1;
        }
        out.sort_by_key(|m| (m.stamp(), m.kind));
        Ok(out)
    }

    /// What the marks on a place add up to.
    pub fn mark_state(&self, pack: &PackId, offset: u32) -> Result<MarkState> {
        let marks = self.marks_at(pack, offset)?;
        let mut s = MarkState {
            lost: marks.iter().any(|m| m.kind == MarkKind::Lost),
            newest: None,
        };
        s.newest = marks
            .iter()
            .filter(|m| m.kind != MarkKind::Lost)
            .max_by_key(|m| m.stamp())
            .map(|m| m.kind);
        Ok(s)
    }

    /// Every row, in object order (a scan of the whole table).
    pub fn scan(&self) -> impl Iterator<Item = Result<MapRow>> + '_ {
        (0..self.n_rows).map(move |i| self.decode_row(&self.raw_row(i)?))
    }

    /// Every mark, in place order.
    pub fn scan_marks(&self) -> impl Iterator<Item = Result<MarkRow>> + '_ {
        (0..self.n_marks).map(move |i| self.decode_mark(&self.raw_mark(i)?))
    }

    /// The rows of one writer (for its base rewrite).
    pub fn rows_by(&self, writer: &DeviceBin) -> Result<Vec<MapRow>> {
        let Some(w) = self.streams.iter().position(|s| s.device == *writer) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for i in 0..self.n_rows {
            let b = self.raw_row(i)?;
            if row_writer(&b) as usize == w {
                out.push(self.decode_row(&b)?);
            }
        }
        Ok(out)
    }

    /// The marks one device made.
    pub fn marks_by(&self, marker: &DeviceBin) -> Result<Vec<MarkRow>> {
        let Some(w) = self.streams.iter().position(|s| s.device == *marker) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for i in 0..self.n_marks {
            let b = self.raw_mark(i)?;
            if mark_marker(&b) as usize == w {
                out.push(self.decode_mark(&b)?);
            }
        }
        Ok(out)
    }

    // ---- updating ------------------------------------------------------------

    /// Apply the records of some writers. A writer's records are applied
    /// in order from its base (a record that is a base replaces every row
    /// and mark of that writer) or from the record after the one applied
    /// (its `prev` must name the applied one). Records that do not follow
    /// are skipped and reported, and so are the writer's records after
    /// them. `folder_pack` says whether a pack outside this table may be
    /// of the folder (the ledger view's claims; a pack the view does not
    /// know yet may): marks on other packs are refused and counted. The new table replaces the old one on disk
    /// atomically.
    pub fn apply(
        &mut self,
        updates: Vec<MapUpdate>,
        folder_pack: &dyn Fn(&PackId) -> bool,
    ) -> Result<ApplyReport> {
        let mut report = ApplyReport::default();
        let mut streams = self.streams.clone();
        // Writers whose rows and marks a new base replaces.
        let mut replaced: Vec<bool> = vec![false; streams.len()];
        let mut accepted: Vec<(u16, Vec<BlockMap>)> = Vec::new();
        for u in updates {
            let idx = match streams.iter().position(|s| s.device == u.device) {
                Some(i) => i,
                None => {
                    if streams.len() >= MAX_STREAMS {
                        bail!("more than {MAX_STREAMS} writers in one folder");
                    }
                    streams.push(StreamMarker {
                        device: u.device,
                        base: 0,
                        applied: 0,
                        applied_hash: [0; 32],
                    });
                    replaced.push(false);
                    streams.len() - 1
                }
            };
            let mut recs = u.records;
            recs.sort_by_key(|(b, _)| b.seq);
            // Start at the newest base among them, if any.
            if let Some(k) = recs.iter().rposition(|(b, _)| b.is_base()) {
                recs.drain(..k);
            }
            let mut take: Vec<BlockMap> = Vec::new();
            let mut cur = streams[idx].clone();
            let mut new_base = false;
            for (body, hash) in recs {
                let why = if body.folder != self.folder {
                    Some("names another folder".to_string())
                } else if body.device != u.device {
                    Some("names another writer".to_string())
                } else if let Err(e) = body.check_limits(u16::MAX) {
                    Some(e)
                } else if body.is_base() {
                    None
                } else if body.seq <= cur.applied {
                    continue; // applied before
                } else if cur.applied == 0 {
                    Some("a delta without its base".to_string())
                } else if body.seq != cur.applied + 1 {
                    Some(format!("record {} is missing", cur.applied + 1))
                } else if body.base != cur.base {
                    Some(format!("a delta of base {}, not {}", body.base, cur.base))
                } else if body.prev != cur.applied_hash {
                    Some("prev does not name the record before".to_string())
                } else {
                    None
                };
                if let Some(why) = why {
                    report.skipped.push((u.device, body.seq, why));
                    break;
                }
                if body.is_base() {
                    if body.seq <= cur.base {
                        continue; // this base or a newer one is applied
                    }
                    take.clear();
                    new_base = true;
                    cur.base = body.seq;
                }
                cur.applied = body.seq;
                cur.applied_hash = hash;
                take.push(body);
            }
            if take.is_empty() {
                continue;
            }
            if new_base {
                replaced[idx] = true;
            }
            report.records += take.len() as u64;
            streams[idx] = cur;
            match accepted.iter_mut().find(|(i, _)| *i as usize == idx) {
                Some((_, v)) if new_base => *v = take,
                Some((_, v)) => v.extend(take),
                None => accepted.push((idx as u16, take)),
            }
        }
        if report.records == 0 {
            return Ok(report);
        }
        self.rewrite(streams, &replaced, &accepted, folder_pack, &mut report)?;
        Ok(report)
    }

    fn rewrite(
        &mut self,
        streams: Vec<StreamMarker>,
        replaced: &[bool],
        accepted: &[(u16, Vec<BlockMap>)],
        folder_pack: &dyn Fn(&PackId) -> bool,
        report: &mut ApplyReport,
    ) -> Result<()> {
        let dir = self
            .path
            .parent()
            .ok_or_else(|| anyhow!("table path without a directory"))?
            .to_path_buf();
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        let keep_writer = |w: u16| !replaced.get(w as usize).copied().unwrap_or(false);

        // Pass 1: the packs the kept old rows use.
        let mut used_old = vec![false; self.packs.len()];
        for i in 0..self.n_rows {
            let b = self.raw_row(i)?;
            if keep_writer(row_writer(&b)) {
                if let Some(u) = used_old.get_mut(row_pack(&b) as usize) {
                    *u = true;
                }
            }
        }
        let mut pack_class: BTreeMap<PackId, u8> = BTreeMap::new();
        for (i, p) in self.packs.iter().enumerate() {
            if used_old[i] {
                pack_class.insert(p.id, p.class);
            }
        }
        for (_, recs) in accepted {
            for r in recs {
                for e in &r.entries {
                    let p = r.packs[e.pack as usize];
                    pack_class.entry(p.id).or_insert(p.class);
                }
            }
        }
        if pack_class.len() > u32::MAX as usize {
            bail!("too many packs in one table");
        }
        let new_packs: Vec<PackRef> = pack_class
            .iter()
            .map(|(id, class)| PackRef {
                id: *id,
                class: *class,
            })
            .collect();
        let index: HashMap<PackId, u32> = new_packs
            .iter()
            .enumerate()
            .map(|(i, p)| (p.id, i as u32))
            .collect();
        let remap: Vec<u32> = self
            .packs
            .iter()
            .map(|p| index.get(&p.id).copied().unwrap_or(u32::MAX))
            .collect();

        let stem = dir.join(format!("{}.build", hex::encode(self.folder)));
        let mut rows = Sorter::<ROW_W>::new(cmp_row, self.run_rows, stem.with_extension("rows"));
        let mut marks =
            Sorter::<MARK_W>::new(cmp_mark, self.run_rows, stem.with_extension("marks"));
        for (w, recs) in accepted {
            for r in recs {
                for e in &r.entries {
                    let p = r.packs[e.pack as usize];
                    if pack_class.get(&p.id) != Some(&p.class) {
                        // The same pack under another class: not a place.
                        continue;
                    }
                    rows.push(encode_row(&RowFields {
                        object: e.object,
                        chunk: e.chunk,
                        pack: index[&p.id],
                        offset: e.offset,
                        len: e.len,
                        plain_len: e.plain_len,
                        epoch: e.epoch,
                        writer: *w,
                        flags: e.flags,
                    }))?;
                    report.rows += 1;
                }
                for m in &r.marks {
                    if !index.contains_key(&m.pack) && !folder_pack(&m.pack) {
                        report.marks_refused += 1;
                        continue;
                    }
                    marks.push(encode_mark(&MarkFields {
                        pack: m.pack,
                        offset: m.offset,
                        object: m.object,
                        kind: m.kind,
                        marker: *w,
                        lamport: r.lamport,
                        map_seq: r.seq,
                    }))?;
                    report.marks += 1;
                }
            }
        }

        // The old table's kept rows and marks are one more sorted run each.
        let old_rows: Option<Source<ROW_W>> = match &self.file {
            Some(_) if self.n_rows > 0 => {
                let mut f = File::open(&self.path)?;
                use std::io::Seek;
                f.seek(std::io::SeekFrom::Start(self.rows_off()))?;
                let reader = FixedReader::<ROW_W>(BufReader::new(f)).take(self.n_rows as usize);
                let replaced = replaced.to_vec();
                Some(Box::new(reader.filter_map(move |r| match r {
                    Err(e) => Some(Err(e)),
                    Ok(mut b) => {
                        let w = row_writer(&b) as usize;
                        if replaced.get(w).copied().unwrap_or(false) {
                            return None;
                        }
                        let np = remap
                            .get(row_pack(&b) as usize)
                            .copied()
                            .unwrap_or(u32::MAX);
                        if np == u32::MAX {
                            return Some(Err(anyhow!("a kept row lost its pack")));
                        }
                        b[64..68].copy_from_slice(&np.to_le_bytes());
                        Some(Ok(b))
                    }
                })))
            }
            _ => None,
        };
        let old_marks: Option<Source<MARK_W>> = match &self.file {
            Some(_) if self.n_marks > 0 => {
                let mut f = File::open(&self.path)?;
                use std::io::Seek;
                f.seek(std::io::SeekFrom::Start(self.marks_off()))?;
                let reader = FixedReader::<MARK_W>(BufReader::new(f)).take(self.n_marks as usize);
                let replaced = replaced.to_vec();
                Some(Box::new(reader.filter(move |r| {
                    match r {
                        Err(_) => true,
                        Ok(b) => !replaced
                            .get(mark_marker(b) as usize)
                            .copied()
                            .unwrap_or(false),
                    }
                })))
            }
            _ => None,
        };

        let tmp = PathBuf::from(format!("{}.tmp", self.path.display()));
        let result = (|| -> Result<(u64, u64)> {
            let file = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
            let mut out = Hashing {
                inner: BufWriter::with_capacity(1 << 20, file),
                hasher: blake3::Hasher::new(),
            };
            for s in &streams {
                let mut b = [0u8; STREAM_W];
                b[0..16].copy_from_slice(&s.device);
                b[16..24].copy_from_slice(&s.base.to_le_bytes());
                b[24..32].copy_from_slice(&s.applied.to_le_bytes());
                b[32..64].copy_from_slice(&s.applied_hash);
                out.write_all(&b)?;
            }
            for p in &new_packs {
                let mut b = [0u8; PACK_W];
                b[0..32].copy_from_slice(&p.id);
                b[32] = p.class;
                out.write_all(&b)?;
            }
            let mut chunks = Sorter::<CHUNK_KEY_W>::new(
                cmp_chunk_key,
                self.run_rows,
                stem.with_extension("chunks"),
            );
            let mut merged = rows.merge(old_rows)?;
            let mut n_rows = 0u64;
            while let Some(r) = merged.next_record()? {
                if n_rows >= u32::MAX as u64 {
                    bail!("more than {} places in one table", u32::MAX);
                }
                #[cfg(test)]
                if self.crash_after_rows == Some(n_rows) {
                    out.flush()?;
                    bail!("simulated crash after {n_rows} rows");
                }
                out.write_all(&r)?;
                chunks.push(chunk_key(&r, n_rows as u32))?;
                n_rows += 1;
            }
            drop(merged);
            let mut merged = chunks.merge(None)?;
            while let Some(k) = merged.next_record()? {
                out.write_all(&k[36..40])?;
            }
            drop(merged);
            let mut merged = marks.merge(old_marks)?;
            let mut n_marks = 0u64;
            while let Some(m) = merged.next_record()? {
                out.write_all(&m)?;
                n_marks += 1;
            }
            drop(merged);
            let mut foot = [0u8; FOOTER];
            foot[0..4].copy_from_slice(TABLE_MAGIC);
            foot[4..6].copy_from_slice(&TABLE_VERSION.to_le_bytes());
            foot[8..24].copy_from_slice(&self.folder);
            foot[24..28].copy_from_slice(&(streams.len() as u32).to_le_bytes());
            foot[28..32].copy_from_slice(&(new_packs.len() as u32).to_le_bytes());
            foot[32..40].copy_from_slice(&n_rows.to_le_bytes());
            foot[40..48].copy_from_slice(&n_marks.to_le_bytes());
            out.write_all(&foot)?;
            let hash = out.hasher.finalize();
            let mut inner = out.inner;
            inner.write_all(hash.as_bytes())?;
            let file = inner.into_inner().map_err(|e| e.into_error())?;
            file.sync_all()?;
            Ok((n_rows, n_marks))
        })();
        let (n_rows, n_marks) = match result {
            Ok(v) => v,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        };
        // Windows does not rename over an open file.
        self.file = None;
        fs::rename(&tmp, &self.path)
            .with_context(|| format!("rename {} to {}", tmp.display(), self.path.display()))?;
        sync_dir(&dir);
        self.file = Some(File::open(&self.path)?);
        self.streams = streams;
        self.packs = new_packs;
        self.n_rows = n_rows;
        self.n_marks = n_marks;
        self.corrupt = false;
        Ok(())
    }
}
