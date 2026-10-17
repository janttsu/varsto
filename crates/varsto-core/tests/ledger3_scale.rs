// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The estimates of `docs/spec/format-3-design.md` section 4, measured:
//! the pack-level view of a 1 M-file vault (187 000 packs, three storages,
//! four devices) in memory and stored, and the replay of the ~337 000
//! `pack_stored` events of its first upload.
//!
//! Run with
//! `cargo test --release -p varsto-core --features format3 --test ledger3_scale -- --ignored --nocapture`.
#![cfg(feature = "format3")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Instant;

use varsto_core::crypto::{SecretKey, SigningKey};
use varsto_core::ledger3::envelope::kind;
use varsto_core::ledger3::events::{Announcement, Event, PackOn, PackStored, RawEvent};
use varsto_core::ledger3::scope::{ledger_key_id, EventScope};
use varsto_core::ledger3::{device_bin_for, Batch, DeviceBin, LedgerStore, LedgerView, NO_FOLDER};

struct Counting;
static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        LIVE.fetch_add(new as isize - l.size() as isize, Ordering::Relaxed);
        unsafe { System.realloc(p, l, new) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn live() -> isize {
    LIVE.load(Ordering::Relaxed)
}

const HOT_PACKS: u32 = 150_000;
const COLD_PACKS: u32 = 37_000;
const PER_BATCH: usize = 1_000;

fn pack_id(n: u32) -> [u8; 32] {
    // Pack ids are BLAKE3 hashes: spread over the whole key.
    *blake3::hash(&n.to_le_bytes()).as_bytes()
}

fn mb(b: isize) -> f64 {
    b as f64 / (1u64 << 20) as f64
}

/// The upload's events: every hot pack on both hot storages, every cold
/// pack on the cold one, written by one of four devices, with a map
/// announcement per batch; then (`verify`) a verification of every place by
/// the next device; (`all`) claims and verifications by all four devices on
/// all three storages.
fn upload(devices: &[DeviceBin], verify: bool, all: bool) -> Vec<(usize, Vec<Event>)> {
    let folder = [1u8; 16];
    let mut out: Vec<(usize, Vec<Event>)> = Vec::new();
    let mut cur: Vec<Event> = Vec::new();
    let mut writer = 0usize;
    let flush = |cur: &mut Vec<Event>, writer: usize, out: &mut Vec<(usize, Vec<Event>)>| {
        if !cur.is_empty() {
            cur.push(Event::RecordPublished(Announcement {
                kind: kind::BLOCK_MAP,
                scope: folder,
                seq: out.len() as u64 + 1,
                base: 1,
                parts: 1,
                body_hash: [7; 32],
                size: 440 * 1024,
            }));
            out.push((writer, std::mem::take(cur)));
        }
    };
    for n in 0..HOT_PACKS + COLD_PACKS {
        let id = pack_id(n);
        let storages: &[&str] = if all {
            &["hot-a", "hot-b", "cold"]
        } else if n < HOT_PACKS {
            &["hot-a", "hot-b"]
        } else {
            &["cold"]
        };
        let claimers: Vec<usize> = if all {
            (0..devices.len()).collect()
        } else {
            vec![writer]
        };
        for c in &claimers {
            for s in storages {
                cur.push(Event::PackStored(PackStored {
                    storage: s.to_string(),
                    pack: id,
                    // 64 MiB hot, 256 MiB cold.
                    class: if n < HOT_PACKS { 4 } else { 5 },
                    folder,
                    map_seq: n as u64 / 100 + 1,
                }));
                let _ = c;
            }
        }
        if verify {
            let verifiers: Vec<usize> = if all {
                (0..devices.len()).collect()
            } else {
                vec![(writer + 1) % devices.len()]
            };
            for _ in verifiers {
                for s in storages {
                    cur.push(Event::PackVerified(PackOn {
                        storage: s.to_string(),
                        pack: id,
                    }));
                }
            }
        }
        if cur.len() >= PER_BATCH {
            flush(&mut cur, writer, &mut out);
            writer = (writer + 1) % devices.len();
        }
    }
    flush(&mut cur, writer, &mut out);
    out
}

/// Events by `device` index: claims stay with their writer; with `verify`
/// the verifications are signed by another device (split into its own
/// batches), as in a real vault.
fn batches(devices: &[DeviceBin], plan: Vec<(usize, Vec<Event>)>, all: bool) -> Vec<Batch> {
    let mut seqs = vec![0u64; devices.len()];
    let mut lamport = 0;
    let mut out = Vec::new();
    for (w, events) in plan {
        let mut by_dev: Vec<Vec<RawEvent>> = vec![Vec::new(); devices.len()];
        let mut verifier_turn = 0usize;
        for (i, e) in events.iter().enumerate() {
            let d = match e {
                Event::PackVerified(_) if all => {
                    verifier_turn = (verifier_turn + 1) % devices.len();
                    verifier_turn
                }
                Event::PackVerified(_) => (w + 1) % devices.len(),
                Event::PackStored(_) if all => i % devices.len(),
                _ => w,
            };
            by_dev[d].push(e.to_raw());
        }
        for (d, evs) in by_dev.into_iter().enumerate() {
            if evs.is_empty() {
                continue;
            }
            seqs[d] += 1;
            lamport += 1;
            out.push(Batch {
                device: devices[d],
                seq: seqs[d],
                prev: [0; 32],
                lamport,
                created_utc: 1_800_000_000,
                seen: Vec::new(),
                events: evs,
            });
        }
    }
    out
}

fn measure_view(label: &str, devices: &[DeviceBin], verify: bool, all: bool) -> LedgerView {
    let bs = batches(devices, upload(devices, verify, all), all);
    let events: usize = bs.iter().map(|b| b.events.len()).sum();
    let before = live();
    let mut v = LedgerView::default();
    for b in &bs {
        v.apply(b);
    }
    v.finish_in_place([]);
    let held = live() - before;
    drop(bs);
    let plain = postcard::to_allocvec(&v).unwrap();
    let stored = zstd::bulk::compress(&plain, 3).unwrap();
    println!(
        "{label}: {} packs, {events} events: view in memory {:.1} MiB ({:.0} B per pack), \
         postcard {:.1} MiB, stored (zstd 3) {:.1} MiB",
        v.packs.len(),
        mb(held),
        held as f64 / v.packs.len() as f64,
        mb(plain.len() as isize),
        mb(stored.len() as isize),
    );
    v
}

#[test]
#[ignore = "benchmark: run in release with --ignored --nocapture"]
fn ledger3_scale_benchmark() {
    println!(
        "sizes: PackRecord {} B, PackPlace {} B, map entry {} B",
        std::mem::size_of::<varsto_core::ledger3::PackRecord>(),
        std::mem::size_of::<varsto_core::ledger3::PackPlace>(),
        std::mem::size_of::<([u8; 32], varsto_core::ledger3::PackRecord)>(),
    );
    let signers: Vec<SigningKey> = (1..=4u8)
        .map(|i| SigningKey::from_bytes(&[i; 64]).unwrap())
        .collect();
    let devices: Vec<DeviceBin> = signers
        .iter()
        .map(|s| device_bin_for(&s.public()))
        .collect();

    // 1. The view of section 4's vault: 150 k hot packs on two hot
    // storages, 37 k cold packs, claims by their writer, one verification
    // round by another device.
    let v = measure_view(
        "design mix, claims + one verification round",
        &devices,
        true,
        false,
    );
    assert_eq!(v.packs.len(), (HOT_PACKS + COLD_PACKS) as usize);
    assert_eq!(v.holders(&pack_id(1)), vec!["hot-a", "hot-b"]);
    drop(v);
    let _ = measure_view(
        "design mix, claims only (first upload)",
        &devices,
        false,
        false,
    );
    // 2. The worst case asked for: every pack on 3 storages, claimed and
    // verified by all 4 devices.
    let v = measure_view("187 k packs x 3 storages x 4 devices", &devices, true, true);
    assert_eq!(v.copies(&pack_id(5))[0].claimed_by.len(), 4);
    drop(v);

    // 3. Replay of the first upload's ~337 k `pack_stored` events.
    let bs = batches(&devices, upload(&devices, false, false), false);
    let stored: usize = bs
        .iter()
        .flat_map(|b| b.events.iter())
        .filter(|e| e.code == 3)
        .count();
    let t = Instant::now();
    let bodies: Vec<Vec<u8>> = bs.iter().map(|b| b.to_postcard().unwrap()).collect();
    let packed: Vec<Vec<u8>> = bodies
        .iter()
        .map(|b| zstd::bulk::compress(b, 3).unwrap())
        .collect();
    let encode = t.elapsed();
    let bytes: usize = bodies.iter().map(Vec::len).sum();
    let zbytes: usize = packed.iter().map(Vec::len).sum();
    let t = Instant::now();
    let mut v = LedgerView::default();
    for p in &packed {
        let b = Batch::from_postcard(&zstd::bulk::decompress(p, 64 << 20).unwrap()).unwrap();
        v.apply(&b);
    }
    v.finish_in_place([]);
    let replay = t.elapsed();
    println!(
        "replay: {stored} pack_stored events in {} batches, bodies {:.1} MiB postcard / {:.1} MiB zstd \
         ({:.0} B per event before zstd); encode {:.2} s, decompress + decode + apply {:.2} s",
        bs.len(),
        mb(bytes as isize),
        mb(zbytes as isize),
        bytes as f64 / stored as f64,
        encode.as_secs_f64(),
        replay.as_secs_f64(),
    );
    assert_eq!(v.packs.len(), (HOT_PACKS + COLD_PACKS) as usize);

    // 4. The same through the store: signed records ingested (signature
    // checked, written, chained) and the view replayed from disk.
    let dir = tempfile::tempdir().unwrap();
    let key = SecretKey::random();
    let id = ledger_key_id(0);
    let vault = [9u8; 16];
    let mut writers: Vec<LedgerStore> = (0..4)
        .map(|i| LedgerStore::open(&dir.path().join(format!("w{i}")), vault).unwrap())
        .collect();
    let t = Instant::now();
    let mut recs = Vec::new();
    for b in &bs {
        let i = devices.iter().position(|d| *d == b.device).unwrap();
        let rec = writers[i]
            .append_own(
                &b.device,
                b.events.clone(),
                vec![],
                b.lamport,
                &key,
                &id,
                NO_FOLDER,
                &signers[i],
            )
            .unwrap();
        recs.push((i, rec));
    }
    let seal = t.elapsed();
    let mut reader = LedgerStore::open(&dir.path().join("reader"), vault).unwrap();
    let t = Instant::now();
    for (i, rec) in recs {
        reader
            .ingest(rec, &signers[i].public(), Some(&key))
            .unwrap();
    }
    let ingest = t.elapsed();
    let t = Instant::now();
    let full = reader
        .view_scoped(
            |k| (k == id).then(|| key.clone()),
            |_, _| true,
            |_, k| EventScope::of_key_id(k),
        )
        .unwrap();
    let view = t.elapsed();
    println!(
        "store: seal + sign {:.2} s, ingest (verify + write) {:.2} s, view replay from disk {:.2} s",
        seal.as_secs_f64(),
        ingest.as_secs_f64(),
        view.as_secs_f64()
    );
    assert_eq!(full.packs.len(), (HOT_PACKS + COLD_PACKS) as usize);
}
