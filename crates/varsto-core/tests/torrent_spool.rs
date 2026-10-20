// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A torrent three times larger than the room on its download disk goes
//! into a folder on a directory storage in batches, through the
//! in-process fake transmission: every file arrives with its content, the
//! free space never falls below the reserve, and the download directory is
//! empty at the end.

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::{JobState, TorrentAddOptions, TorrentEnv};
use varsto_core::freespace::MinFree;
use varsto_core::pool::DiskSpace;
use varsto_core::storage::StorageSpec;
use varsto_core::transmission::{fake::FakeTransmission, make_metainfo, AddSource, Rpc};
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s & 0xff) as u8
        })
        .collect()
}

fn du(dir: &Path) -> u64 {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

/// A download disk of `capacity` bytes holding only the download directory.
struct SmallDisk {
    dir: PathBuf,
    capacity: u64,
    now: i64,
}

impl SmallDisk {
    fn free(&self) -> u64 {
        self.capacity.saturating_sub(du(&self.dir))
    }
}

impl TorrentEnv for SmallDisk {
    fn space(&mut self, _dir: &Path) -> Option<DiskSpace> {
        Some(DiskSpace {
            free: self.free(),
            total: self.capacity,
        })
    }
    fn now(&mut self) -> i64 {
        self.now += 1;
        self.now
    }
}

#[test]
fn a_torrent_three_times_the_room_arrives_in_three_batches() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut e, _key) = Engine::init(&root.join("home"), "laptop", PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e.add_storage(StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    })
    .unwrap();

    // Nine files of 3000 bytes, a zero-length one, pieces of 1 KiB.
    let mut contents: Vec<Vec<u8>> = (0..9).map(|i| pseudo_random(3000, 11 + i)).collect();
    contents.insert(4, Vec::new());
    let names: Vec<String> = (0..contents.len())
        .map(|i| format!("{}/part-{i:02}.bin", if i % 2 == 0 { "cd1" } else { "cd2" }))
        .collect();
    let files: Vec<(&str, &[u8])> = names
        .iter()
        .zip(&contents)
        .map(|(n, c)| (n.as_str(), c.as_slice()))
        .collect();
    let meta = make_metainfo("Season", &files, 1024);
    let fake = FakeTransmission::start(root);
    fake.provide(&meta, &contents);
    let rpc = Rpc::new(fake.settings());

    let base = root.join("dl");
    let job = e
        .torrent_add(
            &TorrentAddOptions {
                source: AddSource::Metainfo(meta.clone()),
                folder: "season".into(),
                storages: vec!["box".into()],
                free_min: MinFree::Bytes(10_000),
                download_dir: Some(base.clone()),
                folder_parent: root.join("folders"),
                min_copies: Some(1),
                verify_existing: false,
                rpc: fake.settings(),
            },
            &rpc,
        )
        .unwrap();
    assert_eq!(job.files.len(), 10);
    assert!(!fake.running(&job.hash));
    assert!(fake.wanted(&job.hash).iter().all(|w| !w));

    // Room above the reserve: three files and the pieces around them.
    let mut disk = SmallDisk {
        dir: base.clone(),
        capacity: 10_000 + 3 * 3000 + 2 * 1024 + 100,
        now: 1_800_000_000,
    };
    let mut lowest = u64::MAX;
    let mut done = None;
    for _ in 0..60 {
        let j = e
            .torrent_tick(&job.hash, &rpc, &mut disk, true)
            .unwrap()
            .unwrap();
        lowest = lowest.min(disk.free());
        if j.state == JobState::Complete {
            done = Some(j);
            break;
        }
        fake.step(u64::MAX);
        lowest = lowest.min(disk.free());
    }
    let j = done.expect("the job completes");
    assert_eq!(j.batches, 3, "{j:#?}");
    assert_eq!(j.files_done(), 10);
    assert_eq!(j.bytes_stored, 27_000);
    assert!(lowest >= 10_000, "the free space fell to {lowest}");
    for (n, c) in names.iter().zip(&contents) {
        assert_eq!(
            &e.read_file("season", &format!("Season/{n}")).unwrap(),
            c,
            "{n}"
        );
    }
    assert_eq!(
        fs::read_dir(&base).unwrap().count(),
        0,
        "the download directory is empty"
    );
    // Everything is unwanted and stopped in transmission; a further step
    // changes nothing.
    assert!(fake.wanted(&job.hash).iter().all(|w| !w));
    assert!(!fake.running(&job.hash));
    let again = e
        .torrent_tick(&job.hash, &rpc, &mut disk, true)
        .unwrap()
        .unwrap();
    assert_eq!(again.state, JobState::Complete);
    let v = e.import_verify("season").unwrap();
    assert_eq!(v.blocks_without_storage_copy, 0, "{v:#?}");
    // Removing the job leaves the folder.
    e.torrent_remove(&job.hash, false, Some(&rpc)).unwrap();
    assert!(!fake.has(&job.hash));
    assert!(varsto_core::engine::torrent_jobs_at(&root.join("home")).is_empty());
    assert_eq!(
        e.read_file("season", "Season/cd1/part-00.bin").unwrap(),
        contents[0]
    );
}
