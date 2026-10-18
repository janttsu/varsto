// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Forwarding (spec section 70): a phone whose only storage is full writes
//! a camera folder; a laptop that keeps the folder selective (placeholders)
//! and has the bucket the policy wants carries the phone's blocks from the
//! phone, as a peer, to the bucket, and keeps no files. A locked Strongroom
//! is not forwarded, and two laptops with the same bucket write every block
//! once.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::ForwardOptions;
use varsto_core::policy::{Policy, PolicyState};
use varsto_core::storage::StorageSpec;
use varsto_core::strongroom::{Method, SoftwareKey};
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn dir(name: &str, path: &Path, place: &str) -> StorageSpec {
    fs::create_dir_all(path).unwrap();
    StorageSpec::LocalDir {
        name: name.into(),
        path: path.to_path_buf(),
        cold: false,
        carrier: false,
        place: place.into(),
        min_free: None,
    }
}

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

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
}

impl Lab {
    fn new() -> Lab {
        let tmp = tempfile::tempdir().unwrap();
        Lab {
            root: tmp.path().to_path_buf(),
            _tmp: tmp,
        }
    }
    fn p(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
    /// The storage both devices share for the ledger and the file lists
    /// ("home"): full, so the phone's blocks cannot go there.
    fn hub(&self) -> StorageSpec {
        dir("hub", &self.p("hub"), "home")
    }
    /// The S3-like bucket only the laptops have ("cloud").
    fn bucket(&self) -> StorageSpec {
        dir("bucket", &self.p("bucket"), "cloud")
    }
}

/// The policy of the camera folder: one copy in the cloud.
fn cloud_copy() -> Policy {
    Policy {
        min_copies: 1,
        min_per_place: [("cloud".to_string(), 1)].into_iter().collect(),
        verified_within_days: None,
    }
}

/// A phone with the camera folder and three pictures that went nowhere
/// (its only storage is at its quota). Returns the phone and the vault key.
fn phone(lab: &Lab) -> (Engine, String) {
    let (mut phone, key) = Engine::init(&lab.p("phone-home"), "phone", PASS).unwrap();
    phone.chunker = ChunkerParams::SMALL;
    phone.add_storage(lab.hub()).unwrap();
    phone.set_storage_quota("hub", None, Some(Some(1))).unwrap();
    let files = lab.p("phone-camera");
    fs::create_dir_all(&files).unwrap();
    phone.add_folder("camera", &files).unwrap();
    phone.set_policy("camera", Some(cloud_copy())).unwrap();
    for (i, name) in ["a.jpg", "b.jpg", "c.mp4"].iter().enumerate() {
        fs::write(files.join(name), pseudo_random(150_000, i as u64 + 1)).unwrap();
    }
    phone.sync(None).unwrap();
    assert_eq!(
        common::object_count(&lab.p("hub")),
        0,
        "the full storage takes no blocks"
    );
    (phone, key)
}

/// A laptop that joins with the shared storage, adds the bucket and
/// attaches the camera folder with selective sync.
fn laptop(lab: &Lab, name: &str, key: &str, owner: &mut Engine) -> Engine {
    let home = lab.p(&format!("{name}-home"));
    let mut l = common::join_approved(&home, name, PASS, key, lab.hub(), owner);
    l.chunker = ChunkerParams::SMALL;
    l.add_storage(lab.bucket()).unwrap();
    l.attach_folder("camera", &lab.p(&format!("{name}-camera")), true)
        .unwrap();
    l.sync(None).unwrap();
    l
}

/// The phone serves its blocks over TLS on TCP to `to`.
fn serve(phone: &mut Engine, to: &mut [&mut Engine]) -> common::p2p::Serving {
    let serving = common::p2p::Serving::start(phone);
    common::p2p::connect(phone, &serving, to);
    serving
}

fn camera_state(e: &Engine) -> PolicyState {
    e.policy_check()
        .unwrap()
        .into_iter()
        .find(|r| r.folder == "camera")
        .unwrap()
        .state
}

/// Files under a directory, by name.
fn names_in(path: &Path) -> BTreeSet<String> {
    match fs::read_dir(path) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(_) => BTreeSet::new(),
    }
}

/// Lease objects of forwarding left on a storage directory.
fn leases(root: &Path) -> usize {
    let dir = root.join("vault").join("forward-leases");
    if !dir.exists() {
        return 0;
    }
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count()
}

#[test]
fn a_selective_laptop_carries_the_phones_blocks_to_the_bucket() {
    let lab = Lab::new();
    let (mut phone, key) = phone(&lab);
    let mut laptop = laptop(&lab, "laptop", &key, &mut phone);
    assert_eq!(
        common::object_count(&lab.p("bucket")),
        0,
        "a selective push writes nothing: the laptop has no file"
    );
    assert_eq!(camera_state(&laptop), PolicyState::Violated);

    // Nobody to fetch from: every block waits.
    let r = laptop.forward(&ForwardOptions::manual()).unwrap();
    assert_eq!(r.blocks, 0, "{r:?}");
    let waiting = r.folders[0].unavailable;
    assert!(waiting > 0, "{r:?}");
    assert_eq!(common::object_count(&lab.p("bucket")), 0);

    // The phone is online.
    let served = serve(&mut phone, &mut [&mut laptop]);
    let r = laptop.forward(&ForwardOptions::manual()).unwrap();
    let f = &r.folders[0];
    assert_eq!(f.blocks, waiting, "{r:?}");
    assert_eq!(f.unavailable, 0, "{r:?}");
    assert_eq!(f.sources.get("peer phone"), Some(&waiting), "{r:?}");
    assert_eq!(f.for_devices, vec!["phone".to_string()], "{r:?}");
    assert_eq!(f.to_storages.get("bucket"), Some(&waiting), "{r:?}");
    assert!(
        !f.to_storages.contains_key("hub"),
        "the full storage is left alone"
    );
    assert!(!r.work_left);
    assert!(
        r.describe().contains("of camera for phone"),
        "{}",
        r.describe()
    );
    assert_eq!(common::object_count(&lab.p("bucket")) as u64, waiting);
    assert_eq!(
        leases(&lab.p("bucket")) + leases(&lab.p("hub")),
        0,
        "leases given back"
    );
    drop(served);

    // The laptop still keeps only placeholders, and nothing in a cache.
    let here = names_in(&lab.p("laptop-camera"));
    for name in ["a.jpg", "b.jpg", "c.mp4"] {
        assert!(!here.contains(name), "{here:?}");
        assert!(
            here.contains(&format!("{name}.varsto-placeholder")),
            "{here:?}"
        );
    }
    assert!(
        names_in(&lab.p("laptop-home").join("block-cache").join("chunks")).is_empty(),
        "no cached blocks"
    );

    // The policy that needs a cloud copy is kept now.
    assert_eq!(camera_state(&laptop), PolicyState::Ok);

    // The copies are the laptop's claims, and its own read-back is not a
    // verification by another device.
    let view = laptop.ledger_view3().unwrap();
    let me: [u8; 16] = hex::decode(laptop.device_id().as_str())
        .unwrap()
        .try_into()
        .unwrap();
    let packs = laptop.packs_on_storage3("bucket").unwrap();
    assert!(!packs.is_empty());
    for id in packs.keys() {
        let id: [u8; 32] = hex::decode(id).unwrap().try_into().unwrap();
        for c in view.copies(&id) {
            assert_eq!(c.claimed_by, vec![me]);
            assert!(!c.independently_verified);
        }
    }
    let claimed = laptop.objects_on_storage3("bucket").unwrap().len();
    assert_eq!(claimed as u64, waiting);

    // Nothing is left to do.
    let r = laptop.forward(&ForwardOptions::manual()).unwrap();
    assert!(r.folders.is_empty() && r.blocks == 0, "{r:?}");

    // Another device reads the pictures from the bucket alone, with the
    // phone offline: they are complete and intact there.
    let mut desk = common::join_approved(
        &lab.p("desk-home"),
        "desk",
        PASS,
        &key,
        lab.hub(),
        &mut phone,
    );
    desk.add_storage(lab.bucket()).unwrap();
    desk.attach_folder("camera", &lab.p("desk-camera"), false)
        .unwrap();
    desk.sync(None).unwrap();
    for name in ["a.jpg", "b.jpg", "c.mp4"] {
        assert_eq!(
            fs::read(lab.p("desk-camera").join(name)).unwrap(),
            fs::read(lab.p("phone-camera").join(name)).unwrap()
        );
    }
    // The phone learns of the copies too.
    phone.sync(None).unwrap();
    let pv = phone.ledger_view3().unwrap();
    assert!(pv.packs.keys().any(|p| pv.is_held(p, "bucket")));
}

#[test]
fn turned_off_it_forwards_nothing() {
    let lab = Lab::new();
    let (mut phone, key) = phone(&lab);
    let mut laptop = laptop(&lab, "laptop", &key, &mut phone);
    let _served = serve(&mut phone, &mut [&mut laptop]);
    laptop.set_forwarding(false).unwrap();
    let r = laptop.forward(&ForwardOptions::manual()).unwrap();
    assert!(!r.enabled && r.blocks == 0, "{r:?}");
    assert_eq!(common::object_count(&lab.p("bucket")), 0);
    assert_eq!(laptop.forward_status().describe(), "forwarding: off");
    laptop.set_forwarding(true).unwrap();
    assert!(laptop.forward(&ForwardOptions::manual()).unwrap().blocks > 0);
}

#[test]
fn a_locked_strongroom_is_not_forwarded() {
    let lab = Lab::new();
    let (mut phone, key) = Engine::init(&lab.p("phone-home"), "phone", PASS).unwrap();
    phone.chunker = ChunkerParams::SMALL;
    phone.add_storage(lab.hub()).unwrap();
    phone.set_storage_quota("hub", None, Some(Some(1))).unwrap();
    let sk = SoftwareKey {
        path: lab.p("phone-home").join("software-security-key"),
    };
    phone
        .create_strongroom("vault", &lab.p("phone-vault"), Method::Software, &sk, 15)
        .unwrap();
    fs::write(
        lab.p("phone-vault").join("deed.pdf"),
        pseudo_random(90_000, 9),
    )
    .unwrap();
    phone.sync(None).unwrap();
    assert_eq!(common::object_count(&lab.p("hub")), 0);

    let mut laptop = Engine::join(&lab.p("laptop-home"), "laptop", PASS, &key, lab.hub()).unwrap();
    laptop.chunker = ChunkerParams::SMALL;
    laptop.add_storage(lab.bucket()).unwrap();
    laptop
        .attach_folder("vault", &lab.p("laptop-vault"), true)
        .unwrap();
    let _ = laptop.sync(None);
    let _served = serve(&mut phone, &mut [&mut laptop]);

    // Locked: the laptop holds no key for the folder and forwards nothing.
    let r = laptop.forward(&ForwardOptions::manual()).unwrap();
    assert_eq!(r.no_key, vec!["vault".to_string()], "{r:?}");
    assert_eq!(r.blocks, 0);
    assert_eq!(common::object_count(&lab.p("bucket")), 0);

    // Unlocked with the security key: now it does.
    let name = sk.path.file_name().unwrap();
    fs::copy(&sk.path, lab.p("laptop-home").join(name)).unwrap();
    laptop.unlock_strongroom_enrolled("vault", 5).unwrap();
    laptop.sync(None).unwrap();
    let r = laptop.forward(&ForwardOptions::manual()).unwrap();
    assert!(r.no_key.is_empty(), "{r:?}");
    assert!(r.blocks > 0, "{r:?}");
    assert_eq!(common::object_count(&lab.p("bucket")) as u64, r.blocks);
}

#[test]
fn two_laptops_with_one_bucket_write_every_block_once() {
    let lab = Lab::new();
    let (mut phone, key) = phone(&lab);
    let mut one = laptop(&lab, "laptop1", &key, &mut phone);
    let mut two = laptop(&lab, "laptop2", &key, &mut phone);
    let _served = serve(&mut phone, &mut [&mut one, &mut two]);

    // The first stops after one block (its budget) and keeps the lease.
    let small = ForwardOptions {
        max_blocks: 1,
        ..ForwardOptions::manual()
    };
    let r = one.forward(&small).unwrap();
    assert_eq!(r.blocks, 1, "{r:?}");
    assert!(r.work_left && r.folders[0].left > 0, "{r:?}");
    assert!(leases(&lab.p("bucket")) > 0 && leases(&lab.p("hub")) > 0);

    // The second sees the lease and leaves the folder to the first.
    let r = two.forward(&ForwardOptions::manual()).unwrap();
    assert_eq!(r.blocks, 0, "{r:?}");
    assert_eq!(r.folders[0].busy.as_deref(), Some("laptop1"), "{r:?}");
    assert_eq!(common::object_count(&lab.p("bucket")), 1);

    // The first carries on where it stopped and gives the lease back.
    let r = one.forward(&ForwardOptions::manual()).unwrap();
    assert!(r.blocks > 0 && !r.work_left, "{r:?}");
    assert_eq!(leases(&lab.p("bucket")) + leases(&lab.p("hub")), 0);

    // The second finds nothing left: the first one's claims are in the ledger.
    let r = two.forward(&ForwardOptions::manual()).unwrap();
    assert_eq!(r.blocks, 0, "{r:?}");
    assert!(r.folders.iter().all(|f| f.busy.is_none()), "{r:?}");

    // Every block is on the bucket exactly once.
    let blocks = common::blocks(&lab.p("bucket"));
    let names: BTreeSet<&String> = blocks.iter().map(|(o, _, _)| o).collect();
    assert_eq!(names.len(), blocks.len(), "a block written twice");
    assert_eq!(camera_state(&two), PolicyState::Ok);
}
