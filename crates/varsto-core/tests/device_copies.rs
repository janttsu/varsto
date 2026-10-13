// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Copies on the vault's own devices count for durability policies: two
//! devices holding every file and one external storage meet the default
//! policy, and the count drops when a device frees a file, detaches the
//! folder, deletes a file or is removed from the vault.

mod common;

use std::fs;
use std::path::PathBuf;
use varsto_core::chunking::ChunkerParams;
use varsto_core::policy::{Policy, PolicyState};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    /// External storage (S3 and the like): place "cloud".
    storage: StorageSpec,
}

impl Lab {
    fn new() -> Lab {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        Lab {
            storage: StorageSpec::LocalDir {
                name: "s3".into(),
                path: root.join("storage"),
                cold: false,
                carrier: false,
                place: "cloud".into(),
            },
            root,
            _tmp: tmp,
        }
    }
    fn home(&self, who: &str) -> PathBuf {
        self.root.join(format!("{who}-home"))
    }
    fn dir(&self, who: &str) -> PathBuf {
        self.root.join(format!("{who}-docs"))
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

/// A creates the vault with two files and the external storage; B joins
/// and downloads both (which verifies A's copies on the storage).
fn two_devices(lab: &Lab) -> (Engine, Engine) {
    let (mut a, key) = Engine::init(&lab.home("a"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.dir("a")).unwrap();
    fs::write(lab.dir("a").join("one.bin"), pseudo_random(30_000, 1)).unwrap();
    fs::write(lab.dir("a").join("two.bin"), pseudo_random(30_000, 2)).unwrap();
    a.sync(None).unwrap();
    let mut b = Engine::join(&lab.home("b"), "desk", PASS, &key, lab.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &lab.dir("b"), false).unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    (a, b)
}

fn home_policy(n: u32) -> Policy {
    Policy {
        min_per_place: [("home".to_string(), n)].into_iter().collect(),
        ..Policy::folder_default()
    }
}

/// Chunks of `docs` the view says `who` holds.
fn held_by(e: &Engine, who: &Engine) -> usize {
    let me = &who.status().unwrap().device_id;
    e.view()
        .unwrap()
        .chunks
        .values()
        .filter(|r| r.holders().any(|d| &d.to_string() == me))
        .count()
}

#[test]
fn own_devices_are_copies_at_home() {
    let lab = Lab::new();
    let (mut a, mut b) = two_devices(&lab);
    // One external storage and two devices: the default policy is met.
    let r = &a.policy_check().unwrap()[0];
    assert_eq!(r.policy, Policy::folder_default());
    assert_eq!(r.state, PolicyState::Ok, "{:?}", r.reasons);
    assert!(r
        .policy
        .describe()
        .contains("1 on your own devices and disks"));
    // Both devices hold every block: two copies at home.
    let all = held_by(&a, &a);
    assert!(all > 0);
    assert_eq!(held_by(&a, &b), all);
    // Nothing changed: a sync records no device copies again.
    let synced = a.sync(None).unwrap();
    assert!(
        synced.iter().all(|(_, push)| push.batch_seq.is_none()),
        "an unchanged sync writes no batch"
    );

    // B frees one.bin: only A holds its blocks now, which still meets the
    // policy.
    b.sync(None).unwrap();
    b.free_file("docs", "one.bin").unwrap();
    b.sync(None).unwrap();
    let two = held_by(&b, &b);
    let one = (all - two) as u64;
    assert!(one > 0 && two > 0);
    a.sync(None).unwrap();
    assert_eq!(held_by(&a, &b), two);
    assert_eq!(held_by(&a, &a), all);
    assert_eq!(a.policy_check().unwrap()[0].state, PolicyState::Ok);

    // A detaches the folder: one.bin is on no device, two.bin on B only.
    a.detach_folder("docs").unwrap();
    assert_eq!(held_by(&a, &a), 0, "the detach lets A's copies go");
    b.sync(None).unwrap();
    assert_eq!(held_by(&b, &a), 0);
    let r = &b.policy_check().unwrap()[0];
    assert_eq!(r.policy, Policy::folder_default());
    assert_eq!(r.state, PolicyState::Violated);
    assert_eq!(r.chunks_short_per_place["home"], one);
    assert!(r
        .reasons
        .iter()
        .any(|m| m.contains("fewer than 1 copies on your own devices and disks")));
    assert_eq!(held_by(&b, &b), two);

    // B deletes two.bin: its blocks are on no device any more.
    fs::remove_file(lab.dir("b").join("two.bin")).unwrap();
    b.sync(None).unwrap();
    assert_eq!(held_by(&b, &b), 0);
}

#[test]
fn a_removed_device_is_no_copy() {
    let lab = Lab::new();
    let (mut a, _b) = two_devices(&lab);
    a.set_policy("docs", Some(home_policy(2))).unwrap();
    assert_eq!(a.policy_check().unwrap()[0].state, PolicyState::Ok);
    a.revoke_device("desk", false).unwrap();
    let r = &a.policy_check().unwrap()[0];
    assert_eq!(r.state, PolicyState::Violated);
    assert!(r.chunks_short_per_place["home"] > 0);
}
