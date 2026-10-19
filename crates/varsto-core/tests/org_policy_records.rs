// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Signed policy records (kind 11, `docs/spec/alpha-0-format.md` sections
//! 27 and 77): a tampered or junk record in a device's policy stream is
//! refused and does not hide the real one, and in an organization a
//! member's policy is adopted only when the organization lets members set
//! policies.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::org::OrgPolicy;
use varsto_core::policy::Policy;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn storage(root: &Path) -> StorageSpec {
    StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

fn copies(n: u32) -> Option<Policy> {
    Some(Policy {
        min_copies: n,
        min_per_place: Default::default(),
        verified_within_days: None,
    })
}

fn min_copies(e: &Engine) -> Option<u32> {
    let docs = e
        .folders()
        .into_iter()
        .find(|(r, _)| r.name == "docs")
        .unwrap()
        .0;
    docs.policy.as_ref().map(|p| p.min_copies)
}

/// A creates the vault with one file; the others join, are approved for the
/// folder and sync it.
fn vault(root: &Path, others: &[&str]) -> (Engine, Vec<Engine>) {
    let (a, key) = Engine::init(&root.join("a-home"), "hq", PASS).unwrap();
    let mut a = a;
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage(root)).unwrap();
    let docs = root.join("a-docs");
    a.add_folder("docs", &docs).unwrap();
    fs::write(docs.join("one.txt"), b"a file").unwrap();
    a.push("docs").unwrap();
    let mut out = Vec::new();
    for who in others {
        let mut e = common::join_approved(
            &root.join(format!("{who}-home")),
            who,
            PASS,
            &key,
            storage(root),
            &mut a,
        );
        e.chunker = ChunkerParams::SMALL;
        e.attach_folder("docs", &root.join(format!("{who}-docs")), false)
            .unwrap();
        e.sync(None).unwrap();
        out.push(e);
    }
    a.sync(None).unwrap();
    (a, out)
}

/// The record files of a device's policy stream, oldest first.
fn policy_records(root: &Path, device: &impl std::fmt::Display) -> Vec<PathBuf> {
    let dir = root
        .join("storage")
        .join("vault/policy")
        .join(device.to_string());
    let mut out: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "rec"))
        .collect();
    out.sort();
    out
}

/// `<prefix><seq>-0000.rec` with a seq `ahead` above the stream's last one.
fn next_name(records: &[PathBuf], ahead: u64) -> PathBuf {
    let last = records.last().unwrap();
    let name = last.file_name().unwrap().to_str().unwrap();
    let stem = &name[..name.len() - "-0000.rec".len()];
    let (prefix, seq) = stem.split_at(stem.len() - 16);
    let seq: u64 = seq.parse().unwrap();
    last.with_file_name(format!("{prefix}{:016}-0000.rec", seq + ahead))
}

#[test]
fn tampered_and_junk_policy_records_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, mut others) = vault(root, &["b"]);
    let mut b = others.pop().unwrap();

    a.set_policy("docs", copies(2)).unwrap();
    b.sync(None).unwrap();
    assert_eq!(min_copies(&b), Some(2), "the signed record is adopted");

    // Junk under the next seqs of A's stream, and A's newest record with a
    // byte changed: none of them is adopted, and the real record stays.
    let before = policy_records(root, a.device_id());
    fs::write(next_name(&before, 1), b"not a record").unwrap();
    fs::write(next_name(&before, 2), vec![0u8; 4096]).unwrap();
    a.set_policy("docs", copies(3)).unwrap();
    let after = policy_records(root, a.device_id());
    let newest = after
        .iter()
        .filter(|p| !before.contains(p))
        .max()
        .expect("A wrote a new record")
        .clone();
    let mut bytes = fs::read(&newest).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x40;
    fs::write(&newest, &bytes).unwrap();
    b.sync(None).unwrap();
    assert_eq!(min_copies(&b), Some(2), "a tampered record is adopted");

    // The writer goes on past the junk, and its next record is adopted.
    a.set_policy("docs", copies(1)).unwrap();
    b.sync(None).unwrap();
    assert_eq!(min_copies(&b), Some(1));
}

#[test]
fn a_members_policy_needs_the_organization_to_allow_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, mut others) = vault(root, &["b", "c"]);
    let mut c = others.pop().unwrap();
    let mut b = others.pop().unwrap();

    // B sets a policy before the organization exists, and C has not read
    // it yet. A founds the organization: B is a member, not an admin.
    b.set_policy("docs", copies(3)).unwrap();
    a.org_create("Acme", "alice").unwrap();
    c.sync(None).unwrap();
    assert!(c.org().is_some());
    assert_ne!(min_copies(&c), Some(3), "a member's policy is adopted");
    // B learns it, and may no longer set one.
    b.sync(None).unwrap();
    assert!(b.set_policy("docs", copies(4)).is_err());

    // The organization lets members set policies: B's record counts.
    a.org_set_policy(OrgPolicy {
        members_may_set_policies: true,
        ..OrgPolicy::default()
    })
    .unwrap();
    c.sync(None).unwrap();
    assert_eq!(min_copies(&c), Some(3));
}
