// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Tests of the format-3 fsck on a vault with real packs, maps, manifests
//! and ledger batches on local-directory storages.

use super::testkit::*;
use super::*;
use crate::blockmap::WrittenPack;
use crate::ledger3::LedgerView;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A vault of one device with two storages: pack `a` on both, `b` on both,
/// `c` on h1 only; two files over their blocks.
struct Vault {
    kit: Kit,
    a: WrittenPack,
    b: WrittenPack,
    c: WrittenPack,
}

fn vault() -> Vault {
    let mut kit = Kit::new(1);
    kit.enroll(0);
    let a = kit.pack(&[0, 1], 3);
    let b = kit.pack(&[0, 1], 2);
    let c = kit.pack(&[0], 2);
    let files = [
        (
            "docs/a.txt",
            vec![
                a.members[0].object,
                a.members[1].object,
                b.members[0].object,
            ],
        ),
        ("docs/b.txt", vec![c.members[0].object, c.members[1].object]),
    ];
    kit.publish(0, &[a.clone(), b.clone(), c.clone()], &files, None);
    Vault { kit, a, b, c }
}

fn input<'a>(
    view: &'a LedgerView,
    storages: &'a [StorageDesc<'a>],
    folders: &'a [FolderInput<'a>],
) -> Fsck3Input<'a> {
    Fsck3Input {
        view,
        storages,
        folders,
        records: None,
        refused: None,
        modified_utc: None,
        verify_pack: None,
        now_utc: 1_000_000_000,
    }
}

fn folder_input<'a>(
    kit: &'a Kit,
    manifests: &'a crate::manifest3::FolderManifests,
) -> FolderInput<'a> {
    FolderInput {
        id: FOLDER,
        name: "docs".into(),
        map: &kit.devs[0].table,
        manifests,
    }
}

/// The verification of WP5, stood in: read the pack and hash it.
fn hash_verify(calls: &AtomicUsize) -> impl Fn(&PackCheck) -> PackVerdict + Sync + '_ {
    move |c| {
        calls.fetch_add(1, Ordering::SeqCst);
        match c.backend.get(&crate::packs::pack_key(&hex::encode(c.pack))) {
            Ok(Some(b)) if crate::crypto::hash(&b) == c.pack => PackVerdict::Ok,
            Ok(Some(_)) => PackVerdict::Corrupt("the bytes do not hash to the pack id".into()),
            Ok(None) => PackVerdict::Missing,
            Err(e) => PackVerdict::Unreadable(format!("{e:#}")),
        }
    }
}

#[test]
fn a_clean_vault_is_clean() {
    let v = vault();
    let view = v.kit.view(0);
    let descs = v.kit.descs();
    let m = v.kit.manifests();
    let folders = [folder_input(&v.kit, &m)];
    let probe = AcceptorProbe {
        vault: VAULT,
        keys: &v.kit.keys,
        trust: &v.kit.trust,
    };
    let calls = AtomicUsize::new(0);
    let verify = hash_verify(&calls);
    let mut inp = input(&view, &descs, &folders);
    inp.records = Some(&probe);
    inp.verify_pack = Some(&verify);
    let r = fsck(&inp, &Fsck3Options { verify: true }).unwrap();
    assert!(r.is_clean(), "{}", r.describe());
    assert_eq!(r.packs, 3);
    assert_eq!(r.copies_claimed, 5);
    assert_eq!(r.copies_present, 5);
    assert_eq!(r.copies_verified_now, 5);
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    assert_eq!(r.blocks.referenced, 5);
    assert_eq!(r.blocks.live, 5);
    assert!(r.orphans.is_empty() && r.damaged_files.is_empty());
    // The map and the manifest of the one batch were probed on both storages.
    assert_eq!(r.records.announced, 2);
    assert_eq!(r.records.checked, 4);
    assert!(r.records.missing.is_empty() && r.records.refused.is_empty());
    assert!(r.describe().starts_with("packs 3 | copies claimed 5"));
    // The JSON is the report.
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["packs"], 3);
    assert!(json["damaged_files"].as_array().unwrap().is_empty());
}

#[test]
fn verify_needs_the_callback() {
    let v = vault();
    let view = v.kit.view(0);
    let descs = v.kit.descs();
    let err = fsck(&input(&view, &descs, &[]), &Fsck3Options { verify: true }).unwrap_err();
    assert!(format!("{err}").contains("verify_pack"));
}

#[test]
fn a_deleted_pack_is_reported_and_copied_back_from_the_other_storage() {
    let v = vault();
    v.kit.delete_pack(1, &v.a.id);
    let view = v.kit.view(0);
    let descs = v.kit.descs();
    let m = v.kit.manifests();
    let folders = [folder_input(&v.kit, &m)];
    let inp = input(&view, &descs, &folders);
    let mut r = fsck(&inp, &Fsck3Options::default()).unwrap();
    assert_eq!(r.missing_copies.len(), 1, "{}", r.describe());
    assert_eq!(r.missing_copies[0].pack, hex::encode(v.a.id));
    assert_eq!(r.missing_copies[0].storage, "h2");
    // h1 still holds it, so no file is damaged.
    assert!(r.damaged_files.is_empty());
    assert!(!r.is_clean());

    fix(&inp, &mut r, &FixOptions::default()).unwrap();
    assert_eq!(r.fixed.len(), 1);
    assert_eq!(
        (r.fixed[0].from.as_str(), r.fixed[0].to.as_str()),
        ("h1", "h2")
    );
    assert!(r.missing_copies.is_empty() && r.fix_failed.is_empty());
    // The copy is the pack again; nothing needed announcing.
    let again = fsck(&inp, &Fsck3Options::default()).unwrap();
    assert!(again.is_clean(), "{}", again.describe());
    assert_eq!(again.copies_present, 5);
}

#[test]
fn a_pack_lost_everywhere_damages_its_files_and_cannot_be_fixed() {
    let v = vault();
    v.kit.delete_pack(0, &v.c.id); // c was on h1 only
    let view = v.kit.view(0);
    let descs = v.kit.descs();
    let m = v.kit.manifests();
    let folders = [folder_input(&v.kit, &m)];
    let inp = input(&view, &descs, &folders);
    let mut r = fsck(&inp, &Fsck3Options::default()).unwrap();
    assert_eq!(r.damaged_files.len(), 1);
    assert_eq!(r.damaged_files[0].path, "docs/b.txt");
    assert_eq!(r.damaged_files[0].blocks_missing, 2);
    assert_eq!(r.blocks.missing, 2);
    assert!(r.describe().contains("file damaged (block missing)"));
    fix(&inp, &mut r, &FixOptions::default()).unwrap();
    assert_eq!(r.fix_failed.len(), 1);
    assert_eq!(r.missing_copies.len(), 1);
    assert!(r.fixed.is_empty());
}

#[test]
fn a_flipped_byte_is_found_by_verify_only() {
    let v = vault();
    v.kit.flip_byte(0, &v.b.id);
    let view = v.kit.view(0);
    let descs = v.kit.descs();
    let m = v.kit.manifests();
    let folders = [folder_input(&v.kit, &m)];
    let calls = AtomicUsize::new(0);
    let verify = hash_verify(&calls);
    let mut inp = input(&view, &descs, &folders);
    inp.verify_pack = Some(&verify);
    // The length is right, so the plain check cannot see it.
    let plain = fsck(&inp, &Fsck3Options::default()).unwrap();
    assert!(plain.is_clean());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let r = fsck(&inp, &Fsck3Options { verify: true }).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    assert_eq!(r.corrupt_copies.len(), 1, "{}", r.describe());
    assert_eq!(r.corrupt_copies[0].storage, "h1");
    assert_eq!(r.copies_verified_now, 4);
    // h2 holds a good copy, so the files are fine; fix hands it to repair.
    assert!(r.damaged_files.is_empty());
    let mut r = r;
    let handed = std::cell::RefCell::new(Vec::new());
    let repair = |i: &PackIssue| -> anyhow::Result<bool> {
        handed.borrow_mut().push(i.clone());
        Ok(true)
    };
    fix(
        &inp,
        &mut r,
        &FixOptions {
            repair_pack: Some(&repair),
        },
    )
    .unwrap();
    assert_eq!(handed.borrow().len(), 1);
    assert!(r.corrupt_copies.is_empty());
    assert_eq!(r.handed_to_repair.len(), 1);
}

#[test]
fn a_corrupt_pack_on_every_storage_damages_the_file() {
    let v = vault();
    v.kit.flip_byte(0, &v.b.id);
    v.kit.flip_byte(1, &v.b.id);
    let view = v.kit.view(0);
    let descs = v.kit.descs();
    let m = v.kit.manifests();
    let folders = [folder_input(&v.kit, &m)];
    let calls = AtomicUsize::new(0);
    let verify = hash_verify(&calls);
    let mut inp = input(&view, &descs, &folders);
    inp.verify_pack = Some(&verify);
    let r = fsck(&inp, &Fsck3Options { verify: true }).unwrap();
    assert_eq!(r.corrupt_copies.len(), 2);
    assert_eq!(r.damaged_files.len(), 1);
    assert_eq!(r.damaged_files[0].path, "docs/a.txt");
    assert_eq!(r.damaged_files[0].blocks_missing, 1);
}

#[test]
fn a_pack_of_the_wrong_length_is_reported() {
    let v = vault();
    let p = v.kit.pack_path(1, &v.b.id);
    let mut bytes = std::fs::read(&p).unwrap();
    bytes.truncate(bytes.len() - 5);
    std::fs::write(&p, bytes).unwrap();
    let longer = v.kit.pack_path(0, &v.a.id);
    let mut bytes = std::fs::read(&longer).unwrap();
    bytes.push(0);
    std::fs::write(&longer, bytes).unwrap();
    let view = v.kit.view(0);
    let descs = v.kit.descs();
    let r = fsck(&input(&view, &descs, &[]), &Fsck3Options::default()).unwrap();
    assert_eq!(r.wrong_length.len(), 2, "{}", r.describe());
    assert!(r.wrong_length.iter().any(|i| i.detail.contains("shorter")));
    assert!(r.wrong_length.iter().any(|i| i.detail.contains("longer")));
}

#[test]
fn an_orphan_pack_is_reported_and_flagged_after_seven_days() {
    let mut v = vault();
    let old = v.kit.orphan(1);
    let young = v.kit.orphan(1);
    let view = v.kit.view(0);
    let descs = v.kit.descs();
    let now = 1_000_000_000;
    let age = move |_: &str, id: &crate::ledger3::PackId| {
        Some(if *id == old {
            now - 8 * 86_400
        } else {
            now - 86_400
        })
    };
    let mut inp = input(&view, &descs, &[]);
    inp.modified_utc = Some(&age);
    let r = fsck(&inp, &Fsck3Options::default()).unwrap();
    assert_eq!(r.orphans.len(), 2, "{}", r.describe());
    let o_old = r
        .orphans
        .iter()
        .find(|o| o.pack == hex::encode(old))
        .unwrap();
    let o_young = r
        .orphans
        .iter()
        .find(|o| o.pack == hex::encode(young))
        .unwrap();
    assert!(o_old.gc_due && o_old.age_days == Some(8) && o_old.kind == "unknown");
    assert!(!o_young.gc_due && o_young.age_days == Some(1));
    assert_eq!(o_old.bytes, Some(PACK_LEN as u64));
    // Orphans are not a problem of the vault.
    assert!(r.is_clean());
    // Without the age hook nothing is ever due.
    let r = fsck(&input(&view, &descs, &[]), &Fsck3Options::default()).unwrap();
    assert!(r.orphans.iter().all(|o| !o.gc_due && o.age_days.is_none()));
}

#[test]
fn a_pack_claimed_on_one_storage_only_is_an_orphan_on_the_other() {
    let v = vault();
    // c is claimed on h1; a copy appears on h2 without a claim.
    let bytes = std::fs::read(v.kit.pack_path(0, &v.c.id)).unwrap();
    std::fs::create_dir_all(v.kit.pack_path(1, &v.c.id).parent().unwrap()).unwrap();
    std::fs::write(v.kit.pack_path(1, &v.c.id), bytes).unwrap();
    let view = v.kit.view(0);
    let descs = v.kit.descs();
    let m = v.kit.manifests();
    let folders = [folder_input(&v.kit, &m)];
    let r = fsck(&input(&view, &descs, &folders), &Fsck3Options::default()).unwrap();
    assert_eq!(r.orphans.len(), 1);
    // A map names it, so it is not for collection.
    assert_eq!(r.orphans[0].kind, "mapped");
    assert!(!r.orphans[0].gc_due);
}

#[test]
fn a_map_place_outside_its_pack_is_reported() {
    // The map says the pack is 16 MiB, the ledger (and the file) 256 KiB.
    let mut kit = Kit::new(1);
    kit.enroll(0);
    let mut p = kit.pack(&[0, 1], 1);
    p.class = 3;
    p.members[0].offset = 5 << 20;
    kit.publish(0, std::slice::from_ref(&p), &[], Some(0));
    let view = kit.view(0);
    let descs = kit.descs();
    let m = kit.manifests();
    let folders = [folder_input(&kit, &m)];
    let r = fsck(&input(&view, &descs, &folders), &Fsck3Options::default()).unwrap();
    assert_eq!(r.maps.len(), 1);
    assert_eq!(r.maps[0].outside_pack.len(), 1, "{}", r.describe());
    assert_eq!(r.maps[0].class_mismatch.len(), 1);
    assert!(!r.is_clean());
    assert!(r.describe().contains("place outside its pack"));
}

#[test]
fn overlapping_places_are_reported() {
    let mut kit = Kit::new(1);
    kit.enroll(0);
    let mut p = kit.pack(&[0, 1], 2);
    // The second member starts inside the first and names another object.
    p.members[1].offset = 500;
    kit.publish(0, &[p], &[], None);
    let view = kit.view(0);
    let descs = kit.descs();
    let m = kit.manifests();
    let folders = [folder_input(&kit, &m)];
    let r = fsck(&input(&view, &descs, &folders), &Fsck3Options::default()).unwrap();
    assert_eq!(r.maps[0].overlapping.len(), 1, "{}", r.describe());
    assert!(!r.is_clean());
}

#[test]
fn a_place_in_a_pack_the_ledger_never_claimed_is_reported() {
    let mut kit = Kit::new(1);
    kit.enroll(0);
    // A pack written to no storage: the batch claims nothing for it.
    let mut ghost = kit.pack(&[], 1);
    ghost.storages.clear();
    kit.publish(0, &[ghost], &[], None);
    let view = kit.view(0);
    let descs = kit.descs();
    let m = kit.manifests();
    let folders = [folder_input(&kit, &m)];
    let r = fsck(&input(&view, &descs, &folders), &Fsck3Options::default()).unwrap();
    assert_eq!(r.maps[0].unknown_pack.len(), 1, "{}", r.describe());
}

#[test]
fn a_record_that_is_gone_from_the_storages_is_reported() {
    let v = vault();
    // The block map record disappears from both storages, the manifest from h2.
    for s in 0..2 {
        let dir = v.kit.dir.path().join(v.kit.st[s].name()).join("maps");
        std::fs::remove_dir_all(dir).unwrap();
    }
    std::fs::remove_dir_all(v.kit.dir.path().join("h2").join("manifests")).unwrap();
    let view = v.kit.view(0);
    let descs = v.kit.descs();
    let m = v.kit.manifests();
    let folders = [folder_input(&v.kit, &m)];
    let probe = AcceptorProbe {
        vault: VAULT,
        keys: &v.kit.keys,
        trust: &v.kit.trust,
    };
    let mut inp = input(&view, &descs, &folders);
    inp.records = Some(&probe);
    let r = fsck(&inp, &Fsck3Options::default()).unwrap();
    assert_eq!(r.records.missing.len(), 1, "{}", r.describe());
    assert_eq!(r.records.missing[0].kind, "block-map");
    assert_eq!(r.records.missing_on.len(), 1);
    assert_eq!(r.records.missing_on[0].storage, "h2");
    assert!(!r.is_clean());
}

#[test]
fn a_record_with_another_body_than_announced_is_refused() {
    let v = vault();
    // Flip a byte of the manifest on h1: its hash is not what the batch
    // announced.
    let dir = v.kit.dir.path().join("h1").join("manifests");
    let file = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .find(|e| e.file_type().is_file())
        .unwrap()
        .into_path();
    let mut b = std::fs::read(&file).unwrap();
    let n = b.len();
    b[n - 3] ^= 1;
    std::fs::write(&file, b).unwrap();
    let view = v.kit.view(0);
    let descs = v.kit.descs();
    let m = v.kit.manifests();
    let folders = [folder_input(&v.kit, &m)];
    let probe = AcceptorProbe {
        vault: VAULT,
        keys: &v.kit.keys,
        trust: &v.kit.trust,
    };
    let mut inp = input(&view, &descs, &folders);
    inp.records = Some(&probe);
    let r = fsck(&inp, &Fsck3Options::default()).unwrap();
    assert_eq!(r.records.refused.len(), 1, "{}", r.describe());
    assert_eq!(r.records.refused[0].storage, "h1");
    // h2 still has the good one.
    assert!(r.records.missing.is_empty());
}

#[test]
fn forked_devices_and_refusals_are_carried_into_the_report() {
    let v = vault();
    let mut view = v.kit.view(0);
    view.forked.insert([9; 16]);
    view.events_refused = 3;
    view.marks_refused = 2;
    let descs = v.kit.descs();
    let mut refused = crate::record::RecordsRefused::default();
    refused.by_kind.insert("block-map".into(), 4);
    let mut inp = input(&view, &descs, &[]);
    inp.refused = Some(&refused);
    let r = fsck(&inp, &Fsck3Options::default()).unwrap();
    assert_eq!(r.forked_devices, vec![hex::encode([9u8; 16])]);
    assert_eq!(r.events_refused, 3);
    assert_eq!(r.marks_refused, 2);
    assert_eq!(r.records_refused["block-map"], 4);
    assert!(!r.is_clean());
}

#[test]
fn a_claim_on_a_storage_that_was_not_given_is_unchecked() {
    let v = vault();
    let view = v.kit.view(0);
    let all = v.kit.descs();
    let only_h1 = &all[..1];
    let r = fsck(&input(&view, only_h1, &[]), &Fsck3Options::default()).unwrap();
    assert_eq!(r.unchecked_storages, vec!["h2".to_string()]);
    assert!(r.is_clean());
}
