// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Tests of the ledger rebuild on the pack-level format: a device whose
//! ledger directory is gone, with and without its batches on the storages.

use super::*;
use crate::fsck3::testkit::*;
use crate::fsck3::{PackCheck, PackVerdict};
use crate::ledger3::checkpoint::batch_key;
use crate::ledger3::{Ingest, LedgerView, PackId};
use crate::storage::Storage;
use std::collections::BTreeMap;

fn verify_by_hash(c: &PackCheck) -> PackVerdict {
    match c.backend.get(&crate::packs::pack_key(&hex::encode(c.pack))) {
        Ok(Some(b)) if crate::crypto::hash(&b) == c.pack => PackVerdict::Ok,
        Ok(Some(_)) => PackVerdict::Corrupt("hash".into()),
        Ok(None) => PackVerdict::Missing,
        Err(e) => PackVerdict::Unreadable(format!("{e:#}")),
    }
}

#[derive(Default)]
struct Extras<'x> {
    fill_own: Option<&'x dyn Fn(u64) -> Option<SignedRecord>>,
    no_verify: bool,
    marker_dir: Option<&'x std::path::Path>,
}

/// Rebuild device `d` of the kit into `store`.
fn run(
    kit: &Kit,
    d: usize,
    store: &mut LedgerStore,
    x: Extras,
) -> Result<RebuildReport, RebuildError> {
    let key_for = key_for(&kit.ledger_key);
    let pubkey_of = |dev: &DeviceBin| kit.trust.keys.get(dev).cloned();
    let descs = kit.descs();
    let input = RebuildInput {
        vault: VAULT,
        me: kit.devs[d].id,
        device_name: format!("device {d}"),
        signer: &kit.devs[d].sk,
        ledger_key: &kit.ledger_key,
        key_id: LEDGER_KEY_ID.to_string(),
        key_for: &key_for,
        scope_of: &scope_of,
        pubkey_of: &pubkey_of,
        storages: &descs,
        folders: vec![FOLDER],
        record_keys: &kit.keys,
        record_trust: &kit.trust,
        verify_pack: if x.no_verify {
            None
        } else {
            Some(&verify_by_hash)
        },
        fill_own: x.fill_own,
        marker_dir: x.marker_dir,
    };
    rebuild(store, &input, &RebuildOptions::default())
}

fn fresh_store(kit: &Kit, name: &str) -> LedgerStore {
    LedgerStore::open(&kit.dir.path().join(name).join("ledger"), VAULT).unwrap()
}

fn view_of(kit: &Kit, store: &LedgerStore) -> LedgerView {
    let k = key_for(&kit.ledger_key);
    store.view_scoped(&k, |_, _| true, scope_of).unwrap()
}

/// What a view says, without the stamps of the batches that said it.
#[allow(clippy::type_complexity)]
#[derive(Debug, PartialEq, Eq)]
struct Summary {
    packs: BTreeMap<PackId, (u8, Option<[u8; 16]>, u64, Vec<(String, bool)>)>,
    streams: BTreeMap<(u8, [u8; 16], [u8; 16]), Vec<(u64, [u8; 32], u64)>>,
    folders: Vec<[u8; 16]>,
}

fn summary(v: &LedgerView, claimant: &DeviceBin) -> Summary {
    Summary {
        packs: v
            .packs
            .iter()
            .map(|(id, r)| {
                let copies = v
                    .copies(id)
                    .into_iter()
                    .map(|c| (c.storage, c.claimed_by.contains(claimant)))
                    .collect();
                (*id, (r.class, v.pack_folder(id), r.map_seq, copies))
            })
            .collect(),
        streams: v
            .streams
            .iter()
            .map(|(k, s)| {
                (
                    *k,
                    s.records
                        .iter()
                        .map(|(seq, a)| (*seq, a.body_hash, a.base))
                        .collect(),
                )
            })
            .collect(),
        folders: v.folders.iter().copied().collect(),
    }
}

/// Two devices; A publishes two records of packs, B enrols between.
struct World {
    kit: Kit,
}

fn world() -> World {
    let mut kit = Kit::new(2);
    kit.enroll(0); // A:1
    kit.enroll(1); // B:1, has seen A:1
    let a = kit.pack(&[0, 1], 3);
    let b = kit.pack(&[0, 1], 2);
    kit.publish(
        0,
        &[a.clone(), b.clone()],
        &[("one.txt", vec![a.members[0].object, b.members[0].object])],
        None,
    ); // A:2
    let c = kit.pack(&[0], 2);
    kit.publish(
        0,
        std::slice::from_ref(&c),
        &[("two.txt", vec![c.members[0].object])],
        None,
    ); // A:3
    World { kit }
}

fn remove_own_batches(kit: &Kit, d: usize, from: u64, to: u64) {
    for s in &kit.st {
        for seq in from..=to {
            let _ = std::fs::remove_file(
                kit.dir
                    .path()
                    .join(s.name())
                    .join(batch_key(&kit.devs[d].id, seq)),
            );
        }
    }
}

fn remove_ledger_dir(kit: &Kit, d: usize) {
    std::fs::remove_dir_all(kit.dir.path().join(format!("dev{}/ledger", d + 1))).unwrap();
}

#[test]
fn a_lost_directory_is_rebuilt_from_the_batches_on_the_storages() {
    let w = world();
    let me = w.kit.devs[0].id;
    let before = w.kit.view(0);
    remove_ledger_dir(&w.kit, 0);
    let mut store = fresh_store(&w.kit, "restored");
    let rep = run(&w.kit, 0, &mut store, Extras::default()).unwrap();
    // Everything was on the storages: nothing to sign.
    assert!(rep.new_batches.is_empty(), "{}", rep.describe());
    assert_eq!(rep.own_head_before, 0);
    assert_eq!(rep.own_head_after, 3);
    assert_eq!(rep.batches, 4); // A:1..3 and B:1
    assert_eq!(rep.claims_from_maps + rep.claims_from_listing, 0);
    let after = view_of(&w.kit, &store);
    assert_eq!(after.canonical(), before.canonical());
    assert_eq!(store.head(&me).seq, 3);
}

#[test]
fn claims_are_rebuilt_from_the_maps_and_the_pack_listing() {
    let mut w = world();
    let me = w.kit.devs[0].id;
    let before = w.kit.view(0);
    // A pack that no map names, with a good hash, on h2; and one whose
    // bytes do not hash to its name.
    let loose = w.kit.orphan(1);
    let bad_name = crate::crypto::hash(b"someone else");
    let bad_path = w.kit.pack_path(1, &bad_name);
    std::fs::create_dir_all(bad_path.parent().unwrap()).unwrap();
    std::fs::write(&bad_path, vec![7u8; PACK_LEN]).unwrap();

    // A's two batches after the enrolment never reached any storage, and
    // its directory is gone. B saw A only up to batch 1.
    remove_own_batches(&w.kit, 0, 2, 3);
    remove_ledger_dir(&w.kit, 0);
    let marker = w.kit.dir.path().join("marker");
    let mut store = fresh_store(&w.kit, "restored");
    let rep = run(
        &w.kit,
        0,
        &mut store,
        Extras {
            marker_dir: Some(&marker),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(rep.own_head_before, 0);
    assert_eq!(rep.new_batches, vec![2], "{}", rep.describe());
    assert_eq!(rep.own_head_after, 2);
    // a, b on h1 and h2, c on h1: from the maps. The loose pack: listing.
    assert_eq!(rep.claims_from_maps, 5);
    assert_eq!(rep.claims_from_listing, 1);
    assert_eq!(rep.unnamed_corrupt.len(), 1);
    assert!(rep.unnamed_corrupt[0].contains(&hex::encode(bad_name)));
    // Two map records, two manifest records.
    assert_eq!(rep.announced, 4);
    assert_eq!(rep.pushed_to, vec!["h1".to_string(), "h2".to_string()]);
    assert!(marker.join("rebuild3.json").exists());

    let after = view_of(&w.kit, &store);
    let (mut want, got) = (summary(&before, &me), summary(&after, &me));
    // The same view as before, plus the claim on the loose pack (no
    // folder known) and nothing for the corrupt one.
    want.packs
        .insert(loose, (0, None, 0, vec![("h2".to_string(), true)]));
    assert_eq!(got, want);
    assert!(!after.packs.contains_key(&bad_name));

    // A second run finds everything claimed: it signs nothing.
    let again = run(&w.kit, 0, &mut store, Extras::default()).unwrap();
    assert!(again.new_batches.is_empty(), "{}", again.describe());
    assert_eq!(again.announced, 0);
    // Another device that pulls sees the batch the rebuild pushed.
    let mut b_store = fresh_store(&w.kit, "other");
    let b_rep = run(&w.kit, 1, &mut b_store, Extras::default()).unwrap();
    assert_eq!(b_rep.own_head_after, 1);
    assert_eq!(view_of(&w.kit, &b_store).canonical(), after.canonical());
}

#[test]
fn without_a_verify_callback_a_pack_nobody_names_is_not_claimed() {
    let mut w = world();
    let loose = w.kit.orphan(1);
    remove_own_batches(&w.kit, 0, 2, 3);
    remove_ledger_dir(&w.kit, 0);
    let mut store = fresh_store(&w.kit, "restored");
    let rep = run(
        &w.kit,
        0,
        &mut store,
        Extras {
            no_verify: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(rep.claims_from_listing, 0);
    assert!(rep.skipped.iter().any(|s| s.contains("not claimed")));
    assert!(!view_of(&w.kit, &store).packs.contains_key(&loose));
}

#[test]
fn a_device_that_never_signed_anything_enrols_again() {
    let mut kit = Kit::new(1);
    let _ = kit.pack(&[0], 1);
    let mut store = fresh_store(&kit, "restored");
    let rep = run(&kit, 0, &mut store, Extras::default()).unwrap();
    assert!(rep.enrolled);
    assert_eq!(rep.new_batches, vec![1]);
    let v = view_of(&kit, &store);
    assert!(v.devices.contains_key(&kit.devs[0].id));
    assert!(v.folders.contains(&FOLDER));
}

#[test]
fn a_cloned_identity_with_two_histories_is_refused() {
    let w = world();
    let me = w.kit.devs[0].id;
    // A clone of A signed another batch 3 with the same key and put it on h2.
    let mut clone = fresh_store(&w.kit, "clone");
    let pubkey = w.kit.devs[0].sk.public();
    for seq in 1..=2 {
        let rec = w.kit.devs[0].store.get(&me, seq).unwrap().unwrap();
        assert_eq!(
            clone
                .ingest_own_restored(rec, &pubkey, Some(&w.kit.ledger_key))
                .unwrap(),
            Ingest::New
        );
    }
    let other = clone
        .append_own(
            &me,
            vec![
                crate::ledger3::Event::DeviceEnrolled(crate::ledger3::events::DeviceEnrolled {
                    name: "the clone".into(),
                })
                .to_raw(),
            ],
            Vec::new(),
            99,
            &w.kit.ledger_key,
            LEDGER_KEY_ID,
            crate::ledger3::NO_FOLDER,
            &w.kit.devs[0].sk,
        )
        .unwrap();
    assert_eq!(other.seq, 3);
    std::fs::write(
        w.kit.dir.path().join("h2").join(batch_key(&me, 3)),
        other.encode().unwrap(),
    )
    .unwrap();

    remove_ledger_dir(&w.kit, 0);
    let mut store = fresh_store(&w.kit, "restored");
    let err = run(&w.kit, 0, &mut store, Extras::default()).unwrap_err();
    assert_eq!(err.code(), "forked", "{err}");
    assert!(err.to_string().contains("pair this computer again"));
    assert!(store.is_forked(&me));
    // Nothing was signed or pushed.
    let h1 = w.kit.st[0]
        .list(&format!("ledger/{}/", hex::encode(me)))
        .unwrap();
    assert_eq!(h1.len(), 3);
    assert_eq!(store.head(&me).seq, 3);
}

#[test]
fn a_number_other_devices_hold_is_never_signed_again() {
    let mut w = world();
    // B publishes after seeing A:3.
    let p = w.kit.pack(&[0], 1);
    w.kit.publish(1, std::slice::from_ref(&p), &[], None);
    let me = w.kit.devs[0].id;
    let lost = w.kit.devs[0].store.get(&me, 3).unwrap().unwrap();
    remove_own_batches(&w.kit, 0, 3, 3);
    remove_ledger_dir(&w.kit, 0);

    let mut store = fresh_store(&w.kit, "restored");
    let err = run(&w.kit, 0, &mut store, Extras::default()).unwrap_err();
    assert!(
        matches!(err, RebuildError::GapNeedsPeers { held: 2, seen: 3 }),
        "{err}"
    );
    assert_eq!(err.code(), "gap_needs_peers");
    // Nothing was signed.
    assert_eq!(store.head(&me).seq, 2);

    // A peer hands the batch back: the rebuild goes on after it.
    let fill = |seq: u64| (seq == 3).then(|| lost.clone());
    let mut store = fresh_store(&w.kit, "restored2");
    let rep = run(
        &w.kit,
        0,
        &mut store,
        Extras {
            fill_own: Some(&fill),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(rep.own_head_before, 0);
    assert!(rep.own_head_after >= 3);
    // Pack c is claimed by the batch the peer returned, so no new number
    // is below 4.
    assert!(rep.new_batches.iter().all(|s| *s >= 4));
}
