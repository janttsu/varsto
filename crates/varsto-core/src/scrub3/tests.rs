// SPDX-License-Identifier: PolyForm-Shield-1.0.0
use super::*;
use crate::fsck3::testkit::*;
use crate::media::Media;
use crate::storage::Storage;
use std::cell::RefCell;

fn kit_with_packs() -> (Kit, Vec<crate::blockmap::WrittenPack>) {
    let mut kit = Kit::new(1);
    kit.enroll(0);
    let packs = vec![
        kit.pack(&[0, 1], 2),
        kit.pack(&[0, 1], 2),
        kit.pack(&[0], 1),
    ];
    kit.publish(0, &packs, &[], None);
    (kit, packs)
}

fn storage_target<'a>(kit: &'a Kit, view: &LedgerView, i: usize) -> PackTarget<'a> {
    let s = &kit.st[i];
    PackTarget {
        target: format!("storage:{}", s.name()),
        label: format!("storage {}", s.name()),
        name: s.name().to_string(),
        lane: LanePlan::sequential(Media::Unknown),
        remote: false,
        items: storage_items(view, s.name()),
        read: Box::new(move |id| s.get(&crate::packs::pack_key(id))),
    }
}

fn run(
    targets: &[PackTarget],
    state: &mut ScrubState,
    pace: Pace,
    budget: u64,
    on: &mut dyn FnMut(&PackMismatch) -> bool,
) -> PackScrubResult {
    scrub_packs(
        targets,
        state,
        &ScrubSchedule::default(),
        pace,
        &mut Budget::new(budget),
        &mut Budget::unlimited(),
        1_000_000,
        on,
    )
}

#[test]
fn a_clean_sweep_reads_every_pack_once_and_ends_the_pass() {
    let (kit, _) = kit_with_packs();
    let view = kit.view(0);
    let t = [storage_target(&kit, &view, 0)];
    assert_eq!(t[0].items.len(), 3);
    let mut state = ScrubState::default();
    let r = run(&t, &mut state, Pace::Budget, u64::MAX, &mut |_| true);
    assert_eq!(r.report.objects_checked, 3);
    assert_eq!(r.report.object_bytes, 3 * PACK_LEN as u64);
    assert!(r.mismatches.is_empty() && r.report.problems() == 0);
    let sweep = &state.sweeps["storage:h1"];
    assert_eq!(sweep.cursor, None);
    assert_eq!(sweep.last_pass_done_utc, Some(1_000_000));
    assert!(r.report.targets[0].pass_done);
}

#[test]
fn progress_is_kept_per_pack_across_runs() {
    let (kit, _) = kit_with_packs();
    let view = kit.view(0);
    let t = [storage_target(&kit, &view, 0)];
    let ids: Vec<String> = t[0].items.iter().map(|(k, _)| k.clone()).collect();
    let mut state = ScrubState::default();
    // A budget of one byte: the first pack of a run is always read.
    for (n, id) in ids.iter().enumerate() {
        let r = run(&t, &mut state, Pace::Budget, 1, &mut |_| true);
        assert_eq!(r.report.objects_checked, 1, "run {n}");
        let sweep = &state.sweeps["storage:h1"];
        if n + 1 < ids.len() {
            assert_eq!(sweep.cursor.as_deref(), Some(id.as_str()));
            assert_eq!(sweep.checked_in_pass, n as u64 + 1);
            assert_eq!(r.report.targets[0].left_in_pass, (ids.len() - n - 1) as u64);
        } else {
            assert_eq!(sweep.cursor, None);
            assert!(r.report.targets[0].pass_done);
        }
    }
    // The next pass starts again from the first pack.
    let r = run(&t, &mut state, Pace::Budget, 1, &mut |_| true);
    assert_eq!(r.report.objects_checked, 1);
    assert_eq!(
        state.sweeps["storage:h1"].cursor.as_deref(),
        Some(ids[0].as_str())
    );
}

#[test]
fn a_mismatch_is_handed_to_the_repair_callback() {
    let (kit, packs) = kit_with_packs();
    kit.flip_byte(0, &packs[1].id);
    kit.delete_pack(0, &packs[2].id);
    // A pack of the wrong length.
    let p = kit.pack_path(0, &packs[0].id);
    let mut b = std::fs::read(&p).unwrap();
    b.truncate(b.len() - 1);
    std::fs::write(&p, b).unwrap();
    let view = kit.view(0);
    let t = [
        storage_target(&kit, &view, 0),
        storage_target(&kit, &view, 1),
    ];
    let mut state = ScrubState::default();
    let handed = RefCell::new(Vec::new());
    let r = run(&t, &mut state, Pace::Full, 0, &mut |m| {
        handed.borrow_mut().push(m.clone());
        true
    });
    // h1: three bad packs; h2 (two packs): clean.
    assert_eq!(r.report.objects_checked, 3 + 2);
    assert_eq!(r.mismatches.len(), 3);
    assert_eq!(handed.borrow().len(), 3);
    assert_eq!(r.report.queued_for_repair, 3);
    let kind_of = |id: &crate::ledger3::PackId| {
        r.mismatches
            .iter()
            .find(|m| m.pack == hex::encode(id))
            .unwrap()
            .kind
            .clone()
    };
    assert_eq!(
        kind_of(&packs[0].id),
        MismatchKind::WrongLength {
            len: PACK_LEN as u64 - 1
        }
    );
    assert!(matches!(
        kind_of(&packs[1].id),
        MismatchKind::Corrupt { .. }
    ));
    assert_eq!(kind_of(&packs[2].id), MismatchKind::Missing);
    assert!(r.mismatches.iter().all(|m| m.name == "h1"));
    assert_eq!(r.report.missing.len(), 1);
    assert_eq!(r.report.corrupt.len(), 2);
    assert_eq!(r.report.problems(), 3);
    // The callback may decline: the pack is not counted as queued.
    let r = run(&t, &mut state, Pace::Full, 0, &mut |_| false);
    assert_eq!(r.report.queued_for_repair, 0);
    assert_eq!(r.mismatches.len(), 3);
}

#[test]
fn a_pool_disk_hashes_each_pack_file() {
    let (kit, packs) = kit_with_packs();
    // A disk with two packs and an unrelated object.
    let disk = tempfile::tempdir().unwrap();
    let mut objects = vec![("chunks/ab/abcdef".to_string(), 10u64)];
    for p in &packs[..2] {
        let key = crate::packs::pack_key(&hex::encode(p.id));
        let bytes = std::fs::read(kit.pack_path(0, &p.id)).unwrap();
        std::fs::create_dir_all(disk.path().join(&key).parent().unwrap()).unwrap();
        std::fs::write(disk.path().join(&key), &bytes).unwrap();
        objects.push((key, bytes.len() as u64));
    }
    // The second one rots on the disk.
    let rotten = disk
        .path()
        .join(crate::packs::pack_key(&hex::encode(packs[1].id)));
    let mut b = std::fs::read(&rotten).unwrap();
    b[10] ^= 1;
    std::fs::write(&rotten, b).unwrap();
    let root = disk.path().to_path_buf();
    let target = PackTarget {
        target: "disk:shelf/d1".into(),
        label: "disk d1 of pool shelf".into(),
        name: "shelf/d1".into(),
        lane: LanePlan::sequential(Media::Unknown),
        remote: false,
        items: disk_items(&objects),
        read: Box::new(move |id| {
            let p = root.join(crate::packs::pack_key(id));
            Ok(std::fs::read(p).ok())
        }),
    };
    assert_eq!(target.items.len(), 2);
    let mut state = ScrubState::default();
    let r = run(
        std::slice::from_ref(&target),
        &mut state,
        Pace::Full,
        0,
        &mut |_| true,
    );
    assert_eq!(r.report.objects_checked, 2);
    assert_eq!(r.mismatches.len(), 1);
    assert_eq!(r.mismatches[0].pack, hex::encode(packs[1].id));
    assert!(matches!(r.mismatches[0].kind, MismatchKind::Corrupt { .. }));
    assert_eq!(r.mismatches[0].name, "shelf/d1");
    assert_eq!(state.sweeps["disk:shelf/d1"].label, "disk d1 of pool shelf");
}

#[test]
fn a_read_error_stops_the_target_without_passing_the_pack() {
    let (kit, _) = kit_with_packs();
    let view = kit.view(0);
    let mut t = storage_target(&kit, &view, 0);
    let fail_on = t.items[1].0.clone();
    let inner = t.read;
    t.read = Box::new(move |id| {
        if id == fail_on {
            anyhow::bail!("storage unreachable")
        }
        inner(id)
    });
    let first = t.items[0].0.clone();
    let mut state = ScrubState::default();
    let r = run(&[t], &mut state, Pace::Full, 0, &mut |_| true);
    assert_eq!(r.report.objects_checked, 1);
    assert!(r.report.skipped[0].contains("read failed"));
    let sweep = &state.sweeps["storage:h1"];
    assert_eq!(sweep.cursor.as_deref(), Some(first.as_str()));
    assert_eq!(sweep.last_pass_done_utc, None);
}
