// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Version history (`docs/spec/alpha-0-format.md`, the section after the
//! trash): a file overwritten on one device keeps its previous version,
//! listed and restorable on every device; versions share unchanged blocks;
//! the history thins versions on a fixed schedule and drops the blocks of
//! those it lets go when nothing else uses them; a trash storage takes the
//! blocks only versions use.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::{history_kept, HistoryTarget};
use varsto_core::price::StoragePrice;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";
const HOUR: i64 = 3_600;
const DAY: i64 = 86_400;
const WEEK: i64 = 7 * DAY;

fn dir(name: &str, path: &Path, cold: bool) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: path.to_path_buf(),
        cold,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed * 2 + 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s & 0xff) as u8
        })
        .collect()
}

fn objects(root: &Path) -> BTreeSet<String> {
    common::object_names(root)
}

fn init(home: &Path, name: &str) -> (Engine, String) {
    let (mut e, key) = Engine::init(home, name, PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    (e, key)
}

fn join(owner: &mut Engine, home: &Path, name: &str, key: &str, storage: StorageSpec) -> Engine {
    let mut e = common::join_approved(home, name, PASS, key, storage, owner);
    e.chunker = ChunkerParams::SMALL;
    e
}

fn here() -> HistoryTarget {
    HistoryTarget::default()
}

/// A body of `len` bytes whose part from `at` is replaced by other bytes:
/// the blocks before it stay the same (content-defined chunking).
fn edited(base: &[u8], at: usize, seed: u64) -> Vec<u8> {
    let mut out = base[..at].to_vec();
    out.extend(pseudo_random(base.len() - at, seed));
    out
}

struct Lab {
    t: tempfile::TempDir,
}

impl Lab {
    fn new() -> Lab {
        Lab {
            t: tempfile::tempdir().unwrap(),
        }
    }
    fn p(&self, name: &str) -> PathBuf {
        self.t.path().join(name)
    }
}

#[test]
fn an_overwrite_on_one_device_is_restored_on_another() {
    let lab = Lab::new();
    let store = dir("box", &lab.p("store"), false);
    let (a_dir, b_dir) = (lab.p("a-docs"), lab.p("b-docs"));
    let (mut a, key) = init(&lab.p("a"), "laptop");
    a.add_storage(store.clone()).unwrap();
    a.add_folder("docs", &a_dir).unwrap();
    let v1 = pseudo_random(120_000, 1);
    fs::write(a_dir.join("report.bin"), &v1).unwrap();
    a.sync(None).unwrap();
    let mut b = join(&mut a, &lab.p("b"), "phone", &key, store.clone());
    b.attach_folder("docs", &b_dir, false).unwrap();
    b.sync(None).unwrap();
    assert!(b
        .history_list("docs", "report.bin")
        .unwrap()
        .versions
        .is_empty());

    // Overwritten on A: B lists the previous version at once.
    let v2 = edited(&v1, 80_000, 2);
    fs::write(a_dir.join("report.bin"), &v2).unwrap();
    a.sync(None).unwrap();
    let list = b.history_list("docs", "report.bin").unwrap();
    assert_eq!(list.days, Some(90));
    assert_eq!(list.versions.len(), 1);
    assert_eq!(list.versions[0].replaced_by, "laptop");
    assert_eq!(list.versions[0].author.as_deref(), Some("laptop"));

    // B restores it over the current file: byte for byte, and the current
    // version (v2) becomes a version itself.
    b.sync(None).unwrap();
    assert_eq!(fs::read(b_dir.join("report.bin")).unwrap(), v2);
    let list = b.history_list("docs", "report.bin").unwrap();
    let ver = &list.versions[0];
    assert_eq!(ver.size, 120_000);
    // Only the changed blocks are its own.
    assert!(
        ver.new_bytes > 0 && ver.new_bytes < 60_000,
        "{}",
        ver.new_bytes
    );
    let r = b
        .history_restore("docs", "report.bin", &ver.id[..8], &here(), false)
        .unwrap();
    assert!(r.replaced_current);
    assert_eq!(r.to, "report.bin");
    assert_eq!(fs::read(b_dir.join("report.bin")).unwrap(), v1);
    let list = b.history_list("docs", "report.bin").unwrap();
    assert_eq!(list.versions.len(), 2, "{:?}", list.versions);
    assert_eq!(list.versions[0].replaced_by, "phone");
    assert_eq!(list.versions[0].author.as_deref(), Some("laptop"));
    assert_eq!(list.current_size, Some(120_000));
    // A gets the restored version and sees both earlier versions.
    a.sync(None).unwrap();
    assert_eq!(fs::read(a_dir.join("report.bin")).unwrap(), v1);
    assert_eq!(
        a.history_list("docs", "report.bin").unwrap().versions.len(),
        2
    );

    // Restoring what is already current is refused.
    let same = b.history_list("docs", "report.bin").unwrap().versions[1]
        .id
        .clone();
    let err = b
        .history_restore("docs", "report.bin", &same, &here(), false)
        .unwrap_err();
    assert!(err.to_string().contains("already the current"), "{err}");

    // v2 by time (the version current at the end of yesterday is the
    // oldest one), under a new name and into a directory; never over an
    // existing file.
    let yesterday = varsto_core::util::format_date(varsto_core::util::now_utc() - DAY);
    let as_name = HistoryTarget {
        as_name: Some("report-v2.bin".into()),
        to: None,
    };
    let newest = b.history_list("docs", "report.bin").unwrap().versions[0]
        .id
        .clone();
    let r = b
        .history_restore("docs", "report.bin", &newest, &as_name, false)
        .unwrap();
    assert_eq!(r.to, "report-v2.bin");
    assert!(!r.replaced_current);
    assert_eq!(fs::read(b_dir.join("report-v2.bin")).unwrap(), v2);
    assert!(b
        .history_restore("docs", "report.bin", &newest, &as_name, false)
        .unwrap_err()
        .to_string()
        .contains("already exists"));
    let into = HistoryTarget {
        to: Some("old".into()),
        as_name: None,
    };
    let r = b
        .history_restore("docs", "report.bin", &yesterday, &into, false)
        .unwrap();
    assert_eq!(r.to, "old/report.bin");
    assert_eq!(fs::read(b_dir.join("old/report.bin")).unwrap(), v1);
    let r = b
        .history_restore("docs", "report.bin", &yesterday, &into, false)
        .unwrap();
    assert_eq!(r.to, "old/report (restored).bin");
    // The current file was never touched by those.
    assert_eq!(fs::read(b_dir.join("report.bin")).unwrap(), v1);
    assert!(b
        .history_restore("docs", "report.bin", "not-a-version", &here(), false)
        .is_err());
}

#[test]
fn versions_share_unchanged_blocks() {
    let lab = Lab::new();
    let store = lab.p("store");
    let docs = lab.p("docs");
    let (mut a, _) = init(&lab.p("a"), "laptop");
    a.add_storage(dir("box", &store, false)).unwrap();
    a.add_folder("docs", &docs).unwrap();
    let base = pseudo_random(400_000, 3);
    fs::write(docs.join("big.bin"), &base).unwrap();
    a.sync(None).unwrap();
    let first = objects(&store);
    // A small edit near the end: few new blocks are stored.
    fs::write(docs.join("big.bin"), edited(&base, 390_000, 4)).unwrap();
    a.sync(None).unwrap();
    let added = objects(&store).difference(&first).count();
    assert!(
        added > 0 && added * 10 < first.len(),
        "{added} of {}",
        first.len()
    );
    let st = a.history_status().unwrap();
    assert_eq!(st.days, 90);
    let f = &st.folders[0];
    assert_eq!((f.files, f.versions, f.bytes), (1, 1, 400_000));
    // The history really costs only the blocks the edit replaced.
    assert!(
        f.extra_bytes > 0 && f.extra_bytes < 40_000,
        "{}",
        f.extra_bytes
    );
    assert_eq!(f.by_storage.get("box").copied(), Some(f.extra_bytes));
    // The version's blocks are referenced, not unreferenced objects.
    let fsck = a.fsck(false).unwrap();
    assert_eq!(fsck.objects_unreferenced, 0);
}

#[test]
fn the_thinning_schedule_keeps_exactly_the_expected_versions() {
    // A version every ten minutes for 100 days; `now` falls on a week
    // boundary (and so on an hour and a day boundary).
    let now = 2_900 * WEEK;
    let times: Vec<i64> = (0..100 * 144).map(|i| now - i * 600).collect();
    let ids: Vec<String> = (0..times.len()).map(|i| format!("{i:08}")).collect();
    let v: Vec<(i64, u64, &str)> = times
        .iter()
        .zip(&ids)
        .map(|(t, i)| (*t, 1, i.as_str()))
        .collect();
    let kept = history_kept(&v, now, 90);
    let ages: BTreeSet<i64> = v
        .iter()
        .zip(&kept)
        .filter(|(_, k)| **k)
        .map(|((t, _, _), _)| now - t)
        .collect();
    // Every version of the last hour (ages 0, 10, ... 50 minutes); then the
    // newest version of each earlier clock hour until a day, of each
    // earlier UTC day until 30 days, of each earlier week until the 90
    // days; nothing older. (The version at the one-hour mark is the oldest
    // of the current hour, the one at a day of the previous day, the one at
    // 30 days of a week with newer versions: they go.)
    let mut expected: BTreeSet<i64> = (0..6).map(|i| i * 600).collect();
    expected.extend((1..=23).map(|k| k * HOUR + 600));
    expected.extend((1..=29).map(|k| k * DAY + 600));
    expected.extend((5..=12).map(|k| k * WEEK + 600));
    assert_eq!(ages, expected);
    assert_eq!(ages.len(), 6 + 23 + 29 + 8);

    // As time passes, a version let go never comes back, and with a
    // shorter history the schedule stops at its days.
    let mut before: BTreeSet<usize> = (0..v.len()).filter(|i| kept[*i]).collect();
    for step in 1..200 {
        let later = now + step * 1_800;
        let k = history_kept(&v, later, 90);
        let now_kept: BTreeSet<usize> = (0..v.len()).filter(|i| k[*i]).collect();
        assert!(now_kept.is_subset(&before), "step {step}");
        before = now_kept;
    }
    let short = history_kept(&v, now, 7);
    assert!(v
        .iter()
        .zip(&short)
        .all(|((t, _, _), k)| !*k || now - t < 7 * DAY));
    assert_eq!(short.iter().filter(|k| **k).count(), 6 + 23 + 6);
}

#[test]
#[ignore = "f3-switch: port in part B (upkeep)"]
// Waits for garbage collection in trash upkeep.
fn thinning_and_expiry_drop_only_unreferenced_blocks() {
    let lab = Lab::new();
    let store = lab.p("store");
    let docs = lab.p("docs");
    let (mut a, _) = init(&lab.p("a"), "laptop");
    a.add_storage(dir("box", &store, false)).unwrap();
    a.add_folder("docs", &docs).unwrap();
    fs::write(docs.join("other.bin"), pseudo_random(50_000, 20)).unwrap();
    a.sync(None).unwrap();
    // Four versions: a shared first part, then a part of their own.
    let common = pseudo_random(100_000, 21);
    let mut own: Vec<BTreeSet<String>> = Vec::new();
    let mut bodies = Vec::new();
    for i in 0..4u64 {
        let mut body = common.clone();
        body.extend(pseudo_random(60_000, 30 + i));
        let before = objects(&store);
        fs::write(docs.join("f.bin"), &body).unwrap();
        a.sync(None).unwrap();
        own.push(objects(&store).difference(&before).cloned().collect());
        bodies.push(body);
    }
    let shared = own[0].clone();
    let list = a.history_list("docs", "f.bin").unwrap();
    assert_eq!(list.versions.len(), 3);
    // Oldest first: the versions as written (v0, v1, v2).
    let mut vers = list.versions.clone();
    vers.reverse();

    // 40 days on, the week bucket keeps the newest version of the three
    // (or more if they straddle a week boundary); the others go.
    let now = varsto_core::util::now_utc();
    let later = now + 40 * DAY;
    let keys: Vec<(i64, u64, &str)> = vers
        .iter()
        .map(|v| (v.replaced_utc, v.clock, v.id.as_str()))
        .collect();
    let expect = history_kept(&keys, later, 90);
    assert!(expect[2] && expect.iter().filter(|k| **k).count() < 3);
    let up = a.trash_upkeep_at(later).unwrap();
    assert_eq!(
        up.versions_dropped as usize,
        expect.iter().filter(|k| !**k).count()
    );
    assert!(up.blocks_dropped > 0, "{up:?}");
    let left = objects(&store);
    for (i, k) in expect.iter().enumerate() {
        if i == 0 {
            continue; // v0's new blocks include the shared part
        }
        if *k {
            assert!(own[i].is_subset(&left), "kept v{i}");
        } else {
            assert!(own[i].is_disjoint(&left), "thinned v{i}");
        }
    }
    assert!(own[3].is_subset(&left), "the current file's blocks stay");
    assert!(
        shared.intersection(&left).count() > 0,
        "blocks the current file shares stay"
    );
    let kept = a.history_list_at("docs", "f.bin", later).unwrap();
    assert_eq!(kept.versions.len(), expect.iter().filter(|k| **k).count());
    let r = a
        .history_restore(
            "docs",
            "f.bin",
            &vers[2].id,
            &HistoryTarget {
                as_name: Some("f-v2.bin".into()),
                to: None,
            },
            false,
        )
        .unwrap();
    assert_eq!(fs::read(docs.join(&r.to)).unwrap(), bodies[2]);
    fs::remove_file(docs.join(&r.to)).unwrap();
    a.sync(None).unwrap();
    // The removed copy went to the trash; empty it so only history counts.
    a.trash_purge(None, &[], true).unwrap();

    // Past the 90 days every version expires: only what the current files
    // use is left.
    let up = a.trash_upkeep_at(now + 100 * DAY).unwrap();
    assert!(up.versions_dropped >= 1);
    let left = objects(&store);
    for o in own.iter().take(3).skip(1) {
        assert!(o.is_disjoint(&left));
    }
    assert!(own[3].is_subset(&left));
    assert!(a
        .history_list_at("docs", "f.bin", now + 100 * DAY)
        .unwrap()
        .versions
        .is_empty());
    let f = a.fsck(false).unwrap();
    assert!(f.chunks_missing.is_empty(), "{:?}", f.chunks_missing);
    assert_eq!(f.claims_without_object, 0);
    assert_eq!(fs::read(docs.join("f.bin")).unwrap(), bodies[3]);
}

#[test]
#[ignore = "f3-switch: port in part B (upkeep)"]
// Waits for garbage collection in trash upkeep.
fn a_trash_storage_takes_the_blocks_only_versions_use() {
    let lab = Lab::new();
    let (one, cold, a_dir, b_dir) = (
        lab.p("one"),
        lab.p("glacier"),
        lab.p("a-docs"),
        lab.p("b-docs"),
    );
    let (mut a, key) = init(&lab.p("a"), "laptop");
    a.add_storage(dir("one", &one, false)).unwrap();
    a.add_storage(dir("glacier", &cold, true)).unwrap();
    a.set_storage_price(
        "glacier",
        Some(StoragePrice {
            storage_per_gb_month: Some(0.004),
            retrieval_per_gb: Some(0.03),
            minimum_storage_days: Some(90),
            currency: "USD".into(),
            ..Default::default()
        }),
    )
    .unwrap();
    a.trash_set(None, None, Some(Some("glacier".into())))
        .unwrap();
    a.add_folder("docs", &a_dir).unwrap();
    let v1 = pseudo_random(150_000, 40);
    fs::write(a_dir.join("doc.bin"), &v1).unwrap();
    a.sync(None).unwrap();
    assert!(objects(&cold).is_empty());
    fs::write(a_dir.join("doc.bin"), edited(&v1, 50_000, 41)).unwrap();
    a.sync(None).unwrap();
    let all = objects(&one);
    let up = a.trash_upkeep().unwrap();
    assert!(up.blocks_moved > 0, "{up:?}");
    // The version's own blocks left the warm storage; shared ones stayed.
    let moved = objects(&cold);
    assert!(!moved.is_empty());
    assert!(moved.is_subset(&all));
    assert!(objects(&one).is_disjoint(&moved));
    let st = a.history_status().unwrap();
    assert_eq!(st.storage.as_deref(), Some("glacier"));
    assert!(st.storage_cold);
    assert!(st.by_storage.get("glacier").copied().unwrap_or(0) > 0);
    assert!(!st.by_storage.contains_key("one"));

    // On another device restoring needs the confirmed cold read.
    let mut b = join(&mut a, &lab.p("b"), "phone", &key, dir("one", &one, false));
    b.add_storage(dir("glacier", &cold, true)).unwrap();
    b.attach_folder("docs", &b_dir, false).unwrap();
    b.sync(None).unwrap();
    let list = b.history_list("docs", "doc.bin").unwrap();
    assert!(list.versions[0].cold_only);
    let id = list.versions[0].id.clone();
    let plan = b
        .history_restore_plan("docs", "doc.bin", &id, &here())
        .unwrap();
    assert_eq!(plan.cold_storages, vec!["glacier".to_string()]);
    let err = b
        .history_restore("docs", "doc.bin", &id, &here(), false)
        .unwrap_err()
        .to_string();
    assert!(err.contains("cold read"), "{err}");
    b.history_restore("docs", "doc.bin", &id, &here(), true)
        .unwrap();
    assert_eq!(fs::read(b_dir.join("doc.bin")).unwrap(), v1);
}

#[test]
fn history_can_be_turned_off_per_folder() {
    let lab = Lab::new();
    let (mut a, _) = init(&lab.p("a"), "laptop");
    a.add_storage(dir("box", &lab.p("store"), false)).unwrap();
    a.add_folder("docs", &lab.p("docs")).unwrap();
    a.add_folder("media", &lab.p("media")).unwrap();
    assert!(a.history_set(None, Some("media"), false).is_err());
    assert!(a.history_set(Some(0), None, false).is_err());
    let st = a.history_set(None, Some("media"), true).unwrap();
    assert_eq!(st.folder_days.get("media"), Some(&0));
    for (folder, d) in [("docs", lab.p("docs")), ("media", lab.p("media"))] {
        fs::write(d.join("x.txt"), b"one").unwrap();
        a.sync(Some(folder)).unwrap();
        fs::write(d.join("x.txt"), b"two").unwrap();
        a.sync(Some(folder)).unwrap();
    }
    assert_eq!(a.history_list("docs", "x.txt").unwrap().versions.len(), 1);
    let media = a.history_list("media", "x.txt").unwrap();
    assert_eq!(media.days, None);
    assert!(media.versions.is_empty());
    // A folder's own days, then back to the vault's; the vault off.
    let st = a.history_set(Some(14), Some("media"), false).unwrap();
    assert_eq!(st.folder_days.get("media"), Some(&14));
    let st = a.history_set(Some(0), Some("media"), false).unwrap();
    assert!(st.folder_days.is_empty());
    let st = a.history_set(None, None, true).unwrap();
    assert_eq!(st.days, 0);
    fs::write(lab.p("docs").join("x.txt"), b"three").unwrap();
    a.sync(Some("docs")).unwrap();
    // No new version; the one kept stays on the default schedule.
    assert_eq!(a.history_list("docs", "x.txt").unwrap().versions.len(), 1);
}

#[test]
fn a_folder_kept_encrypted_here_keeps_versions_too() {
    let lab = Lab::new();
    let store = dir("box", &lab.p("store"), false);
    let (mut a, key) = init(&lab.p("a"), "laptop");
    a.add_storage(store.clone()).unwrap();
    a.add_folder("docs", &lab.p("a-docs")).unwrap();
    let v1 = pseudo_random(60_000, 50);
    fs::write(lab.p("a-docs").join("n.bin"), &v1).unwrap();
    a.sync(None).unwrap();
    let mut b = join(&mut a, &lab.p("b"), "phone", &key, store);
    b.attach_folder("docs", &lab.p("b-docs"), false).unwrap();
    b.set_encrypted_here("docs", true).unwrap();
    b.sync(None).unwrap();
    // Written through the app: the replaced version is kept.
    let v2 = edited(&v1, 30_000, 51);
    b.write_file("docs", "n.bin", &v2).unwrap();
    let list = b.history_list("docs", "n.bin").unwrap();
    assert_eq!(list.versions.len(), 1);
    assert_eq!(list.versions[0].author.as_deref(), Some("laptop"));
    assert_eq!(list.versions[0].replaced_by, "phone");
    let id = list.versions[0].id.clone();
    let r = b
        .history_restore("docs", "n.bin", &id, &here(), false)
        .unwrap();
    assert!(r.replaced_current);
    assert_eq!(b.read_file("docs", "n.bin").unwrap(), v1);
    assert_eq!(b.history_list("docs", "n.bin").unwrap().versions.len(), 2);
    a.sync(None).unwrap();
    assert_eq!(fs::read(lab.p("a-docs").join("n.bin")).unwrap(), v1);
}
