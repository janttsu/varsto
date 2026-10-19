// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The trash (`docs/spec/alpha-0-format.md` section 43): a file deleted on
//! one device can be restored on any device from the storages for the
//! trash days; its blocks survive moves and storage removal meanwhile and
//! are dropped once it expires or is deleted for good; a trash storage
//! takes the trashed blocks off the warm storages.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::placement::MoveRequest;
use varsto_core::policy::Policy;
use varsto_core::price::StoragePrice;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";
const DAY: i64 = 86_400;

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
    // Distinct seeds give distinct content.
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

fn join(home: &Path, name: &str, key: &str, storage: StorageSpec, owner: &mut Engine) -> Engine {
    let mut e = common::join_approved(home, name, PASS, key, storage, owner);
    e.chunker = ChunkerParams::SMALL;
    e
}

fn paths(list: &[varsto_core::engine::TrashItem]) -> Vec<String> {
    list.iter().map(|i| i.path.clone()).collect()
}

fn s(p: &str) -> Vec<String> {
    vec![p.to_string()]
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
fn a_deletion_on_one_device_is_restored_on_another() {
    let lab = Lab::new();
    let store = dir("box", &lab.p("store"), false);
    let (a_dir, b_dir) = (lab.p("a-docs"), lab.p("b-docs"));
    let (mut a, key) = init(&lab.p("a"), "laptop");
    a.add_storage(store.clone()).unwrap();
    a.add_folder("docs", &a_dir).unwrap();
    fs::create_dir_all(a_dir.join("sub")).unwrap();
    let report = pseudo_random(150_000, 1);
    fs::write(a_dir.join("report.bin"), &report).unwrap();
    fs::write(a_dir.join("notes.txt"), b"version one").unwrap();
    fs::write(a_dir.join("sub/c.txt"), b"c in sub").unwrap();
    fs::write(a_dir.join("sub/d.bin"), pseudo_random(90_000, 2)).unwrap();
    a.sync(None).unwrap();

    let mut b = join(&lab.p("b"), "phone", &key, store.clone(), &mut a);
    b.attach_folder("docs", &b_dir, false).unwrap();
    b.sync(None).unwrap();
    assert_eq!(fs::read(b_dir.join("report.bin")).unwrap(), report);

    // Deleted on A: the entry is in B's trash at once, with who and when.
    fs::remove_file(a_dir.join("report.bin")).unwrap();
    a.sync(None).unwrap();
    let list = b.trash_list(None).unwrap();
    assert_eq!(paths(&list), s("report.bin"));
    assert_eq!(list[0].deleted_by, "laptop");
    assert_eq!(list[0].size, 150_000);
    assert_eq!(list[0].expires_utc - list[0].deleted_utc, 30 * DAY);
    assert!(!list[0].local_copy);

    // B applies the deletion (its copy goes to its local trash), then that
    // local copy is lost: the restore reads the blocks from the storage.
    b.sync(None).unwrap();
    assert!(!b_dir.join("report.bin").exists());
    assert!(b.trash_list(Some("docs")).unwrap()[0].local_copy);
    fs::remove_dir_all(lab.p("b").join("trash")).unwrap();
    let r = b
        .trash_restore("docs", &s("report.bin"), None, false)
        .unwrap();
    assert_eq!(r.restored.len(), 1);
    assert_eq!(r.restored[0].to, "report.bin");
    assert_eq!(r.from_storages, 1);
    assert_eq!(fs::read(b_dir.join("report.bin")).unwrap(), report);
    // The restore is a new version: A gets the file back, and the entry
    // left the trash on both devices.
    assert!(b.trash_list(None).unwrap().is_empty());
    a.sync(None).unwrap();
    assert_eq!(fs::read(a_dir.join("report.bin")).unwrap(), report);
    assert!(a.trash_list(None).unwrap().is_empty());

    // A path taken again: the old version comes back under a new name.
    fs::write(a_dir.join("notes.txt"), b"version two").unwrap();
    a.sync(None).unwrap();
    fs::remove_file(a_dir.join("notes.txt")).unwrap();
    a.sync(None).unwrap();
    fs::write(a_dir.join("notes.txt"), b"a new file").unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    let r = b
        .trash_restore("docs", &s("notes.txt"), None, false)
        .unwrap();
    assert_eq!(r.restored[0].to, "notes (restored).txt");
    assert_eq!(fs::read(b_dir.join("notes.txt")).unwrap(), b"a new file");
    assert_eq!(
        fs::read(b_dir.join("notes (restored).txt")).unwrap(),
        b"version two"
    );

    // A whole directory, into another directory of the folder.
    fs::remove_dir_all(a_dir.join("sub")).unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    let list = b.trash_list(None).unwrap();
    assert_eq!(list.len(), 2, "{:?}", paths(&list));
    let r = b
        .trash_restore("docs", &s("sub"), Some("back"), false)
        .unwrap();
    assert_eq!(r.restored.len(), 2);
    assert_eq!(fs::read(b_dir.join("back/sub/c.txt")).unwrap(), b"c in sub");
    assert_eq!(
        fs::read(b_dir.join("back/sub/d.bin")).unwrap(),
        pseudo_random(90_000, 2)
    );
    assert!(b.trash_list(None).unwrap().is_empty());
    // Nothing in the trash: nothing to restore.
    assert!(b.trash_restore("docs", &s("sub"), None, false).is_err());
}

#[test]
fn a_rename_is_not_a_deletion() {
    let lab = Lab::new();
    let (mut a, _) = init(&lab.p("a"), "laptop");
    a.add_storage(dir("box", &lab.p("store"), false)).unwrap();
    a.add_folder("docs", &lab.p("docs")).unwrap();
    fs::write(lab.p("docs").join("a.txt"), b"same content").unwrap();
    a.sync(None).unwrap();
    a.move_file("docs", "a.txt", "b.txt").unwrap();
    assert!(a.trash_list(None).unwrap().is_empty());
}

#[test]
fn the_local_trash_copy_is_used_first_and_cleared_with_the_entry() {
    let lab = Lab::new();
    let store = dir("box", &lab.p("store"), false);
    let (a_dir, b_dir) = (lab.p("a-docs"), lab.p("b-docs"));
    let (mut a, key) = init(&lab.p("a"), "laptop");
    a.add_storage(store.clone()).unwrap();
    a.add_folder("docs", &a_dir).unwrap();
    let body = pseudo_random(120_000, 9);
    fs::write(a_dir.join("x.bin"), &body).unwrap();
    fs::write(a_dir.join("y.txt"), b"why").unwrap();
    a.sync(None).unwrap();
    let mut b = join(&lab.p("b"), "phone", &key, store.clone(), &mut a);
    b.attach_folder("docs", &b_dir, false).unwrap();
    b.sync(None).unwrap();
    fs::remove_file(a_dir.join("x.bin")).unwrap();
    fs::remove_file(a_dir.join("y.txt")).unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();

    // The storage loses every block: B still restores from its local trash.
    let _ = fs::remove_dir_all(lab.p("store").join("chunks"));
    let _ = fs::remove_dir_all(lab.p("store").join("packs"));
    let r = b.trash_restore("docs", &s("x.bin"), None, false).unwrap();
    assert_eq!(r.from_local_copies, 1);
    assert_eq!(fs::read(b_dir.join("x.bin")).unwrap(), body);

    // Local copies follow the trash days.
    let now = varsto_core::util::now_utc();
    let up = b.trash_upkeep_at(now + 29 * DAY).unwrap();
    assert_eq!(up.local_copies_removed, 0);
    let up = b.trash_upkeep_at(now + 31 * DAY).unwrap();
    assert_eq!(up.local_copies_removed, 1);
    let list = b.trash_list(None).unwrap();
    assert_eq!(paths(&list), s("y.txt"));
    assert!(!list[0].local_copy);
}

#[test]
fn trashed_blocks_survive_moves_and_storage_removal() {
    let lab = Lab::new();
    let (one, two, docs) = (lab.p("one"), lab.p("two"), lab.p("docs"));
    let (mut a, _) = init(&lab.p("a"), "laptop");
    a.add_storage(dir("one", &one, false)).unwrap();
    a.add_folder("docs", &docs).unwrap();
    // No copy rules: what is tested is the trash's own rule (one copy).
    a.set_policy("docs", Some(Policy::default())).unwrap();
    fs::write(docs.join("keep.bin"), pseudo_random(80_000, 4)).unwrap();
    a.sync(None).unwrap();
    let kept = objects(&one);
    let gone_body = pseudo_random(130_000, 5);
    fs::write(docs.join("gone.bin"), &gone_body).unwrap();
    a.sync(None).unwrap();
    let gone: BTreeSet<String> = objects(&one).difference(&kept).cloned().collect();
    assert!(!gone.is_empty());
    fs::remove_file(docs.join("gone.bin")).unwrap();
    a.sync(None).unwrap();

    // Moving the whole folder takes the trash along.
    a.add_storage(dir("two", &two, false)).unwrap();
    let r = a
        .move_data(&MoveRequest {
            folder: "docs".into(),
            from: "one".into(),
            to: "two".into(),
            idle_days: None,
            dry_run: false,
            confirm_cold_read: false,
        })
        .unwrap();
    assert_eq!(r.blocks_kept, 0, "{}", r.summary);
    assert!(gone.is_subset(&objects(&two)));
    assert!(objects(&one).is_disjoint(&gone));

    // A storage holding the only copy of trashed blocks is not removed
    // before they are copied elsewhere.
    let three = lab.p("three");
    a.add_storage(dir("three", &three, false)).unwrap();
    let plan = a.plan_storage_removal("two").unwrap();
    assert!(plan.blocked.is_none(), "{:?}", plan.blocked);
    // Whole copies of the packs that hold them.
    assert!(!plan.copies.is_empty(), "{plan:?}");
    a.remove_storage("two", true).unwrap();
    let left: BTreeSet<String> = objects(&one).union(&objects(&three)).cloned().collect();
    assert!(gone.is_subset(&left));

    // fsck counts them as referenced, not as unreferenced objects.
    let f = a.fsck(false).unwrap();
    assert!(f.chunks_missing.is_empty(), "{:?}", f.chunks_missing);
    assert_eq!(f.objects_unreferenced, 0);

    let r = a
        .trash_restore("docs", &s("gone.bin"), None, false)
        .unwrap();
    assert_eq!(r.from_storages, 1);
    assert_eq!(fs::read(docs.join("gone.bin")).unwrap(), gone_body);
}

#[test]
fn expired_entries_drop_only_blocks_nothing_else_uses() {
    let lab = Lab::new();
    let (one, docs) = (lab.p("one"), lab.p("docs"));
    let (mut a, _) = init(&lab.p("a"), "laptop");
    a.add_storage(dir("one", &one, false)).unwrap();
    a.add_folder("docs", &docs).unwrap();
    fs::write(docs.join("keep.bin"), pseudo_random(70_000, 6)).unwrap();
    a.sync(None).unwrap();
    let kept = objects(&one);
    fs::write(docs.join("gone.bin"), pseudo_random(110_000, 7)).unwrap();
    a.sync(None).unwrap();
    let gone: BTreeSet<String> = objects(&one).difference(&kept).cloned().collect();
    let before_twin = objects(&one);
    let twin_body = pseudo_random(60_000, 8);
    fs::write(docs.join("twin.bin"), &twin_body).unwrap();
    a.sync(None).unwrap();
    let twin: BTreeSet<String> = objects(&one).difference(&before_twin).cloned().collect();
    fs::remove_file(docs.join("gone.bin")).unwrap();
    fs::remove_file(docs.join("twin.bin")).unwrap();
    a.sync(None).unwrap();
    // The same content comes back as a new file: its blocks stay in use.
    fs::write(docs.join("twin again.bin"), &twin_body).unwrap();
    a.sync(None).unwrap();
    assert_eq!(a.trash_list(None).unwrap().len(), 2);

    // A folder kept longer than the vault's 30 days.
    let st = a.trash_set(None, Some("docs"), None).err();
    assert!(st.is_some(), "--folder needs --days");
    a.trash_set(Some(40), Some("docs"), None).unwrap();
    let now = varsto_core::util::now_utc();
    let up = a.trash_upkeep_at(now + 31 * DAY).unwrap();
    assert_eq!(up.expired, 0);
    assert!(gone.is_subset(&objects(&one)));
    // Back to the vault's days.
    a.trash_set(Some(0), Some("docs"), None).unwrap();
    let up = a.trash_upkeep_at(now + 29 * DAY).unwrap();
    assert_eq!(up.expired, 0);
    // The packs that hold the expired blocks.
    let gone_packs: BTreeSet<String> = gone
        .iter()
        .filter_map(|o| common::pack_path(&one, o))
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert!(!gone_packs.is_empty());
    let up = a.trash_upkeep_at(now + 31 * DAY).unwrap();
    assert_eq!(up.expired, 2);
    assert!(up.blocks_dropped >= gone.len() as u64, "{up:?}");
    let left = objects(&one);
    assert!(left.is_disjoint(&gone), "expired blocks are deleted");
    assert!(twin.is_subset(&left), "blocks a current file uses stay");
    assert!(kept.is_subset(&left));
    // The drops are in the ledger: no device counts those packs any more.
    let view = a.ledger_view3().unwrap();
    for p in &gone_packs {
        let mut id = [0u8; 32];
        hex::decode_to_slice(p, &mut id).unwrap();
        assert!(view.holders(&id).is_empty(), "pack {p} still held");
    }
    let f = a.fsck(false).unwrap();
    assert_eq!(f.claims_without_object, 0);
}

#[test]
fn purging_deletes_for_good() {
    let lab = Lab::new();
    let store = dir("box", &lab.p("store"), false);
    let (a_dir, b_dir) = (lab.p("a-docs"), lab.p("b-docs"));
    let (mut a, key) = init(&lab.p("a"), "laptop");
    a.add_storage(store.clone()).unwrap();
    a.add_folder("docs", &a_dir).unwrap();
    fs::write(a_dir.join("keep.txt"), b"keep").unwrap();
    a.sync(None).unwrap();
    let kept = objects(&lab.p("store"));
    fs::write(a_dir.join("one.bin"), pseudo_random(50_000, 10)).unwrap();
    fs::write(a_dir.join("two.bin"), pseudo_random(50_000, 11)).unwrap();
    a.sync(None).unwrap();
    let mut b = join(&lab.p("b"), "phone", &key, store.clone(), &mut a);
    b.attach_folder("docs", &b_dir, false).unwrap();
    b.sync(None).unwrap();
    fs::remove_file(a_dir.join("one.bin")).unwrap();
    fs::remove_file(a_dir.join("two.bin")).unwrap();
    a.sync(None).unwrap();

    // B deletes one entry for good, then empties the trash. B marks the
    // blocks dead in its block map; they go once A, the folder's other
    // writer, has acknowledged the marks (storage format 3).
    let r = b.trash_purge(Some("docs"), &s("one.bin"), false).unwrap();
    assert_eq!(r.entries, 1);
    assert_eq!(r.blocks_dropped, 0, "{r:?}");
    assert_eq!(paths(&a.trash_list(None).unwrap()), s("two.bin"));
    let r = b.trash_purge(None, &[], true).unwrap();
    assert_eq!(r.entries, 1);
    assert!(a.trash_list(None).unwrap().is_empty());
    assert!(b.trash_list(None).unwrap().is_empty());
    let up = b.trash_upkeep().unwrap();
    assert_eq!(up.blocks_dropped, 0, "{up:?}");
    assert!(
        up.notes.iter().any(|n| n.contains("laptop")),
        "collection waits for the laptop: {up:?}"
    );
    // A syncs: it acknowledges B's marks, and B's next upkeep collects.
    a.sync(None).unwrap();
    let up = b.trash_upkeep().unwrap();
    assert!(up.blocks_dropped > 0, "{up:?}");
    // Only the blocks of the kept file are left.
    assert_eq!(objects(&lab.p("store")), kept);
    assert!(b.trash_purge(Some("docs"), &s("nothing"), false).is_err());
}

#[test]
fn a_trash_storage_takes_the_trashed_blocks() {
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
    let st = a
        .trash_set(None, None, Some(Some("glacier".into())))
        .unwrap();
    assert_eq!(st.storage.as_deref(), Some("glacier"));
    assert!(st.storage_cold);
    a.add_folder("docs", &a_dir).unwrap();
    fs::write(a_dir.join("keep.bin"), pseudo_random(60_000, 12)).unwrap();
    a.sync(None).unwrap();
    // Current files are not written to the trash storage.
    assert!(objects(&cold).is_empty());
    let kept = objects(&one);
    let body = pseudo_random(140_000, 13);
    fs::write(a_dir.join("old.bin"), &body).unwrap();
    fs::write(a_dir.join("older.bin"), pseudo_random(40_000, 14)).unwrap();
    a.sync(None).unwrap();
    let all = objects(&one);
    fs::remove_file(a_dir.join("old.bin")).unwrap();
    fs::remove_file(a_dir.join("older.bin")).unwrap();
    a.sync(None).unwrap();

    let up = a.trash_upkeep().unwrap();
    assert!(up.blocks_moved > 0, "{up:?}");
    let trashed: BTreeSet<String> = all.difference(&kept).cloned().collect();
    assert!(trashed.is_subset(&objects(&cold)));
    assert_eq!(objects(&one), kept, "warm storage keeps current files only");
    let status = a.trash_status().unwrap();
    assert!(status.by_storage.get("glacier").copied().unwrap_or(0) > 0);
    assert!(!status.by_storage.contains_key("one"));

    // Another device restores: the cold read must be confirmed.
    let mut b = join(&lab.p("b"), "phone", &key, dir("one", &one, false), &mut a);
    b.add_storage(dir("glacier", &cold, true)).unwrap();
    b.attach_folder("docs", &b_dir, false).unwrap();
    b.sync(None).unwrap();
    let list = b.trash_list(None).unwrap();
    assert!(list.iter().all(|i| i.cold_only));
    let plan = b.trash_restore_plan("docs", &s("old.bin"), None).unwrap();
    assert_eq!(plan.cold_storages, s("glacier"));
    let err = b
        .trash_restore("docs", &s("old.bin"), None, false)
        .unwrap_err()
        .to_string();
    assert!(err.contains("cold read"), "{err}");
    let r = b.trash_restore("docs", &s("old.bin"), None, true).unwrap();
    assert!(r.cold_read);
    assert_eq!(fs::read(b_dir.join("old.bin")).unwrap(), body);
    // A current file again: its blocks are back on the warm storage.
    let back: BTreeSet<String> = objects(&one).difference(&kept).cloned().collect();
    assert!(!back.is_empty());

    // Deleting for good does not delete from cold storage before its
    // minimum duration; the upkeep does it afterwards. (A cold pack goes
    // whole once none of its blocks is used, so both files go here.)
    a.sync(None).unwrap();
    fs::remove_file(a_dir.join("old.bin")).unwrap();
    a.sync(None).unwrap();
    let r = a
        .trash_purge(
            Some("docs"),
            &["old.bin".to_string(), "older.bin".to_string()],
            false,
        )
        .unwrap();
    assert_eq!(r.entries, 2);
    // The phone's manifest still names old.bin until it has pulled the
    // deletion and published its own view; then the laptop marks the rest,
    // and the phone acknowledges the marks.
    b.sync(None).unwrap();
    a.trash_upkeep().unwrap();
    b.sync(None).unwrap();
    let up = a.trash_upkeep().unwrap();
    assert!(up.blocks_waiting > 0, "{up:?}");
    let before = objects(&cold).len();
    let now = varsto_core::util::now_utc();
    let up = a.trash_upkeep_at(now + 91 * DAY).unwrap();
    assert!(up.blocks_dropped > 0, "{up:?}");
    assert!(objects(&cold).len() < before);
}

#[test]
fn the_upkeep_runs_daily() {
    let lab = Lab::new();
    let (mut a, _) = init(&lab.p("a"), "laptop");
    a.add_storage(dir("one", &lab.p("one"), false)).unwrap();
    let now = varsto_core::util::now_utc();
    assert!(a.trash_upkeep_due(now));
    a.trash_upkeep_at(now).unwrap();
    assert!(!a.trash_upkeep_due(now + 3600));
    assert!(a.trash_upkeep_due(now + DAY));
    let st = a.trash_status().unwrap();
    assert_eq!(st.days, 30);
    assert_eq!(st.last_upkeep_utc, Some(now));
    assert!(a.trash_set(Some(0), None, None).is_err());
}

/// The vault's trash settings travel as `settings` records (kind 18,
/// `vault/settings/<device>/`): what one device sets, another reads.
#[test]
fn trash_settings_reach_the_other_devices() {
    let lab = Lab::new();
    let store = dir("box", &lab.p("store"), false);
    let (mut a, key) = init(&lab.p("a"), "laptop");
    a.add_storage(store.clone()).unwrap();
    a.add_folder("docs", &lab.p("a-docs")).unwrap();
    a.sync(None).unwrap();
    let mut b = join(&lab.p("b"), "phone", &key, store, &mut a);
    b.attach_folder("docs", &lab.p("b-docs"), false).unwrap();
    b.sync(None).unwrap();
    assert_eq!(b.trash_status().unwrap().days, 30);

    a.trash_set(Some(45), None, None).unwrap();
    a.trash_set(Some(60), Some("docs"), None).unwrap();
    let st = b.trash_status().unwrap();
    assert_eq!(st.days, 45);
    assert_eq!(st.folder_days.get("docs"), Some(&60));
    assert!(lab.p("store").join("vault/settings").is_dir());
    assert!(!lab.p("store").join("vault/trash-settings").exists());

    // B changes them back; A follows.
    b.trash_set(Some(0), Some("docs"), None).unwrap();
    let st = a.trash_status().unwrap();
    assert_eq!(st.days, 45);
    assert!(st.folder_days.is_empty(), "{:?}", st.folder_days);
}
