// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Change history of files (`varsto changes`): versions made on two devices
//! with the right devices and order, a rename shown as a rename (and the
//! file's history followed back through it), a deletion and a restore, the
//! folder feed with its filters, the history surviving a restart, and a
//! device that joins later starting its history from the manifests.

use std::fs;
use std::path::PathBuf;
use varsto_core::changes::Action;
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::{ChangesQuery, ChangesReport};
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

struct Lab {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    storage: StorageSpec,
}

impl Lab {
    fn new() -> Lab {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        Lab {
            storage: StorageSpec::LocalDir {
                name: "box".into(),
                path: root.join("storage"),
                cold: false,
                carrier: false,
                place: String::new(),
                min_free: None,
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

fn small(mut e: Engine) -> Engine {
    e.chunker = ChunkerParams::SMALL;
    e
}

fn of(e: &Engine, path: Option<&str>) -> ChangesReport {
    e.changes(
        "docs",
        &ChangesQuery {
            path: path.map(|p| p.to_string()),
            ..Default::default()
        },
    )
    .unwrap()
}

fn actions(r: &ChangesReport) -> Vec<(Action, String, String)> {
    r.changes
        .iter()
        .map(|c| (c.event.action, c.event.path.clone(), c.device_name.clone()))
        .collect()
}

#[test]
fn who_changed_what_and_when() {
    let lab = Lab::new();
    let (a, key) = Engine::init(&lab.home("a"), "laptop", PASS).unwrap();
    let mut a = small(a);
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.dir("a")).unwrap();
    fs::write(lab.dir("a").join("plan.txt"), b"first draft").unwrap();
    a.sync(None).unwrap();
    let mut b =
        small(Engine::join(&lab.home("b"), "desk", PASS, &key, lab.storage.clone()).unwrap());
    Engine::grant_all_for_tests(&mut a, &mut b).unwrap();
    b.attach_folder("docs", &lab.dir("b"), false).unwrap();
    b.sync(None).unwrap();

    // B edits; A takes it.
    fs::write(
        lab.dir("b").join("plan.txt"),
        b"second draft, from the desk",
    )
    .unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    let r = of(&a, Some("plan.txt"));
    assert!(r.file);
    assert_eq!(
        actions(&r),
        vec![
            (Action::Modified, "plan.txt".into(), "desk".into()),
            (Action::Created, "plan.txt".into(), "laptop".into()),
        ]
    );
    let newest = &r.changes[0].event;
    assert_eq!(newest.size, 27);
    assert_eq!(newest.hash.len(), 16);
    assert!(
        newest.verified,
        "B's manifest matched its signed announcement"
    );
    assert_eq!(&newest.source, b.device_id());

    // A renames the file: shown as a rename, and the file's history goes on
    // through its old name.
    fs::rename(
        lab.dir("a").join("plan.txt"),
        lab.dir("a").join("final.txt"),
    )
    .unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    for e in [&a, &b] {
        let r = of(e, Some("final.txt"));
        let first = &r.changes[0].event;
        assert_eq!(first.action, Action::Renamed, "{:?}", actions(&r));
        assert_eq!(first.from.as_deref(), Some("plan.txt"));
        let all = actions(&r);
        assert!(
            all.contains(&(Action::Created, "plan.txt".into(), "laptop".into())),
            "{all:?}"
        );
        assert!(
            all.contains(&(Action::Modified, "plan.txt".into(), "desk".into())),
            "{all:?}"
        );
        let old = of(e, Some("plan.txt"));
        assert_eq!(old.changes[0].event.action, Action::Renamed);
        assert_eq!(old.changes[0].event.to.as_deref(), Some("final.txt"));
    }

    // B deletes it; A brings the same content back: a deletion and a restore.
    fs::remove_file(lab.dir("b").join("final.txt")).unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    assert!(!lab.dir("a").join("final.txt").exists());
    fs::write(
        lab.dir("a").join("final.txt"),
        b"second draft, from the desk",
    )
    .unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    let r = of(&b, Some("final.txt"));
    assert_eq!(
        actions(&r)[..2].to_vec(),
        vec![
            (Action::Restored, "final.txt".into(), "laptop".into()),
            (Action::Deleted, "final.txt".into(), "desk".into()),
        ]
    );

    // The folder feed, filtered by device, directory and time.
    fs::create_dir_all(lab.dir("b").join("notes")).unwrap();
    fs::write(lab.dir("b").join("notes/monday.txt"), b"call the bank").unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    let all = of(&a, None);
    assert!(!all.file);
    assert!(all.changes.len() >= 7, "{:?}", actions(&all));
    let desk = a
        .changes(
            "docs",
            &ChangesQuery {
                device: Some("desk".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(desk.changes.iter().all(|c| c.device_name == "desk"));
    assert_eq!(desk.changes[0].event.path, "notes/monday.txt");
    let notes = of(&a, Some("notes"));
    assert_eq!(notes.changes.len(), 1);
    assert!(!notes.file);
    let later = a
        .changes(
            "docs",
            &ChangesQuery {
                since_utc: Some(varsto_core::util::now_utc() + 3600),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(later.changes.is_empty());
    let limited = a
        .changes(
            "docs",
            &ChangesQuery {
                limit: 2,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(limited.changes.len(), 2);
    assert!(limited.truncated);

    // In an organization, by person.
    a.org_create("Acme", "alice").unwrap();
    let alice = a
        .changes(
            "docs",
            &ChangesQuery {
                user: Some("alice".into()),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(alice.changes.len(), all.changes.len());
    assert!(alice
        .changes
        .iter()
        .all(|c| c.user.as_deref() == Some("alice")));

    // The history survives a restart.
    let before = actions(&of(&b, None));
    drop(b);
    let b = Engine::open(&lab.home("b"), PASS).unwrap();
    assert_eq!(actions(&of(&b, None))[..before.len()].to_vec(), before);

    // A device that joins later starts from the manifests: the newest
    // version of every file, with the device that made it.
    let mut c = small(
        Engine::join(
            &lab.home("c"),
            "phone",
            PASS,
            &a.export_vault_key().unwrap(),
            lab.storage.clone(),
        )
        .unwrap(),
    );
    // In the organization, an administrator lists it before it is trusted
    // with a folder key.
    c.sync(None).unwrap();
    a.sync(None).unwrap();
    a.org_add_device(c.device_id().as_str(), "alice").unwrap();
    Engine::grant_all_for_tests(&mut a, &mut c).unwrap();
    c.attach_folder("docs", &lab.dir("c"), false).unwrap();
    c.sync(None).unwrap();
    let r = of(&c, Some("notes/monday.txt"));
    assert_eq!(r.changes.len(), 1);
    assert_eq!(r.changes[0].device_name, "desk");
    assert!(r.changes[0].event.verified);
    let r = of(&c, Some("final.txt"));
    assert_eq!(r.changes[0].device_name, "laptop");
    assert!(!r.changes[0].event.backfilled);
}
