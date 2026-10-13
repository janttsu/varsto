// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The Help page's next steps follow the vault's situation: no vault, a
//! locked vault, a fresh vault, a storage only, a folder on one device, two
//! devices, a broken policy, paused syncing, a folder not synced here, the
//! recovery kit printed or out of date, and a vault where all is in order.

use std::fs;
use std::path::Path;
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::{help_without_vault, HelpObserved};
use varsto_core::help::{self, HelpState, Inputs, Kit, Phase, ServiceIn, StorageIn};
use varsto_core::policy::Policy;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "help-test-passphrase-5521";

fn dir(root: &Path, name: &str, place: &str) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: root.join(name),
        cold: false,
        carrier: false,
        place: place.into(),
        min_free: None,
    }
}

fn running() -> HelpObserved {
    HelpObserved {
        service: Some(ServiceIn {
            running: true,
            p2p_listening: true,
            p2p_reachable: true,
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn ids(h: &HelpState) -> Vec<&str> {
    h.steps.iter().map(|s| s.id.as_str()).collect()
}

fn first(h: &HelpState) -> &str {
    h.steps.first().map(|s| s.id.as_str()).unwrap_or("")
}

/// Every sentence's placeholders have values, and the English text renders.
fn well_formed(h: &HelpState) {
    let mut texts = vec![&h.headline];
    texts.extend(h.summary.iter());
    texts.extend(h.details.iter());
    texts.extend(h.attention.iter().map(|a| &a.text));
    texts.extend(h.folders.iter().map(|f| &f.line));
    texts.extend(h.storages.iter().map(|s| &s.line));
    for s in h.steps.iter().chain(h.tips.iter()) {
        texts.push(&s.title);
        texts.push(&s.why);
        texts.extend(s.how.iter());
        if let Some(a) = &s.action {
            texts.push(&a.label);
            assert!(!a.page.is_empty());
        }
    }
    for t in texts {
        let r = t.render();
        assert!(!r.is_empty(), "empty sentence {t:?}");
        assert!(!r.contains('{'), "unfilled placeholder in {r:?}");
    }
    let text = help::render_text(h);
    assert!(text.contains("WHAT TO DO NEXT"));
}

#[test]
fn no_vault_and_locked() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let h = help_without_vault(&home);
    assert_eq!(h.phase, "no_vault");
    assert_eq!(ids(&h), ["create_vault", "pair_device"]);
    assert_eq!(h.steps[0].action.as_ref().unwrap().page, "setup");
    assert!(!h.all_ok);
    well_formed(&h);

    let (e, _) = Engine::init(&home, "laptop", PASS).unwrap();
    drop(e);
    let h = help_without_vault(&home);
    assert_eq!(h.phase, "locked");
    assert_eq!(first(&h), "unlock");
    assert_eq!(h.device, "laptop");
    assert!(h.headline.render().contains("laptop"));
    well_formed(&h);
}

#[test]
fn steps_follow_the_vault_as_it_grows() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let home = root.join("a-home");
    let (mut a, key) = Engine::init(&home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;

    // A fresh vault: the first step is a storage.
    let h = a.help_state(running()).unwrap();
    assert_eq!(h.phase, "ready");
    assert_eq!(first(&h), "add_storage");
    let act = h.steps[0].action.as_ref().unwrap();
    assert_eq!(
        (act.page.as_str(), act.target.as_deref()),
        ("storages", Some("addstorage"))
    );
    assert!(h.steps[0]
        .command
        .as_deref()
        .unwrap()
        .starts_with("varsto storage add-"));
    assert!(!ids(&h).contains(&"add_folder"));
    assert_eq!(h.figures.storages, 0);
    assert!(h.headline.render().contains("no storage"));
    assert!(!h.all_ok);
    well_formed(&h);

    // A storage but no folder: add a folder. The storage is a pool of
    // disks with no disk yet, so nothing reaches it.
    a.add_storage(StorageSpec::Pool {
        name: "shelf".into(),
        place: "home".into(),
        reserve_percent: 5,
        min_reserve_bytes: 0,
        disks: vec![],
        scan_roots: vec![],
        copies: 1,
        verify_after_days: 180,
    })
    .unwrap();
    let h = a.help_state(running()).unwrap();
    assert_eq!(first(&h), "add_folder");
    assert!(!ids(&h).contains(&"add_storage"));
    assert_eq!(
        h.steps[0].action.as_ref().unwrap().target.as_deref(),
        Some("addfolder")
    );
    assert!(ids(&h).contains(&"kit"));
    well_formed(&h);

    // A folder with files, pushed while no storage can take them: they lack a copy.
    let docs = root.join("docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("a.txt"), vec![7u8; 50_000]).unwrap();
    fs::write(docs.join("b.txt"), b"hello").unwrap();
    fs::write(docs.join("c.txt"), vec![9u8; 30_000]).unwrap();
    a.add_folder("docs", &docs).unwrap();
    a.push("docs").unwrap();
    let h = a.help_state(running()).unwrap();
    assert!(ids(&h).contains(&"sync"), "{:?}", ids(&h));
    assert!(h.figures.unkept_bytes > 0);
    assert!(h.headline.render().contains("no copy on a storage"));
    let sync = h.steps.iter().find(|s| s.id == "sync").unwrap();
    assert_eq!(
        sync.action.as_ref().unwrap().target.as_deref(),
        Some("do:sync")
    );
    assert_eq!(sync.command.as_deref(), Some("varsto sync"));

    // A directory storage takes them. The default policy wants a copy in
    // the cloud too, so that comes first, then the kit and other devices.
    a.add_storage(dir(root, "box", "home")).unwrap();
    a.push("docs").unwrap();
    let h = a.help_state(running()).unwrap();
    assert_eq!(h.figures.unkept_bytes, 0);
    assert_eq!(h.figures.files, 3);
    assert_eq!(h.folders[0].storages[0].name, "box");
    assert_eq!(h.folders[0].devices, ["laptop"]);
    assert!(!ids(&h).contains(&"sync"));
    assert_eq!(first(&h), "policy:docs", "{:?}", ids(&h));
    assert!(h.steps[0].title.render().contains("cloud"));
    assert_eq!(
        h.steps[0].action.as_ref().unwrap().target.as_deref(),
        Some("addstorage")
    );
    assert!(ids(&h).contains(&"kit"));
    assert!(ids(&h).contains(&"add_device"));
    // The cloud step already leads to Add a storage.
    assert!(!ids(&h).contains(&"offsite"), "{:?}", ids(&h));
    assert!(h.attention.iter().any(|x| x.id == "kit"));
    assert!(h.attention.iter().any(|x| x.id == "policy:docs"));
    assert!(!h.figures.offsite);
    assert!(!h.all_ok);
    assert!(h.tips.is_empty());
    well_formed(&h);

    // The kit printed: no more kit step.
    varsto_core::recovery_guide::record_kit_printed(&home, a.key_epoch(), false).unwrap();
    let h = a.help_state(running()).unwrap();
    assert!(!ids(&h).contains(&"kit"));
    assert!(!h.attention.iter().any(|x| x.id == "kit"));

    // A second device joins through the storage. On it the folder is not
    // synced yet, and it is not asked to add devices.
    let b_home = root.join("b-home");
    let b_docs = root.join("b-docs");
    let mut b = Engine::join(&b_home, "phone", PASS, &key, dir(root, "box", "home")).unwrap();
    b.chunker = ChunkerParams::SMALL;
    let hb = b.help_state(running()).unwrap();
    assert!(ids(&hb).contains(&"attach"), "{:?}", ids(&hb));
    assert!(!ids(&hb).contains(&"add_device"));
    assert!(hb.folders.iter().any(|f| f.name == "docs" && !f.attached));
    well_formed(&hb);
    // It syncs the folder, which checks the copies it reads.
    b.attach_folder("docs", &b_docs, false).unwrap();
    b.pull("docs").unwrap();
    drop(b);

    // A copy in the cloud, and the laptop learns of the phone's checks.
    a.add_storage(dir(root, "cloudbox", "cloud")).unwrap();
    a.sync(None).unwrap();
    a.push("docs").unwrap();
    let h = a.help_state(running()).unwrap();
    assert_eq!(h.figures.devices, 2);
    assert!(h.summary[0].render().contains("phone"));
    assert!(!ids(&h).contains(&"add_device"), "{:?}", ids(&h));
    assert!(
        h.folders[0].storages.iter().any(|s| s.name == "cloudbox"),
        "{:?}",
        h.folders[0]
    );
    assert!(h.figures.offsite);
    // Everything is in order: nothing to do, tips instead.
    assert!(h.all_ok, "{:?} {:?}", ids(&h), h.attention);
    assert!(
        h.steps.iter().all(|s| s.level == "suggested"),
        "{:?}",
        ids(&h)
    );
    assert!(h.tips.iter().any(|t| t.id == "tip:backups"));
    well_formed(&h);

    // A policy that asks for more copies than there are storages.
    a.set_policy(
        "docs",
        Some(Policy {
            min_copies: 4,
            ..Default::default()
        }),
    )
    .unwrap();
    let h = a.help_state(running()).unwrap();
    assert_eq!(first(&h), "policy:docs", "{:?}", ids(&h));
    assert_eq!(h.steps[0].level, "urgent");
    assert!(
        h.steps[0].how[0].render().contains("only 3 storages"),
        "{:?}",
        h.steps[0].how
    );
    assert!(h
        .attention
        .iter()
        .any(|x| x.id == "policy:docs" && x.level == "bad"));
    assert!(!h.all_ok);
    assert!(h.tips.is_empty());
    well_formed(&h);
    a.set_policy("docs", None).unwrap();

    // Syncing paused in the service.
    let paused = HelpObserved {
        service: Some(ServiceIn {
            running: true,
            paused: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    let h = a.help_state(paused).unwrap();
    assert_eq!(first(&h), "resume");
    assert_eq!(
        h.steps[0].action.as_ref().unwrap().target.as_deref(),
        Some("pause")
    );
    assert!(h.attention.iter().any(|x| x.id == "service"));

    // No service at all (the command line without one).
    let none = HelpObserved {
        service: Some(ServiceIn::default()),
        ..Default::default()
    };
    let h = a.help_state(none).unwrap();
    assert!(ids(&h).contains(&"start_service"));
}

#[test]
fn kit_out_of_date_and_member_rules() {
    // Pure rules: a kit printed before a key change.
    let base = Inputs {
        phase: Phase::Ready,
        device: "laptop".into(),
        other_devices: vec!["phone".into()],
        storages: vec![
            StorageIn {
                name: "box".into(),
                kind: "directory".into(),
                place: "home".into(),
                bytes: 10,
                quota_state: "none".into(),
                ..Default::default()
            },
            StorageIn {
                name: "bucket".into(),
                kind: "s3".into(),
                place: "cloud".into(),
                bytes: 10,
                quota_state: "none".into(),
                ..Default::default()
            },
        ],
        folders: vec![help::FolderIn {
            name: "docs".into(),
            attached: true,
            files: 1,
            bytes: 10,
            policy: true,
            ..Default::default()
        }],
        total_bytes: 10,
        copies_bytes: [0, 0, 10, 0],
        kit: Kit::Outdated,
        trash_days: 30,
        ..Default::default()
    };
    let h = help::build(&base);
    assert_eq!(first(&h), "kit");
    assert!(h.steps[0].title.render().contains("new recovery words"));
    assert!(!h.all_ok);
    well_formed(&h);

    let ok = Inputs {
        kit: Kit::Printed,
        ..base.clone()
    };
    let h = help::build(&ok);
    assert!(h.steps.is_empty(), "{:?}", ids(&h));
    assert!(h.all_ok);
    assert!(!h.tips.is_empty());
    well_formed(&h);

    // A quota at its limit and a full disk on this device.
    let mut full = ok.clone();
    full.storages[1].quota_state = "full".into();
    full.home_space = Some((500_000_000, 100_000_000_000));
    let h = help::build(&full);
    assert!(ids(&h).contains(&"quota"));
    assert!(ids(&h).contains(&"space"));
    well_formed(&h);

    // A member of someone else's shared folder: no vault-owner steps.
    let member = Inputs {
        member: true,
        kit: Kit::NotPrinted,
        other_devices: vec![],
        storages: vec![],
        ..base
    };
    let h = help::build(&member);
    assert!(!ids(&h).contains(&"kit"));
    assert!(!ids(&h).contains(&"add_storage"));
    assert!(!ids(&h).contains(&"add_device"));
    assert!(h.headline.render().contains("shared"));
}
