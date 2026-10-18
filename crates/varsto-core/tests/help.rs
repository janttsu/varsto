// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! The Help page's next steps follow the vault's situation: no vault, a
//! locked vault, a fresh vault, a storage only, a folder on one device, two
//! devices, a broken policy, paused syncing, a folder not synced here, the
//! recovery kit printed or out of date, and a vault where all is in order.

mod common;

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

    // A storage but no folder: add a folder. A folder's records live on the
    // storage, so it comes first.
    a.add_storage(dir(root, "box", "home")).unwrap();
    let h = a.help_state(running()).unwrap();
    assert_eq!(first(&h), "add_folder");
    assert!(!ids(&h).contains(&"add_storage"));
    assert_eq!(
        h.steps[0].action.as_ref().unwrap().target.as_deref(),
        Some("addfolder")
    );
    assert!(ids(&h).contains(&"kit"));
    well_formed(&h);

    // A folder with files that were read but not stored yet: they lack a copy.
    let docs = root.join("docs");
    fs::create_dir_all(&docs).unwrap();
    fs::write(docs.join("a.txt"), vec![7u8; 50_000]).unwrap();
    fs::write(docs.join("b.txt"), b"hello").unwrap();
    fs::write(docs.join("c.txt"), vec![9u8; 30_000]).unwrap();
    a.add_folder("docs", &docs).unwrap();
    a.pull("docs").unwrap();
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

    // The sync stores them. The default policy wants a copy in the cloud
    // too, so that comes first, then the kit and other devices.
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
    // The laptop approves it for the folder, and it syncs the folder, which
    // checks the copies it reads.
    common::approve_all(&mut a, &mut b);
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

#[test]
fn paused_folders_come_first() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let (mut a, _) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(dir(root, "box", "home")).unwrap();
    let docs = root.join("docs");
    fs::create_dir_all(&docs).unwrap();
    for n in 0..150 {
        fs::write(docs.join(format!("f{n}.txt")), format!("file {n}")).unwrap();
    }
    a.add_folder("docs", &docs).unwrap();
    a.push("docs").unwrap();
    let h = a.help_state(running()).unwrap();
    assert!(
        !ids(&h).iter().any(|i| i.starts_with("paused:")),
        "{:?}",
        ids(&h)
    );

    // The folder's disk is gone: paused, the marker step first of all.
    fs::rename(&docs, root.join("docs-away")).unwrap();
    let h = a.help_state(running()).unwrap();
    let att = h.attention.iter().find(|x| x.id == "paused:docs").unwrap();
    assert_eq!(att.level, "bad");
    assert!(att.text.render().contains(".varsto-folder"));
    let step = h.steps.iter().find(|s| s.id == "paused:docs").unwrap();
    assert_eq!(step.level, "urgent");
    assert_eq!(
        step.command.as_deref(),
        Some("varsto folder repair-marker docs")
    );
    assert_eq!(
        step.action.as_ref().unwrap().target.as_deref(),
        Some("foldersafety")
    );
    well_formed(&h);
    fs::rename(root.join("docs-away"), &docs).unwrap();

    // Every file deleted at once: held, with the count.
    for n in 0..150 {
        fs::remove_file(docs.join(format!("f{n}.txt"))).unwrap();
    }
    assert!(a.push("docs").is_err());
    let h = a.help_state(running()).unwrap();
    let att = h.attention.iter().find(|x| x.id == "paused:docs").unwrap();
    assert!(att.text.render().contains("150 deletions"), "{att:?}");
    let step = h.steps.iter().find(|s| s.id == "paused:docs").unwrap();
    assert_eq!(step.level, "urgent");
    assert!(step
        .command
        .as_deref()
        .unwrap()
        .starts_with("varsto folder confirm-deletions docs"));
    assert!(step.title.render().contains("deletions held"));
    well_formed(&h);

    // Confirmed: nothing paused any more.
    a.confirm_deletions("docs").unwrap();
    let h = a.help_state(running()).unwrap();
    assert!(!ids(&h).contains(&"paused:docs"), "{:?}", ids(&h));
}

/// A vault in order, for the pure rules below.
fn in_order() -> Inputs {
    Inputs {
        phase: Phase::Ready,
        device: "laptop".into(),
        other_devices: vec!["phone".into()],
        storages: vec![StorageIn {
            name: "box".into(),
            kind: "directory".into(),
            place: "home".into(),
            bytes: 10,
            quota_state: "none".into(),
            ..Default::default()
        }],
        folders: vec![help::FolderIn {
            name: "docs".into(),
            attached: true,
            files: 1,
            bytes: 10,
            ..Default::default()
        }],
        total_bytes: 10,
        copies_bytes: [0, 10, 0, 0],
        kit: Kit::Printed,
        trash_days: 30,
        ..Default::default()
    }
}

#[test]
fn read_only_folder_with_changes_kept_aside() {
    let mut i = in_order();
    i.kept_aside = vec![help::KeptAsideIn {
        folder: "team".into(),
        files: 3,
        dir: "/home/u/.varsto/kept-aside/team".into(),
    }];
    let h = help::build(&i);
    let att = h
        .attention
        .iter()
        .find(|a| a.id == "kept_aside:team")
        .unwrap();
    assert_eq!(att.level, "warn");
    assert!(att.text.render().contains("3 files"));
    assert_eq!(first(&h), "kept_aside:team");
    assert_eq!(h.steps[0].level, "urgent");
    assert!(h.steps[0].how[0].render().contains("kept-aside/team"));
    assert_eq!(h.steps[0].action.as_ref().unwrap().page, "shared");
    well_formed(&h);
}

#[test]
fn device_locked_out_by_the_organization() {
    let mut i = in_order();
    i.org = Some(help::OrgIn {
        name: "Acme".into(),
        listed: true,
        blocked: Some("this organization (Acme) does not allow linux devices".into()),
        ..Default::default()
    });
    let h = help::build(&i);
    let att = h.attention.iter().find(|a| a.id == "org_blocked").unwrap();
    assert_eq!(att.level, "bad");
    assert!(att.text.render().contains("linux devices"));
    assert_eq!(first(&h), "org_blocked");
    assert_eq!(h.steps[0].level, "urgent");
    assert_eq!(h.steps[0].action.as_ref().unwrap().page, "organization");
    assert_eq!(h.steps[0].command.as_deref(), Some("varsto org status"));
    // One bad item: the headline says so in the singular.
    assert!(h
        .headline
        .render()
        .ends_with("but 1 thing needs your attention."));
    well_formed(&h);
}

#[test]
fn below_the_minimum_free_space() {
    let mut i = in_order();
    i.low_space = vec![help::LowSpaceIn {
        key: "folder:docs".into(),
        label: "folder docs".into(),
        stops: "downloads".into(),
        free: 1_000_000_000,
    }];
    let h = help::build(&i);
    let att = h
        .attention
        .iter()
        .find(|a| a.id == "space:folder:docs")
        .unwrap();
    assert!(att.text.render().contains("folder docs"));
    assert_eq!(first(&h), "space");
    assert_eq!(h.steps[0].level, "urgent");
    assert_eq!(
        h.steps[0].command.as_deref(),
        Some("varsto folder set docs --min-free <limit>")
    );
    well_formed(&h);

    // The device directory short as well as low on the disk: one item
    // and one step for it, not two.
    i.low_space = vec![help::LowSpaceIn {
        key: "device".into(),
        label: "the device directory".into(),
        stops: "writes".into(),
        free: 500_000_000,
    }];
    i.home_space = Some((500_000_000, 100_000_000_000));
    let h = help::build(&i);
    let space: Vec<&str> = h
        .attention
        .iter()
        .filter(|a| a.id.starts_with("space"))
        .map(|a| a.id.as_str())
        .collect();
    assert_eq!(space, ["space:device"]);
    assert_eq!(ids(&h).iter().filter(|s| **s == "space").count(), 1);
    well_formed(&h);
}

#[test]
fn headline_counts_in_singular_and_plural() {
    let mut i = in_order();
    i.scrub_damaged = 1;
    i.repair_losses = 1;
    let h = help::build(&i);
    assert_eq!(
        h.headline.render(),
        "Your files are kept in 1 storage, but 2 things need your attention."
    );
    i.storages.push(StorageIn {
        name: "bucket".into(),
        kind: "s3".into(),
        place: "cloud".into(),
        bytes: 10,
        quota_state: "none".into(),
        ..Default::default()
    });
    i.repair_losses = 0;
    let h = help::build(&i);
    assert_eq!(
        h.headline.render(),
        "Your files are kept in 2 storages, but 1 thing needs your attention."
    );
}
