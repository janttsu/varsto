// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Organizations (`docs/spec/alpha-0-format.md` section 27): creating one,
//! approving a device, removing a user with every device at once, what a
//! member may not do, a device that joined without approval, and rosters
//! that only an admin can write.

use std::fs;
use std::path::PathBuf;
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::DeviceRemoved;
use varsto_core::org::{OrgEvent, OrgPolicy, OrgRequest};
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

/// A creates the vault with one file; B and C join and sync it.
fn three_devices(lab: &Lab) -> (Engine, Engine, Engine, String) {
    let (a, key) = Engine::init(&lab.home("a"), "hq", PASS).unwrap();
    let mut a = small(a);
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.dir("a")).unwrap();
    fs::write(lab.dir("a").join("one.txt"), b"before the organization").unwrap();
    a.push("docs").unwrap();
    let mut others = Vec::new();
    for who in ["b", "c"] {
        let mut e =
            small(Engine::join(&lab.home(who), who, PASS, &key, lab.storage.clone()).unwrap());
        e.attach_folder("docs", &lab.dir(who), false).unwrap();
        e.sync(None).unwrap();
        others.push(e);
    }
    a.sync(None).unwrap();
    let c = others.pop().unwrap();
    let b = others.pop().unwrap();
    (a, b, c, key)
}

fn removed(e: &anyhow::Error) -> Option<&DeviceRemoved> {
    e.downcast_ref::<DeviceRemoved>()
}

#[test]
fn create_approve_and_remove_a_user() {
    let lab = Lab::new();
    let (mut a, mut b, mut c, key) = three_devices(&lab);
    assert!(a.org().is_none());

    // A founds the organization: it is the admin, every device is alice's.
    let created = a.org_create("Acme", "alice").unwrap();
    assert_eq!(created.root_words.split(' ').count(), 24);
    assert_eq!(created.devices.len(), 3);
    let s = a.org_summary().unwrap();
    assert!(s.this_device_admin && s.this_device_listed);
    assert_eq!(s.users.len(), 1);
    assert_eq!(s.users[0].devices.len(), 3);
    assert_eq!(s.log.len(), 1);
    assert!(a.org_create("Twice", "x").is_err());

    // B learns it on its next sync and is a member, not an admin.
    b.sync(None).unwrap();
    let sb = b.org_summary().unwrap();
    assert_eq!(sb.name, "Acme");
    assert!(!sb.this_device_admin && sb.this_device_listed);
    assert_eq!(sb.this_user.as_deref(), Some("alice"));
    assert_eq!(sb.org_id, s.org_id);
    assert!(b.status().unwrap().org.unwrap().user.as_deref() == Some("alice"));
    let info = b.devices_list();
    assert!(info.iter().all(|d| d.user.as_deref() == Some("alice")));
    assert_eq!(
        info.iter()
            .filter(|d| d.role.as_deref() == Some("admin"))
            .count(),
        1
    );

    // What a member may not do under the default policy.
    assert!(
        b.revoke_device("c", false).is_err(),
        "members cannot revoke"
    );
    assert!(
        b.pairing_bundle().is_err(),
        "members cannot hand out the key"
    );
    assert!(b.export_vault_key().is_err());
    assert!(b.share_create("docs").is_err());
    assert!(b
        .set_policy(
            "docs",
            Some(varsto_core::policy::Policy {
                min_copies: 1,
                min_per_place: Default::default(),
                verified_within_days: None,
            })
        )
        .is_err());
    assert!(b.org_remove_user("alice", false).is_err());
    assert!(b.org_approve("vor1.junk", "x", None).is_err());

    // A new device D asks to join; A approves it for "dana".
    let code = OrgRequest::code_for(&lab.home("d"), Some("d-laptop")).unwrap();
    let fp = OrgRequest::fingerprint_for(&lab.home("d")).unwrap();
    assert!(
        a.org_approve(&code, "dana", Some("wrong words here"))
            .is_err(),
        "a mismatching fingerprint is refused"
    );
    let approved = a.org_approve(&code, "dana", Some(&fp)).unwrap();
    assert_eq!(approved.user, "dana");
    assert_eq!(approved.name, "d-laptop");
    let (d, notes, approval) =
        Engine::org_join(&lab.home("d"), "d-laptop", PASS, &approved.token).unwrap();
    let mut d = small(d);
    assert_eq!(approval.user, "dana");
    assert!(notes.iter().any(|n| n.contains("joined")));
    assert_eq!(d.device_id().to_string(), approved.device_id);
    d.attach_folder("docs", &lab.dir("d"), false).unwrap();
    d.sync(None).unwrap();
    assert!(lab.dir("d").join("one.txt").exists());
    let sd = d.org_summary().unwrap();
    assert!(sd.this_device_listed);
    assert_eq!(sd.this_user.as_deref(), Some("dana"));
    assert!(
        !OrgRequest::fingerprint_for(&lab.home("d")).is_ok(),
        "the request is cleared"
    );

    // D writes a file; A and B get it, because D is in the roster.
    fs::write(lab.dir("d").join("from-d.txt"), b"hello from dana").unwrap();
    d.push("docs").unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(lab.dir("a").join("from-d.txt").exists());
    assert!(lab.dir("b").join("from-d.txt").exists());
    assert_eq!(a.org_summary().unwrap().users.len(), 2);

    // E joins with the vault key itself, without approval: nobody trusts it.
    let mut e = small(Engine::join(&lab.home("e"), "e", PASS, &key, lab.storage.clone()).unwrap());
    e.attach_folder("docs", &lab.dir("e"), false).unwrap();
    e.sync(None).unwrap();
    assert!(
        lab.dir("e").join("one.txt").exists(),
        "it holds the key, so it reads"
    );
    assert!(!e.org_summary().unwrap().this_device_listed);
    fs::write(lab.dir("e").join("from-e.txt"), b"not approved").unwrap();
    e.push("docs").unwrap();
    a.sync(None).unwrap();
    assert!(
        !lab.dir("a").join("from-e.txt").exists(),
        "an unlisted device's manifests are ignored"
    );
    assert!(!a.devices_list().iter().any(|x| x.name == "e"));
    let sa = a.org_summary().unwrap();
    assert_eq!(sa.unlisted.len(), 1);
    assert_eq!(sa.unlisted[0].name, "e");
    // Until an admin adds it.
    a.org_add_device("e", "erin").unwrap();
    a.sync(None).unwrap();
    assert!(lab.dir("a").join("from-e.txt").exists());
    assert!(a.org_summary().unwrap().unlisted.is_empty());

    // Alice has two more devices; removing dana removes d only, in one epoch.
    let d_id = d.device_id().clone();
    let report = a.org_remove_user("dana", true).unwrap();
    assert_eq!(report.devices, vec!["d-laptop".to_string()]);
    assert_eq!(report.revoke.key_epoch, 1);
    assert!(report.revoke.keys_sent_to.contains(&"b".to_string()));
    let sa = a.org_summary().unwrap();
    assert_eq!(sa.users.len(), 2, "alice and erin remain");
    assert_eq!(sa.removed.len(), 1);
    assert!(sa.removed[0].wipe);
    assert!(matches!(
        sa.log.last().unwrap().event,
        OrgEvent::UserRemoved { ref user, wipe: true, .. } if user == "dana"
    ));
    assert!(a.is_revoked(&d_id));
    // D finds out and is wiped; B follows the new epoch.
    let err = d.sync(None).unwrap_err();
    assert!(removed(&err).is_some_and(|r| r.wiped));
    assert!(!lab.dir("d").join("one.txt").exists());
    b.sync(None).unwrap();
    assert_eq!(b.key_epoch(), 1);
    assert!(b.org_summary().unwrap().removed.len() == 1);
    assert!(b
        .org_log_entries()
        .iter()
        .any(|l| l.text.contains("removed dana")));
    c.sync(None).unwrap();
    assert_eq!(c.key_epoch(), 1);

    // Removing a single device through the ordinary path keeps the roster in step.
    let r = a.revoke_device("c", false).unwrap();
    assert_eq!(r.key_epoch, 2);
    let sa = a.org_summary().unwrap();
    assert_eq!(sa.removed.len(), 2);
    assert_eq!(
        sa.users
            .iter()
            .find(|u| u.user == "alice")
            .unwrap()
            .devices
            .len(),
        2
    );
    assert!(a.org_remove_user("nobody", false).is_err());
    assert!(
        a.org_remove_user("alice", false).is_err(),
        "an admin cannot remove the user who owns the device it runs on"
    );
}

#[test]
fn policy_lets_admins_open_things_up_and_only_admins_write_rosters() {
    let lab = Lab::new();
    let (mut a, mut b, _c, _key) = three_devices(&lab);
    a.org_create("Acme", "alice").unwrap();
    b.sync(None).unwrap();
    assert!(b.share_create("docs").is_err());
    assert!(
        b.org_set_policy(OrgPolicy::default()).is_err(),
        "members cannot change the policy"
    );

    a.org_set_policy(OrgPolicy {
        members_may_share: true,
        members_may_add_devices: true,
        ..OrgPolicy::default()
    })
    .unwrap();
    b.sync(None).unwrap();
    assert!(b.org_summary().unwrap().policy.members_may_share);
    assert!(b.share_create("docs").is_ok());
    assert!(b.pairing_bundle().is_ok());
    assert!(
        b.add_storage(StorageSpec::LocalDir {
            name: "extra".into(),
            path: lab.root.join("extra"),
            cold: false,
            carrier: false,
            place: String::new(),
        })
        .is_err(),
        "storages are still admin-only"
    );
    assert!(matches!(
        a.org_log_entries().last().unwrap().event,
        OrgEvent::PolicyChanged { .. }
    ));

    // A roster written by B (not an admin) is ignored by A: fake it by
    // copying B's identity into a forged object is not possible without its
    // key; here B simply cannot publish one, and a stray object under the
    // roster prefix that is not signed by an admin changes nothing.
    let next = a.org_summary().unwrap().roster_seq + 1;
    let path = lab
        .root
        .join("storage")
        .join(format!("org/roster/{next:08}.json"));
    fs::write(&path, b"{\"format_version\":1,\"org_id\":\"x\",\"seq\":9,\"key_epoch\":0,\"issuer\":\"00000000000000000000000000000000\",\"body_hex\":\"\",\"sig_alg\":\"ed25519\",\"sig_hex\":\"\"}").unwrap();
    a.sync(None).unwrap();
    assert_eq!(a.org_summary().unwrap().roster_seq, next - 1);
    // The real admin's next roster is blocked by the stray object (same name).
    assert!(a.org_add_device("nobody", "x").is_err());
    fs::remove_file(&path).unwrap();
}

#[test]
fn the_root_key_appoints_and_dismisses_admins() {
    let lab = Lab::new();
    let (mut a, mut b, _c, _key) = three_devices(&lab);
    let created = a.org_create("Acme", "alice").unwrap();
    b.sync(None).unwrap();
    assert!(b.revoke_device("c", false).is_err());
    assert!(a.org_admin_add("b", "wrong words").is_err());
    assert!(
        a.org_admin_remove("hq", &created.root_words).is_err(),
        "the last admin stays"
    );
    a.org_admin_add("b", &created.root_words).unwrap();
    b.sync(None).unwrap();
    let sb = b.org_summary().unwrap();
    assert!(sb.this_device_admin);
    assert_eq!(sb.admins.len(), 2);
    assert_eq!(sb.manifest_seq, 2);
    // Now B can act as an admin, and A sees B's log entries.
    let r = b.revoke_device("c", false).unwrap();
    assert_eq!(r.key_epoch, 1);
    a.sync(None).unwrap();
    assert_eq!(a.key_epoch(), 1);
    assert!(a
        .org_log_entries()
        .iter()
        .any(|l| l.issuer_name == "b" && l.text.contains("removed c")));
    // And the root key can take the role back.
    b.org_admin_remove("hq", &created.root_words).unwrap();
    a.sync(None).unwrap();
    assert!(!a.org_summary().unwrap().this_device_admin);
    assert!(a.revoke_device("b", false).is_err());
}
