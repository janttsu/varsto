// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Organizations: which device platforms may belong. An approval for a
//! platform the policy does not allow is refused; a device already in the
//! organization is locked out when its platform stops being allowed (the
//! others ignore what it writes, its own client refuses to open the vault)
//! and comes back once allowed again; policies and device details that are
//! not signed by the right device are ignored.

mod common;

use std::fs;
use std::path::PathBuf;
use varsto_core::chunking::ChunkerParams;
use varsto_core::org::{OrgPolicy, OrgRequest};
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

/// A (Linux, the administrator), B (Windows) and C (Linux) in one
/// organization; everyone synced so that their signed details went around.
fn org(lab: &Lab) -> (Engine, Engine, Engine) {
    let (a, key) = Engine::init(&lab.home("a"), "hq", PASS).unwrap();
    let mut a = small(a);
    a.set_platform_for_tests("linux", None);
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.dir("a")).unwrap();
    fs::write(lab.dir("a").join("one.txt"), b"first").unwrap();
    a.sync(None).unwrap();
    let mut others = Vec::new();
    for (who, platform) in [("b", "windows"), ("c", "linux")] {
        let mut e = small(common::join_approved(
            &lab.home(who),
            who,
            PASS,
            &key,
            lab.storage.clone(),
            &mut a,
        ));
        e.set_platform_for_tests(platform, None);
        e.attach_folder("docs", &lab.dir(who), false).unwrap();
        e.sync(None).unwrap();
        others.push(e);
    }
    a.org_create("Acme", "alice").unwrap();
    for _ in 0..2 {
        a.sync(None).unwrap();
        for e in others.iter_mut() {
            e.sync(None).unwrap();
        }
    }
    let c = others.pop().unwrap();
    let b = others.pop().unwrap();
    (a, b, c)
}

fn only(platforms: &[&str]) -> OrgPolicy {
    OrgPolicy {
        allowed_platforms: platforms.iter().map(|p| p.to_string()).collect(),
        ..OrgPolicy::default()
    }
}

#[test]
fn approval_refuses_platforms_the_policy_does_not_allow() {
    let lab = Lab::new();
    let (mut a, _b, _c) = org(&lab);
    // Unknown names and a policy that would lock out the admin itself are refused.
    assert!(a.org_set_policy(only(&["beos"])).is_err());
    let err = a.org_set_policy(only(&["windows"])).unwrap_err();
    assert!(
        format!("{err:#}").contains("lock out this device"),
        "{err:#}"
    );
    a.org_set_policy(only(&["Linux", "macOS"])).unwrap();
    let s = a.org_summary().unwrap();
    assert_eq!(s.policy.allowed_platforms, vec!["linux", "macos"]);

    // The request code names the platform, and the fingerprint covers it.
    let code = OrgRequest::code_for_platform(&lab.home("d"), Some("d-phone"), "android").unwrap();
    assert!(code.starts_with("vor2."));
    let info = OrgRequest::parse(&code).unwrap();
    assert_eq!(info.platform, "android");
    let swapped = code.replace(".android.", ".linux.");
    assert_ne!(
        OrgRequest::parse(&swapped).unwrap().fingerprint,
        info.fingerprint,
        "a platform changed on the way changes the words"
    );
    let err = a.org_approve(&code, "dana", None).unwrap_err();
    assert!(
        format!("{err:#}").contains("does not allow Android"),
        "{err:#}"
    );
    // A code without a platform (an older version's) is refused too.
    let parts: Vec<&str> = code.trim_start_matches("vor2.").splitn(4, '.').collect();
    let old = format!("vor1.{}.{}.{}", parts[0], parts[1], parts[3]);
    let err = a.org_approve(&old, "dana", None).unwrap_err();
    assert!(format!("{err:#}").contains("platform"), "{err:#}");

    // A Linux device is approved, and the roster records its platform.
    let code = OrgRequest::code_for_platform(&lab.home("e"), Some("e-laptop"), "linux").unwrap();
    let approved = a.org_approve(&code, "erin", None).unwrap();
    let (e, _, _) = Engine::org_join(&lab.home("e"), "e-laptop", PASS, &approved.token).unwrap();
    let mut e = small(e);
    e.set_platform_for_tests("linux", None);
    common::approve_all(&mut a, &mut e);
    e.attach_folder("docs", &lab.dir("e"), false).unwrap();
    e.sync(None).unwrap();
    assert!(lab.dir("e").join("one.txt").exists());
    let s = a.org_summary().unwrap();
    let dev = s
        .users
        .iter()
        .flat_map(|u| u.devices.iter())
        .find(|d| d.name == "e-laptop")
        .unwrap();
    assert_eq!(dev.platform, "linux");
    assert!(dev.refused.is_none());
}

#[test]
fn a_device_on_a_platform_no_longer_allowed_is_locked_out_until_allowed_again() {
    let lab = Lab::new();
    let (mut a, mut b, mut c) = org(&lab);
    // B writes while allowed; then the policy changes before A reads it.
    fs::write(lab.dir("b").join("from-b.txt"), b"written on windows").unwrap();
    b.sync(None).unwrap();
    a.org_set_policy(only(&["linux", "macos"])).unwrap();
    let s = a.org_summary().unwrap();
    let bdev = s
        .users
        .iter()
        .flat_map(|u| u.devices.iter())
        .find(|d| d.name == "b")
        .unwrap();
    assert_eq!(bdev.platform, "windows");
    assert!(bdev.refused.as_deref().unwrap().contains("Windows"));
    // The others do not take what B writes.
    a.sync(None).unwrap();
    c.sync(None).unwrap();
    assert!(!lab.dir("a").join("from-b.txt").exists());
    assert!(!lab.dir("c").join("from-b.txt").exists());

    // B's own client sees the signed policy and refuses to sync or open files.
    let err = b.sync(None).unwrap_err();
    assert!(
        format!("{err:#}").contains("does not allow Windows devices"),
        "{err:#}"
    );
    let st = b.status().unwrap();
    assert!(st.org.unwrap().blocked.unwrap().contains("Windows"));
    assert!(b.read_file("docs", "one.txt").is_err());
    assert!(b.org_summary().unwrap().this_device_blocked.is_some());

    // No new keys while it is locked out: a removal seals the new key to C only.
    let r = a.revoke_device("c", false).unwrap();
    assert!(!r.keys_sent_to.contains(&"b".to_string()), "{r:?}");

    // Allowed again: A takes B's file, B gets the new key and syncs.
    a.org_set_policy(OrgPolicy::default()).unwrap();
    a.sync(None).unwrap();
    assert!(lab.dir("a").join("from-b.txt").exists());
    b.sync(None).unwrap();
    assert_eq!(b.key_epoch(), a.key_epoch());
    assert!(b.status().unwrap().org.unwrap().blocked.is_none());
    fs::write(lab.dir("a").join("after.txt"), b"after the new key").unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(lab.dir("b").join("after.txt").exists());
}

#[test]
fn unsigned_or_forged_policies_and_details_are_ignored() {
    let lab = Lab::new();
    let (mut a, mut b, mut c) = org(&lab);
    a.org_set_policy(only(&["linux"])).unwrap();
    b.sync(None).unwrap_err();
    c.sync(None).unwrap();
    // A member is not an administrator: the honest client refuses outright.
    assert!(c.org_set_policy(OrgPolicy::default()).is_err());
    // A modified client publishes a roster allowing every platform anyway,
    // signed by itself: nobody else takes it.
    c.org_publish_roster_unchecked(OrgPolicy::default())
        .unwrap();
    a.sync(None).unwrap();
    assert_eq!(
        a.org_summary().unwrap().policy.allowed_platforms,
        vec!["linux"]
    );
    // B (locked out) does not take it either.
    assert!(b.sync(None).is_err());
    // Device details in B's name, signed by C (anyone with the vault key can
    // seal them), do not make B a Linux device.
    let bid = b.device_id().clone();
    c.forge_device_details_for_tests(&bid, "linux").unwrap();
    a.sync(None).unwrap();
    let s = a.org_summary().unwrap();
    let bdev = s
        .users
        .iter()
        .flat_map(|u| u.devices.iter())
        .find(|d| d.name == "b")
        .unwrap();
    assert_eq!(bdev.platform, "windows");
    assert!(bdev.refused.is_some());
    // The minimum version works the same way, from the signed details.
    let mut p = only(&[]);
    p.min_app_version = "999.0.0".into();
    assert!(
        a.org_set_policy(p).is_err(),
        "it would lock out the administrator itself"
    );
}
