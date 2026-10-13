// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Read-only members of shared folders: a viewer reads; its own client keeps
//! its changes aside instead of publishing them; what a modified client
//! publishes anyway is refused by the owner's devices and the editors; an
//! editor writes; the owner changes roles and the change takes effect; a
//! member cannot give itself a role.

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::engine::ManifestPolicy;
use varsto_core::share::ShareRole;
use varsto_core::storage::StorageSpec;
use varsto_core::vault::ShareRequest;
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

fn owner(lab: &Lab) -> Engine {
    let (a, _) = Engine::init(&lab.home("a"), "laptop", PASS).unwrap();
    let mut a = small(a);
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("project", &lab.dir("a")).unwrap();
    fs::write(lab.dir("a").join("plan.txt"), b"the plan").unwrap();
    a.sync(None).unwrap();
    a
}

fn invite(lab: &Lab, owner: &mut Engine, who: &str, role: ShareRole) -> Engine {
    let home = lab.home(who);
    let code = ShareRequest::code_for_named(&home, Some(who)).unwrap();
    let words = ShareRequest::fingerprint_for(&home).unwrap();
    let (sealed, _) = owner
        .share_create_sealed_as("project", &code, Some(&words), role)
        .unwrap();
    let token = ShareRequest::open_token(&home, &sealed.encode()).unwrap();
    assert_eq!(token.role, role);
    let mut m = small(Engine::accept_share(&home, who, PASS, &token, lab.storage.clone()).unwrap());
    ShareRequest::clear(&home);
    m.attach_folder("project", &lab.dir(who), false).unwrap();
    m.sync(None).unwrap();
    m
}

fn read(dir: &Path, f: &str) -> Option<Vec<u8>> {
    fs::read(dir.join(f)).ok()
}

fn role_of(e: &Engine, name: &str) -> String {
    e.share_members("project")
        .unwrap()
        .members
        .into_iter()
        .find(|m| m.name == name && m.kind == "member")
        .map(|m| m.role)
        .unwrap_or_default()
}

/// Owner, an editor and a viewer; everyone synced twice so that role
/// records and join proofs went around.
fn three(lab: &Lab) -> (Engine, Engine, Engine) {
    let mut a = owner(lab);
    let mut b = invite(lab, &mut a, "bea", ShareRole::Editor);
    let mut v = invite(lab, &mut a, "vic", ShareRole::Viewer);
    for _ in 0..2 {
        a.sync(None).unwrap();
        b.sync(None).unwrap();
        v.sync(None).unwrap();
    }
    (a, b, v)
}

#[test]
fn a_viewer_reads_and_its_own_changes_stay_here() {
    let lab = Lab::new();
    let (mut a, mut b, mut v) = three(&lab);
    assert_eq!(
        read(&lab.dir("vic"), "plan.txt").as_deref(),
        Some(&b"the plan"[..])
    );
    // Everyone sees the roles; the owner listed the members by their join proofs.
    assert_eq!(role_of(&a, "vic"), "viewer");
    assert_eq!(role_of(&a, "bea"), "editor");
    assert_eq!(role_of(&b, "vic"), "viewer");
    assert_eq!(v.share_members("project").unwrap().this_role, "viewer");
    assert_eq!(b.share_members("project").unwrap().this_role, "editor");
    let st = v.status().unwrap();
    assert!(st.folders[0].read_only);
    #[cfg(unix)]
    assert!(fs::metadata(lab.dir("vic").join("plan.txt"))
        .unwrap()
        .permissions()
        .readonly());

    // The viewer changes a file, adds one and deletes nothing: none of it is
    // published; the changes go aside and the shared version comes back.
    let plan = lab.dir("vic").join("plan.txt");
    let mut p = fs::metadata(&plan).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    p.set_readonly(false);
    fs::set_permissions(&plan, p).unwrap();
    fs::write(&plan, b"changed by the viewer").unwrap();
    fs::write(lab.dir("vic").join("new.txt"), b"a new file").unwrap();
    let r = v.sync(None).unwrap();
    let (pull, push) = &r[0];
    assert!(push.read_only);
    let kept: Vec<&String> = pull
        .kept_aside
        .iter()
        .chain(push.kept_aside.iter())
        .collect();
    assert!(kept.iter().any(|p| *p == "plan.txt"), "{kept:?}");
    assert!(kept.iter().any(|p| *p == "new.txt"), "{kept:?}");
    v.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("vic"), "plan.txt").as_deref(),
        Some(&b"the plan"[..])
    );
    assert!(read(&lab.dir("vic"), "new.txt").is_none());
    let aside = lab
        .home("vic")
        .join(varsto_core::engine::KEPT_ASIDE_DIR)
        .join("project");
    let names: Vec<String> = fs::read_dir(&aside)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(names.iter().any(|n| n.starts_with("new.txt.")), "{names:?}");
    assert!(
        names.iter().any(|n| n.starts_with("plan.txt.")),
        "{names:?}"
    );
    // Deleting is undone as well.
    fs::remove_file(&plan).unwrap();
    v.sync(None).unwrap();
    v.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("vic"), "plan.txt").as_deref(),
        Some(&b"the plan"[..])
    );
    // Writes through the interface are refused.
    assert!(v.write_file("project", "api.txt", b"x").is_err());
    assert!(v.mkdir("project", "sub").is_err());

    a.sync(None).unwrap();
    b.sync(None).unwrap();
    for d in ["a", "bea"] {
        assert!(read(&lab.dir(d), "new.txt").is_none(), "{d}");
        assert_eq!(
            read(&lab.dir(d), "plan.txt").as_deref(),
            Some(&b"the plan"[..]),
            "{d}"
        );
    }

    // The editor writes; everyone, the viewer too, gets it.
    fs::write(lab.dir("bea").join("from-b.txt"), b"by the editor").unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    v.sync(None).unwrap();
    assert!(read(&lab.dir("a"), "from-b.txt").is_some());
    assert!(read(&lab.dir("vic"), "from-b.txt").is_some());

    // A member cannot change roles, its own included.
    assert!(v
        .share_set_role("project", "vic", ShareRole::Editor)
        .is_err());
    assert!(b
        .share_set_role("project", "vic", ShareRole::Editor)
        .is_err());
}

#[test]
fn what_a_modified_viewer_client_publishes_is_refused() {
    let lab = Lab::new();
    let (mut a, mut b, mut v) = three(&lab);
    // A client that ignores its role: it scans, uploads and publishes.
    v.disable_read_only_guard();
    let plan = lab.dir("vic").join("plan.txt");
    let mut p = fs::metadata(&plan).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    p.set_readonly(false);
    fs::set_permissions(&plan, p).unwrap();
    fs::write(&plan, b"overwritten by a modified client").unwrap();
    fs::write(lab.dir("vic").join("evil.txt"), b"planted").unwrap();
    let r = v.sync(None).unwrap();
    assert!(r[0].1.manifest_seq.is_some(), "it did publish");

    // The owner's device does not count the viewer's ledger batches, so it
    // learns of the manifest only from a full listing: list in full now.
    a.set_manifest_policy(ManifestPolicy {
        sweep_secs: 0,
        prune: true,
    });
    let r = a.sync(None).unwrap();
    assert!(
        r[0].0.writes_refused.iter().any(|n| n == "vic"),
        "{:?}",
        r[0].0
    );
    b.sync(None).unwrap();
    for d in ["a", "bea"] {
        assert!(read(&lab.dir(d), "evil.txt").is_none(), "{d}");
        assert_eq!(
            read(&lab.dir(d), "plan.txt").as_deref(),
            Some(&b"the plan"[..]),
            "{d}"
        );
    }
    let st = a.list_files("project").unwrap();
    assert!(st.iter().all(|f| f.path != "evil.txt"));
}

#[test]
fn role_changes_take_effect_and_only_the_owner_makes_them() {
    let lab = Lab::new();
    let (mut a, mut b, mut v) = three(&lab);
    // The owner lets the viewer write.
    let r = a
        .share_set_role("project", "vic", ShareRole::Editor)
        .unwrap();
    assert_eq!(r.role, "editor");
    v.sync(None).unwrap();
    assert_eq!(v.share_members("project").unwrap().this_role, "editor");
    assert!(!v.status().unwrap().folders[0].read_only);
    fs::write(lab.dir("vic").join("now-allowed.txt"), b"editor now").unwrap();
    v.sync(None).unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(read(&lab.dir("a"), "now-allowed.txt").is_some());
    assert!(read(&lab.dir("bea"), "now-allowed.txt").is_some());

    // And takes it away again: what it wrote stays, new changes do not go.
    a.share_set_role("project", "vic", ShareRole::Viewer)
        .unwrap();
    assert_eq!(role_of(&a, "vic"), "viewer");
    v.sync(None).unwrap();
    b.sync(None).unwrap();
    assert_eq!(v.share_members("project").unwrap().this_role, "viewer");
    fs::write(lab.dir("vic").join("not-any-more.txt"), b"viewer again").unwrap();
    let r = v.sync(None).unwrap();
    assert!(r[0].1.read_only);
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(read(&lab.dir("a"), "not-any-more.txt").is_none());
    assert!(read(&lab.dir("a"), "now-allowed.txt").is_some());
    // A fresh device of the owner reads the older change too (it was made
    // while the member was an editor).
    let key = a.export_vault_key().unwrap();
    let mut a2 =
        small(Engine::join(&lab.home("a2"), "desk", PASS, &key, lab.storage.clone()).unwrap());
    a2.attach_folder("project", &lab.dir("a2"), false).unwrap();
    a2.sync(None).unwrap();
    a2.sync(None).unwrap();
    assert!(read(&lab.dir("a2"), "now-allowed.txt").is_some());
    assert!(read(&lab.dir("a2"), "not-any-more.txt").is_none());

    // The editor's role is unchanged throughout.
    fs::write(lab.dir("bea").join("still.txt"), b"editor").unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    assert!(read(&lab.dir("a"), "still.txt").is_some());

    // A role record not signed by the owner's devices is ignored.
    let folder = a.folders()[0].0.folder_id.clone();
    let forged = lab
        .root
        .join("storage/vault/share-roles")
        .join(folder.as_str())
        .join(format!("{:010}-{}.json", 999, v.device_id()));
    fs::create_dir_all(forged.parent().unwrap()).unwrap();
    fs::write(&forged, br#"{"format_version":1,"folder":"00","seq":999}"#).unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert_eq!(role_of(&a, "vic"), "viewer");
    assert_eq!(role_of(&b, "vic"), "viewer");
}

#[test]
fn plain_tokens_are_refused_once_a_folder_has_viewers() {
    let lab = Lab::new();
    let mut a = owner(&lab);
    assert!(a.share_create_plain("project").is_ok());
    let _v = invite(&lab, &mut a, "vic", ShareRole::Viewer);
    let err = a.share_create_plain("project").unwrap_err();
    assert!(format!("{err:#}").contains("request code"), "{err:#}");
    // The pending token lists its role.
    let list = a.share_members("project").unwrap();
    assert!(list.roles_in_use);
}
