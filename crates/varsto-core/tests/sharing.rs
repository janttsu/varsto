// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Shared folders between users (`docs/spec/alpha-0-format.md` section 23):
//! the request fingerprint both sides compare, removing a member (a new
//! share epoch: the members that stay read on, the removed one reads
//! nothing new and its later changes are ignored), revoking a token that was
//! not accepted, sharing a folder that was re-keyed with the vault key, and
//! last-accessed times merged across devices.

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::crypto::{self, SecretKey};
use varsto_core::ids::ChunkId;
use varsto_core::manifest::Manifest;
use varsto_core::storage::StorageSpec;
use varsto_core::vault::{FolderKeys, ShareRequest, ShareToken};
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

/// An owner with a folder "project" holding one file.
fn owner(lab: &Lab) -> (Engine, String) {
    let (a, key) = Engine::init(&lab.home("a"), "laptop", PASS).unwrap();
    let mut a = small(a);
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("project", &lab.dir("a")).unwrap();
    fs::write(lab.dir("a").join("plan.txt"), b"before anyone left").unwrap();
    a.sync(None).unwrap();
    (a, key)
}

/// `who` asks for a share with a request code, the owner checks the
/// fingerprint and seals a token, `who` accepts it and syncs the folder.
fn invite(lab: &Lab, owner: &mut Engine, who: &str) -> Engine {
    let home = lab.home(who);
    let code = ShareRequest::code_for_named(&home, Some(who)).unwrap();
    let words = ShareRequest::fingerprint_for(&home).unwrap();
    let (sealed, req) = owner
        .share_create_sealed("project", &code, Some(&words))
        .unwrap();
    assert_eq!(req.fingerprint, words);
    let token = ShareRequest::open_token(&home, &sealed.encode()).unwrap();
    let mut m = small(Engine::accept_share(&home, who, PASS, &token, lab.storage.clone()).unwrap());
    ShareRequest::clear(&home);
    m.attach_folder("project", &lab.dir(who), false).unwrap();
    m.sync(None).unwrap();
    m
}

fn read(dir: &Path, f: &str) -> Option<Vec<u8>> {
    fs::read(dir.join(f)).ok()
}

#[test]
fn request_fingerprint_matches_on_both_sides() {
    let lab = Lab::new();
    let (mut a, _) = owner(&lab);
    let home = lab.home("robin");
    let code = ShareRequest::code_for_named(&home, Some("Robin")).unwrap();
    // The code carries the name; both sides derive the same six words.
    let mine = ShareRequest::fingerprint_for(&home).unwrap();
    let seen = Engine::share_request_info(&code).unwrap();
    assert_eq!(seen.fingerprint, mine);
    assert_eq!(seen.name, "Robin");
    assert_eq!(mine.split(' ').count(), 6);
    // Asking again keeps the key and the words.
    assert_eq!(ShareRequest::code_for(&home).unwrap(), code);

    // Someone swaps the name on the way: the owner sees other words.
    let (hex, _) = code.split_once(".Robin").unwrap();
    let swapped = format!("{hex}.Mallory");
    let other = Engine::share_request_info(&swapped).unwrap();
    assert_ne!(other.fingerprint, mine);
    // Confirming the words the requester read out refuses the swapped code.
    assert!(a
        .share_create_sealed("project", &swapped, Some(&mine))
        .is_err());
    // An owner who sealed to the swapped code anyway: the requester's device
    // sees that the confirmed words are not its own and refuses the token.
    let (bad, _) = a.share_create_sealed("project", &swapped, None).unwrap();
    let err = ShareRequest::open_token(&home, &bad.encode()).unwrap_err();
    assert!(format!("{err:#}").contains("fingerprint"), "{err:#}");

    // The right code: the token names the confirmed words, and they match.
    let (good, _) = a
        .share_create_sealed("project", &code, Some(&mine.to_uppercase()))
        .unwrap();
    let t = ShareRequest::open_token(&home, &good.encode()).unwrap();
    assert_eq!(t.fingerprint, mine);
    assert!(t.owners.contains(a.device_id()));
    // The owner lists the token as pending, with its words and name.
    let list = a.share_members("project").unwrap();
    let pending: Vec<_> = list
        .members
        .iter()
        .filter(|m| m.kind == "invite" && m.status == "pending")
        .collect();
    assert!(pending
        .iter()
        .any(|m| m.fingerprint == mine && m.name == "Robin"));
}

#[test]
fn removed_member_reads_nothing_new_and_the_others_read_on() {
    let lab = Lab::new();
    let (mut a, key) = owner(&lab);
    // A second device of the owner.
    let mut a2 =
        small(Engine::join(&lab.home("a2"), "desk", PASS, &key, lab.storage.clone()).unwrap());
    a2.attach_folder("project", &lab.dir("a2"), false).unwrap();
    a2.sync(None).unwrap();
    let mut b = invite(&lab, &mut a, "bea");
    let mut c = invite(&lab, &mut a, "cai");
    assert_eq!(
        read(&lab.dir("cai"), "plan.txt").as_deref(),
        Some(&b"before anyone left"[..])
    );
    fs::write(lab.dir("cai").join("from-c.txt"), b"c was here").unwrap();
    c.sync(None).unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(read(&lab.dir("bea"), "from-c.txt").is_some());

    let list = a.share_members("project").unwrap();
    let names: Vec<(String, String)> = list
        .members
        .iter()
        .map(|m| (m.name.clone(), m.status.clone()))
        .collect();
    assert!(
        names.contains(&("bea".into(), "active".into())),
        "{names:?}"
    );
    assert!(
        names.contains(&("cai".into(), "active".into())),
        "{names:?}"
    );
    assert!(
        list.members
            .iter()
            .any(|m| m.name == "cai" && !m.fingerprint.is_empty()),
        "a member is tied to the fingerprint the owner confirmed"
    );

    // A removes C.
    let r = a.share_revoke("project", "cai").unwrap();
    assert_eq!(r.removed, vec!["cai".to_string()]);
    assert!(r.grants_pending.is_empty(), "{r:?}");
    assert!(a.share_members("project").unwrap().share_epoch > 0);
    fs::write(lab.dir("a").join("after.txt"), b"written after C left").unwrap();
    a.sync(None).unwrap();

    // B (stays) reads the new file and keeps writing.
    b.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("bea"), "after.txt").as_deref(),
        Some(&b"written after C left"[..])
    );
    fs::write(lab.dir("bea").join("from-b.txt"), b"b after the change").unwrap();
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    assert!(read(&lab.dir("a"), "from-b.txt").is_some());

    // C keeps what it had, gets nothing new, and syncing does not fail.
    c.sync(None).unwrap();
    assert!(read(&lab.dir("cai"), "after.txt").is_none());
    assert!(read(&lab.dir("cai"), "from-b.txt").is_none());
    assert!(read(&lab.dir("cai"), "plan.txt").is_some());
    assert!(c.share_members("project").unwrap().access_lost);
    assert!(c.read_file("project", "after.txt").is_err());
    // Every key C holds opens nothing written after the change.
    let (crec, _) = c.folders().into_iter().next().unwrap();
    let ck =
        FolderKeys::from_folder_key(&crec.folder_id, SecretKey::from_hex(&crec.key_hex).unwrap())
            .unwrap();
    let vault = a.vault_id().clone();
    let secret = b"written after C left";
    let id = ChunkId::from_bytes(&crypto::keyed_hash(&ck.hash, secret));
    let (k, aad) = (
        ck.chunk_key(0, &id).unwrap(),
        ck.chunk_aad(&vault, &id, secret.len() as u64),
    );
    for e in walkdir::WalkDir::new(lab.root.join("storage").join("chunks"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        assert!(crypto::decrypt(&k, &aad, &fs::read(e.path()).unwrap()).is_err());
    }
    let mdir = lab
        .root
        .join("storage/manifests")
        .join(crec.folder_id.as_str())
        .join(a.device_id().as_str());
    let seq = fs::read_dir(&mdir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.path().file_stem()?.to_string_lossy().parse::<u64>().ok())
        .max()
        .unwrap();
    let blob = fs::read(mdir.join(format!("{seq:016}.enc"))).unwrap();
    assert!(Manifest::open(&blob, &vault, &crec.folder_id, a.device_id(), seq, &ck.meta).is_err());
    // Its later changes are ignored by everyone.
    fs::write(lab.dir("cai").join("late.txt"), b"after removal").unwrap();
    fs::write(lab.dir("cai").join("plan.txt"), b"overwritten by C").unwrap();
    c.sync(None).unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    for d in ["a", "bea"] {
        assert!(read(&lab.dir(d), "late.txt").is_none(), "{d}");
        assert_eq!(
            read(&lab.dir(d), "plan.txt").as_deref(),
            Some(&b"before anyone left"[..]),
            "{d}"
        );
    }

    // The owner's other device learns the new key and the removal.
    a2.sync(None).unwrap();
    assert!(read(&lab.dir("a2"), "after.txt").is_some());
    assert!(read(&lab.dir("a2"), "from-b.txt").is_some());
    assert!(read(&lab.dir("a2"), "late.txt").is_none());
    let l2 = a2.share_members("project").unwrap();
    assert!(l2
        .members
        .iter()
        .any(|m| m.name == "cai" && m.status == "removed"));
    // A2 writes under the new key too: B reads it.
    fs::write(lab.dir("a2").join("from-a2.txt"), b"desk").unwrap();
    a2.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(read(&lab.dir("bea"), "from-a2.txt").is_some());
    c.sync(None).unwrap();
    assert!(read(&lab.dir("cai"), "from-a2.txt").is_none());

    // C cannot come back as a new device with the key it kept.
    let old = ShareToken {
        vault_id: a.vault_id().clone(),
        folder_id: a.folders()[0].0.folder_id.clone(),
        key_hex: a.folders()[0].0.key_hex.clone(),
        name: "project".into(),
        epoch_keys: Default::default(),
        fingerprint: String::new(),
        owners: Vec::new(),
    };
    let mut c2 = small(
        Engine::accept_share(
            &lab.home("c2"),
            "cai-again",
            PASS,
            &old,
            lab.storage.clone(),
        )
        .unwrap(),
    );
    c2.attach_folder("project", &lab.dir("c2"), false).unwrap();
    c2.sync(None).unwrap();
    assert!(read(&lab.dir("c2"), "after.txt").is_none());
    fs::write(lab.dir("c2").join("sneak.txt"), b"new device of C").unwrap();
    c2.sync(None).unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(read(&lab.dir("a"), "sneak.txt").is_none());
    assert!(read(&lab.dir("bea"), "sneak.txt").is_none());
    assert!(!a
        .share_members("project")
        .unwrap()
        .members
        .iter()
        .any(|m| m.name == "cai-again"));

    // Sharing again after the change: a new member reads old and new files.
    let mut d = invite(&lab, &mut a, "dee");
    for f in [
        "plan.txt",
        "after.txt",
        "from-b.txt",
        "from-a2.txt",
        "from-c.txt",
    ] {
        assert!(read(&lab.dir("dee"), f).is_some(), "{f}");
    }
    fs::write(lab.dir("dee").join("from-d.txt"), b"d").unwrap();
    d.sync(None).unwrap();
    a.sync(None).unwrap();
    assert!(read(&lab.dir("a"), "from-d.txt").is_some());
    let _ = d;
}

#[test]
fn a_token_not_accepted_yet_can_be_revoked() {
    let lab = Lab::new();
    let (mut a, _) = owner(&lab);
    let mut b = invite(&lab, &mut a, "bea");
    let home = lab.home("eve");
    let code = ShareRequest::code_for_named(&home, Some("eve")).unwrap();
    let words = ShareRequest::fingerprint_for(&home).unwrap();
    let (sealed, _) = a
        .share_create_sealed("project", &code, Some(&words))
        .unwrap();
    // A second token, kept: it keeps working after the first is revoked.
    let fhome = lab.home("fay");
    let fcode = ShareRequest::code_for_named(&fhome, Some("fay")).unwrap();
    let (fsealed, _) = a.share_create_sealed("project", &fcode, None).unwrap();

    let r = a.share_revoke("project", &words).unwrap();
    assert!(r.removed.is_empty());
    assert_eq!(r.invites_revoked.len(), 1);
    let list = a.share_members("project").unwrap();
    assert!(list
        .members
        .iter()
        .any(|m| m.kind == "invite" && m.status == "revoked" && m.name == "eve"));
    fs::write(
        lab.dir("a").join("after.txt"),
        b"after the token was revoked",
    )
    .unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(read(&lab.dir("bea"), "after.txt").is_some());

    // The revoked token still opens (a key cannot be recalled) but brings
    // nothing written since (the owner's manifests are under the new key
    // now), and what that device writes is ignored.
    let t = ShareRequest::open_token(&home, &sealed.encode()).unwrap();
    let mut e = small(Engine::accept_share(&home, "eve", PASS, &t, lab.storage.clone()).unwrap());
    e.attach_folder("project", &lab.dir("eve"), false).unwrap();
    e.sync(None).unwrap();
    assert!(read(&lab.dir("eve"), "after.txt").is_none());
    assert!(e.share_members("project").unwrap().access_lost);
    fs::write(lab.dir("eve").join("eve.txt"), b"from a revoked token").unwrap();
    e.sync(None).unwrap();
    a.sync(None).unwrap();
    assert!(read(&lab.dir("a"), "eve.txt").is_none());

    // The token that was kept got the new key sealed to its request.
    let ft = ShareRequest::open_token(&fhome, &fsealed.encode()).unwrap();
    let mut f = small(Engine::accept_share(&fhome, "fay", PASS, &ft, lab.storage.clone()).unwrap());
    ShareRequest::clear(&fhome);
    f.attach_folder("project", &lab.dir("fay"), false).unwrap();
    f.sync(None).unwrap();
    assert!(read(&lab.dir("fay"), "after.txt").is_some());
    fs::write(lab.dir("fay").join("fay.txt"), b"kept token").unwrap();
    f.sync(None).unwrap();
    a.sync(None).unwrap();
    assert!(read(&lab.dir("a"), "fay.txt").is_some());
}

#[test]
fn removing_every_member_and_plain_tokens() {
    let lab = Lab::new();
    let (mut a, _) = owner(&lab);
    let mut b = invite(&lab, &mut a, "bea");
    let plain = a.share_create_plain("project").unwrap();
    let r = a.share_revoke("project", "all").unwrap();
    assert_eq!(r.removed, vec!["bea".to_string()]);
    assert_eq!(r.invites_revoked.len(), 1, "{r:?}");
    fs::write(lab.dir("a").join("after.txt"), b"nobody else").unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(read(&lab.dir("bea"), "after.txt").is_none());
    // A plain token cannot carry the new key.
    assert!(a.share_create_plain("project").is_err());
    assert!(plain.encode_plain().is_ok());
    // Nobody left to remove.
    assert!(a.share_revoke("project", "bea").is_err());
}

#[test]
fn a_folder_re_keyed_by_a_device_removal_can_be_shared() {
    let lab = Lab::new();
    let (mut a, key) = owner(&lab);
    let mut lost =
        small(Engine::join(&lab.home("lost"), "lost", PASS, &key, lab.storage.clone()).unwrap());
    lost.attach_folder("project", &lab.dir("lost"), false)
        .unwrap();
    lost.sync(None).unwrap();
    a.revoke_device("lost", false).unwrap();
    fs::write(lab.dir("a").join("rekeyed.txt"), b"under the new vault key").unwrap();
    a.sync(None).unwrap();
    // Sharing used to be refused here.
    let mut b = invite(&lab, &mut a, "bea");
    assert_eq!(
        read(&lab.dir("bea"), "rekeyed.txt").as_deref(),
        Some(&b"under the new vault key"[..])
    );
    assert!(read(&lab.dir("bea"), "plan.txt").is_some());
    // What is written from now on is under a share key the removed device
    // never had.
    fs::write(lab.dir("a").join("shared-later.txt"), b"later").unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(read(&lab.dir("bea"), "shared-later.txt").is_some());
    assert!(a.share_members("project").unwrap().share_epoch > 0);
}

#[test]
fn last_access_is_merged_across_devices() {
    let lab = Lab::new();
    let (mut a, key) = owner(&lab);
    // B keeps placeholders only: it never used plan.txt itself.
    let mut b =
        small(Engine::join(&lab.home("b"), "phone", PASS, &key, lab.storage.clone()).unwrap());
    b.attach_folder("project", &lab.dir("b"), true).unwrap();
    b.sync(None).unwrap();
    let used_on_a = a.list_files("project").unwrap()[0]
        .last_accessed_utc
        .unwrap();
    // A published its record with its first sync, B read it with its own.
    assert_eq!(a.exchange_access_records().unwrap().published, 0);
    let after = b.list_files("project").unwrap();
    assert_eq!(after[0].state, "placeholder");
    assert_eq!(after[0].last_accessed_utc, Some(used_on_a));
    // Nothing new: an exchange reads nothing.
    assert_eq!(b.exchange_access_records().unwrap().received, 0);

    // One record per device and folder: a new one replaces the old.
    a.read_file("project", "plan.txt").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    a.read_file("project", "plan.txt").unwrap();
    a.exchange_access_records().unwrap();
    let count = walkdir::WalkDir::new(lab.root.join("storage").join("vault/access"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count();
    assert_eq!(count, 1);
    b.exchange_access_records().unwrap();
    assert!(
        b.list_files("project").unwrap()[0]
            .last_accessed_utc
            .unwrap()
            >= used_on_a
    );
}
