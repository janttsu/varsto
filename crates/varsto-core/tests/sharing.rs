// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Shared folders between people on storage format 3
//! (`docs/spec/format-3-design.md` section 6; `alpha-0-format.md` section
//! 77.6): the request fingerprint both sides compare, the owner's words the
//! member compares, removing a member (a new folder epoch: the members that
//! stay read on, the removed one reads nothing new and its later changes
//! are ignored), removing a member before it accepted, sharing a folder
//! that a device removal re-keyed, last-accessed times merged across
//! devices, and a member's batches confined to its folder.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::crypto::{self, SecretKey};
use varsto_core::ids::ChunkId;
use varsto_core::record::{KeyId, RecordKeys, SignedRecord};
use varsto_core::share::ShareRole;
use varsto_core::storage::StorageSpec;
use varsto_core::vault::{FolderKeys, ShareRequest};
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

/// `who` asks with a request code, the owner checks the fingerprint and
/// adds it; `who` accepts with the owner device's words and syncs.
fn invite(lab: &Lab, owner: &mut Engine, who: &str) -> Engine {
    let home = lab.home(who);
    let code = ShareRequest::code_for_named(&home, Some(who)).unwrap();
    let words = ShareRequest::fingerprint_for(&home).unwrap();
    let added = owner
        .share_add("project", &code, Some(&words), ShareRole::Editor)
        .unwrap();
    assert_eq!(added.fingerprint, words);
    let mut m = small(
        Engine::accept_share(
            &home,
            who,
            PASS,
            Some(&added.owner_fingerprint),
            lab.storage.clone(),
        )
        .unwrap(),
    );
    assert!(
        !home.join(ShareRequest::FILE).exists(),
        "the request is used up"
    );
    m.attach_folder("project", &lab.dir(who), false).unwrap();
    m.sync(None).unwrap();
    m
}

fn read(dir: &Path, f: &str) -> Option<Vec<u8>> {
    fs::read(dir.join(f)).ok()
}

/// Opens every body with one key.
struct Only(SecretKey);
impl RecordKeys for Only {
    fn symmetric(&self, _: &KeyId) -> Option<SecretKey> {
        Some(self.0.clone())
    }
}

#[test]
fn request_fingerprint_matches_on_both_sides() {
    let lab = Lab::new();
    let (mut a, _) = owner(&lab);
    let home = lab.home("robin");
    let code = ShareRequest::code_for_named(&home, Some("Robin")).unwrap();
    // The code carries the keys and the name; both sides derive the same six words.
    let mine = ShareRequest::fingerprint_for(&home).unwrap();
    let seen = Engine::share_request_info(&code).unwrap();
    assert_eq!(seen.fingerprint, mine);
    assert_eq!(seen.name, "Robin");
    assert_eq!(mine.split(' ').count(), 6);
    // Asking again keeps the keys and the words.
    assert_eq!(ShareRequest::code_for(&home).unwrap(), code);

    // Someone swaps the name on the way: the owner sees other words.
    let (keys, _) = code.rsplit_once(".Robin").unwrap();
    let swapped = format!("{keys}.Mallory");
    let other = Engine::share_request_info(&swapped).unwrap();
    assert_ne!(other.fingerprint, mine);
    // Confirming the words the requester read out refuses the swapped code.
    assert!(a
        .share_add("project", &swapped, Some(&mine), ShareRole::Editor)
        .is_err());

    // The right code: the owner adds the member, and tells its own words.
    let added = a
        .share_add(
            "project",
            &code,
            Some(&mine.to_uppercase()),
            ShareRole::Editor,
        )
        .unwrap();
    assert_eq!(added.fingerprint, mine);
    assert_eq!(added.owner_fingerprint, a.f3_own_fingerprint().unwrap());
    // The member compares them: other words find nothing to accept.
    let Err(err) = Engine::accept_share(
        &home,
        "robin",
        PASS,
        Some("abandon ability able about above absent"),
        lab.storage.clone(),
    ) else {
        panic!("accepted with the wrong words");
    };
    assert!(format!("{err:#}").contains("no owner device"), "{err:#}");
    assert!(!home.join("vault.json").exists());
    // The owner lists the member with its words and name.
    let list = a.share_members("project").unwrap();
    assert!(list
        .members
        .iter()
        .any(|m| m.kind == "member" && m.fingerprint == mine && m.name == "Robin"));
    // Without the words, the only offer is taken.
    let offers = Engine::share_offers(&home, &lab.storage, None).unwrap();
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].owner_fingerprint, added.owner_fingerprint);
    let mut m =
        small(Engine::accept_share(&home, "robin", PASS, None, lab.storage.clone()).unwrap());
    m.attach_folder("project", &lab.dir("robin"), false)
        .unwrap();
    m.sync(None).unwrap();
    assert!(read(&lab.dir("robin"), "plan.txt").is_some());
}

#[test]
fn removed_member_reads_nothing_new_and_the_others_read_on() {
    let lab = Lab::new();
    let (mut a, key) = owner(&lab);
    // A second device of the owner.
    let mut a2 = small(common::join_approved(
        &lab.home("a2"),
        "desk",
        PASS,
        &key,
        lab.storage.clone(),
        &mut a,
    ));
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
    let store = lab.root.join("storage");
    let objs = common::object_names(&store);
    assert!(!objs.is_empty());
    for n in &objs {
        let ct = common::read_object(&store, n).unwrap();
        assert!(
            varsto_core::chunk_seal::open_chunk(&ck, &vault, &id, 0, secret.len() as u64, &ct)
                .is_err()
        );
    }
    let mdir = lab
        .root
        .join("storage/manifests")
        .join(crec.folder_id.as_str())
        .join(a.device_id().as_str());
    let newest = fs::read_dir(&mdir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with("-0000.rec"))
        .max()
        .unwrap();
    let m = SignedRecord::decode(&fs::read(newest).unwrap()).unwrap();
    assert_eq!(m.key_id, format!("meta:{}@1", crec.folder_id.as_str()));
    assert!(m.open_part(&Only(ck.meta.clone())).is_err());
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

    // C cannot come back as a new device: nothing is shared with a new
    // request, and the owner's words do not change that.
    let c2 = lab.home("c2");
    ShareRequest::code_for_named(&c2, Some("cai-again")).unwrap();
    let owner_words = a.f3_own_fingerprint().unwrap();
    assert!(Engine::accept_share(
        &c2,
        "cai-again",
        PASS,
        Some(&owner_words),
        lab.storage.clone()
    )
    .is_err());

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
}

#[test]
fn a_member_removed_before_it_accepted_gets_nothing_new() {
    let lab = Lab::new();
    let (mut a, _) = owner(&lab);
    let mut b = invite(&lab, &mut a, "bea");
    let home = lab.home("eve");
    let code = ShareRequest::code_for_named(&home, Some("eve")).unwrap();
    let words = ShareRequest::fingerprint_for(&home).unwrap();
    let added = a
        .share_add("project", &code, Some(&words), ShareRole::Editor)
        .unwrap();
    // A second one, kept: it keeps working after the first is removed.
    let fhome = lab.home("fay");
    let fcode = ShareRequest::code_for_named(&fhome, Some("fay")).unwrap();
    a.share_add("project", &fcode, None, ShareRole::Editor)
        .unwrap();

    let r = a.share_revoke("project", &words).unwrap();
    assert_eq!(r.removed, vec!["eve".to_string()]);
    let list = a.share_members("project").unwrap();
    assert!(list
        .members
        .iter()
        .any(|m| m.kind == "member" && m.status == "removed" && m.name == "eve"));
    fs::write(
        lab.dir("a").join("after.txt"),
        b"after the member was removed",
    )
    .unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(read(&lab.dir("bea"), "after.txt").is_some());

    // The removed member's grant still opens (a key cannot be recalled)
    // but brings nothing written since, and what that device writes is
    // ignored.
    let mut e = small(
        Engine::accept_share(
            &home,
            "eve",
            PASS,
            Some(&added.owner_fingerprint),
            lab.storage.clone(),
        )
        .unwrap(),
    );
    e.attach_folder("project", &lab.dir("eve"), false).unwrap();
    e.sync(None).unwrap();
    assert!(read(&lab.dir("eve"), "plan.txt").is_some());
    assert!(read(&lab.dir("eve"), "after.txt").is_none());
    assert!(e.share_members("project").unwrap().access_lost);
    fs::write(lab.dir("eve").join("eve.txt"), b"from a removed member").unwrap();
    e.sync(None).unwrap();
    a.sync(None).unwrap();
    assert!(read(&lab.dir("a"), "eve.txt").is_none());

    // The member that was kept got the new key in a new grant.
    let mut f =
        small(Engine::accept_share(&fhome, "fay", PASS, None, lab.storage.clone()).unwrap());
    f.attach_folder("project", &lab.dir("fay"), false).unwrap();
    f.sync(None).unwrap();
    assert!(read(&lab.dir("fay"), "after.txt").is_some());
    fs::write(lab.dir("fay").join("fay.txt"), b"kept member").unwrap();
    f.sync(None).unwrap();
    a.sync(None).unwrap();
    assert!(read(&lab.dir("a"), "fay.txt").is_some());
}

#[test]
fn removing_every_member() {
    let lab = Lab::new();
    let (mut a, _) = owner(&lab);
    let mut b = invite(&lab, &mut a, "bea");
    let r = a.share_revoke("project", "all").unwrap();
    assert_eq!(r.removed, vec!["bea".to_string()]);
    fs::write(lab.dir("a").join("after.txt"), b"nobody else").unwrap();
    a.sync(None).unwrap();
    b.sync(None).unwrap();
    assert!(read(&lab.dir("bea"), "after.txt").is_none());
    // Nobody left to remove.
    assert!(a.share_revoke("project", "bea").is_err());
}

#[test]
fn a_folder_re_keyed_by_a_device_removal_can_be_shared() {
    let lab = Lab::new();
    let (mut a, key) = owner(&lab);
    let mut lost = small(common::join_approved(
        &lab.home("lost"),
        "lost",
        PASS,
        &key,
        lab.storage.clone(),
        &mut a,
    ));
    lost.attach_folder("project", &lab.dir("lost"), false)
        .unwrap();
    lost.sync(None).unwrap();
    a.revoke_device("lost", false).unwrap();
    fs::write(
        lab.dir("a").join("rekeyed.txt"),
        b"under the new folder key",
    )
    .unwrap();
    a.sync(None).unwrap();
    let mut b = invite(&lab, &mut a, "bea");
    assert_eq!(
        read(&lab.dir("bea"), "rekeyed.txt").as_deref(),
        Some(&b"under the new folder key"[..])
    );
    assert!(read(&lab.dir("bea"), "plan.txt").is_some());
    // What is written from now on is under a folder key the removed device
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
    let mut b = small(common::join_approved(
        &lab.home("b"),
        "phone",
        PASS,
        &key,
        lab.storage.clone(),
        &mut a,
    ));
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

    // A new record of a device replaces its older one.
    a.read_file("project", "plan.txt").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    a.read_file("project", "plan.txt").unwrap();
    a.exchange_access_records().unwrap();
    b.exchange_access_records().unwrap();
    assert!(
        b.list_files("project").unwrap()[0]
            .last_accessed_utc
            .unwrap()
            >= used_on_a
    );
}

/// The id of a folder of `e` by name.
fn folder_id(e: &Engine, name: &str) -> varsto_core::ids::FolderId {
    let st = e.status().unwrap();
    let f = st.folders.iter().find(|f| f.name == name).unwrap();
    varsto_core::ids::FolderId::from_hex(&f.folder_id).unwrap()
}

/// A member's ledger batches count only inside its shared folder: a
/// modified client that retires the owner's storage, claims a pack for the
/// owner's private folder and announces a manifest of it (and plants it on
/// the storage) changes nothing for the owner, whose pull of that folder
/// does not stop at the planted manifest.
#[test]
fn a_members_batch_cannot_reach_outside_its_folder() {
    use varsto_core::ledger3::events::{
        Announcement, Event, FolderAdded, PackStored, StorageRetired,
    };
    let lab = Lab::new();
    let (mut a, _) = owner(&lab);
    a.add_folder("private", &lab.dir("a-private")).unwrap();
    fs::write(lab.dir("a-private").join("secret.txt"), b"mine alone").unwrap();
    a.sync(None).unwrap();
    let mut m = invite(&lab, &mut a, "robin");
    let private = varsto_core::record::id16(&folder_id(&a, "private")).unwrap();
    let refused_before = a.ledger_view3().unwrap().events_refused;
    let clock = a.status().unwrap().lamport;
    m.seal_batch3_unchecked(
        vec![
            Event::StorageRetired(StorageRetired {
                storage: "box".into(),
            }),
            Event::RecordPublished(Announcement {
                kind: varsto_core::record::Kind::Manifest.code(),
                scope: private,
                seq: 7,
                base: 7,
                parts: 1,
                body_hash: [7; 32],
                size: 1,
            }),
            Event::FolderAdded(FolderAdded { folder: private }),
            Event::PackStored(PackStored {
                storage: "box".into(),
                pack: [9; 32],
                class: 0,
                folder: private,
                map_seq: 1,
            }),
        ],
        clock + 1000,
    )
    .unwrap();
    let planted = lab
        .root
        .join("storage/manifests")
        .join(hex::encode(private))
        .join(m.device_id().as_str())
        .join("0000000000000007-0000.rec");
    fs::create_dir_all(planted.parent().unwrap()).unwrap();
    fs::write(&planted, b"junk that opens with no key").unwrap();

    fs::write(lab.dir("a-private").join("later.txt"), b"still syncing").unwrap();
    a.sync(None)
        .expect("the owner's sync does not stop at the planted manifest");
    let st = a.status().unwrap();
    for f in &st.folders {
        assert_eq!(
            f.chunks_without_storage_copy, 0,
            "{}: the member retired the owner's storage",
            f.name
        );
    }
    assert!(a.ledger_view3().unwrap().events_refused >= refused_before + 4);
    // The member's own folder still takes its legitimate events.
    fs::write(lab.dir("robin").join("note.txt"), b"from robin").unwrap();
    m.sync(None).unwrap();
    a.sync(None).unwrap();
    assert_eq!(
        read(&lab.dir("a"), "note.txt").as_deref(),
        Some(&b"from robin"[..])
    );
}

/// A name under the folder's epochs that no owner signed (junk anyone with
/// the storage credentials can write) does not make a member believe it
/// was removed, which would silence its errors.
#[test]
fn junk_folder_epoch_does_not_cut_a_member_off() {
    let lab = Lab::new();
    let (mut a, _) = owner(&lab);
    let mut m = invite(&lab, &mut a, "robin");
    let project = folder_id(&a, "project");
    let junk = lab
        .root
        .join("storage/vault/folder-epochs")
        .join(project.as_str())
        .join("0000000000000005-0000.rec");
    fs::create_dir_all(junk.parent().unwrap()).unwrap();
    fs::write(&junk, b"junk").unwrap();
    m.sync(None).unwrap();
    assert!(!m.share_members("project").unwrap().access_lost);
    // The owner still shares with it.
    fs::write(lab.dir("a").join("later.txt"), b"for robin").unwrap();
    a.sync(None).unwrap();
    m.sync(None).unwrap();
    assert!(read(&lab.dir("robin"), "later.txt").is_some());
}
