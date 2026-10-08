// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Two devices that are never online at the same time converge through one
//! shared storage. This is the first scenario of plan section 6.19 and of
//! section 8's blocking question on offline convergence.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for e in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if e.file_type().is_file() {
            let rel = e
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if rel.starts_with(".varsto") {
                continue;
            }
            out.insert(rel, fs::read(e.path()).unwrap());
        }
    }
    out
}

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s & 0xff) as u8
        })
        .collect()
}

struct Lab {
    _tmp: tempfile::TempDir,
    storage: StorageSpec,
    a_home: PathBuf,
    b_home: PathBuf,
    a_dir: PathBuf,
    b_dir: PathBuf,
}

fn lab() -> Lab {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().to_path_buf();
    Lab {
        storage: StorageSpec::LocalDir {
            name: "box".into(),
            path: root.join("storage"),
            cold: false,
            carrier: false,
        },
        a_home: root.join("a-home"),
        b_home: root.join("b-home"),
        a_dir: root.join("a-docs"),
        b_dir: root.join("b-docs"),
        _tmp: tmp,
    }
}

fn open(home: &Path) -> Engine {
    let mut e = Engine::open(home, PASS).unwrap();
    e.chunker = ChunkerParams::SMALL;
    e
}

#[test]
fn devices_never_online_together_converge() {
    let lab = lab();
    // Device A creates the vault, a storage and a folder with files, then pushes.
    let (mut a, vault_key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    fs::create_dir_all(lab.a_dir.join("sub")).unwrap();
    fs::write(lab.a_dir.join("hello.txt"), b"hello from a").unwrap();
    fs::write(lab.a_dir.join("sub/big.bin"), pseudo_random(150_000, 3)).unwrap();
    fs::write(lab.a_dir.join("copy.bin"), pseudo_random(150_000, 3)).unwrap(); // duplicate content
    let push = a.push("docs").unwrap();
    assert_eq!(push.files_changed, 3);
    assert!(push.chunks_uploaded > 1);
    assert_eq!(push.manifest_seq, Some(1));
    drop(a); // A goes offline.

    // Device B joins later through the storage only.
    let mut b = Engine::join(&lab.b_home, "phone", PASS, &vault_key, lab.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    let folders = b.folders();
    assert_eq!(
        folders.len(),
        1,
        "folder record must arrive through the storage"
    );
    b.attach_folder("docs", &lab.b_dir, false).unwrap();
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.files_updated, 3);
    assert_eq!(pull.conflicts, 0);
    assert!(pull.files_unavailable.is_empty());
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
    // Duplicate content was uploaded once: both files share every chunk.
    let dupes = b.dupes("docs").unwrap();
    assert_eq!(dupes.len(), 1);
    assert_eq!(
        dupes[0].paths,
        vec!["copy.bin".to_string(), "sub/big.bin".to_string()]
    );

    // B edits, deletes and adds, then pushes; B's pull verified A's chunks.
    fs::write(lab.b_dir.join("hello.txt"), b"hello from b").unwrap();
    fs::remove_file(lab.b_dir.join("copy.bin")).unwrap();
    fs::write(lab.b_dir.join("new.txt"), b"new on b").unwrap();
    let push = b.push("docs").unwrap();
    assert_eq!(push.files_changed, 3);
    let status = b.status().unwrap();
    let docs = &status.folders[0];
    assert_eq!(docs.files, 3);
    assert_eq!(docs.chunks_without_storage_copy, 0);
    assert!(
        docs.chunks_verified_elsewhere > 0,
        "B verified A's chunks when it fetched them"
    );
    assert_eq!(status.devices.len(), 2);
    drop(b);

    // A comes back alone and pulls.
    let mut a = open(&lab.a_home);
    let pull = a.pull("docs").unwrap();
    assert_eq!(pull.files_updated, 2);
    assert_eq!(pull.files_deleted, 1);
    assert_eq!(pull.conflicts, 0);
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
    assert_eq!(
        fs::read(lab.a_dir.join("hello.txt")).unwrap(),
        b"hello from b"
    );
    // The deleted file went to the trash, not into the void (F-025).
    let trash = walkdir::WalkDir::new(lab.a_home.join("trash"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count();
    assert_eq!(trash, 1);

    // fsck: every referenced chunk has a storage copy and verified status.
    let fsck = a.fsck(true).unwrap();
    assert!(fsck.chunks_missing.is_empty());
    assert!(fsck.objects_corrupt.is_empty());
    assert_eq!(fsck.claims_without_object, 0);
    assert!(fsck.forked_devices.is_empty());
    assert_eq!(fsck.chunks_referenced, fsck.chunks_with_storage_copy);
    let status = a.status().unwrap();
    assert!(status.forked_devices.is_empty());
    assert!(status.ledger_batches >= 4);
}

#[test]
fn concurrent_edits_keep_both_versions() {
    let lab = lab();
    let (mut a, vault_key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    fs::write(lab.a_dir.join("report.txt"), b"v1").unwrap();
    a.push("docs").unwrap();
    let mut b = Engine::join(&lab.b_home, "phone", PASS, &vault_key, lab.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &lab.b_dir, false).unwrap();
    b.pull("docs").unwrap();

    // Both edit offline.
    fs::write(lab.a_dir.join("report.txt"), b"edited on A").unwrap();
    fs::write(lab.b_dir.join("report.txt"), b"edited on B").unwrap();
    a.push("docs").unwrap();
    b.push("docs").unwrap();

    // Each pulls the other's manifest; both end with the same two files.
    let pa = a.pull("docs").unwrap();
    let pb = b.pull("docs").unwrap();
    assert_eq!(pa.conflicts, 1);
    assert_eq!(pb.conflicts, 1);
    a.push("docs").unwrap();
    b.push("docs").unwrap();
    a.pull("docs").unwrap();
    b.pull("docs").unwrap();
    let ta = tree(&lab.a_dir);
    let tb = tree(&lab.b_dir);
    assert_eq!(
        ta, tb,
        "both devices must hold the same files after a conflict"
    );
    assert_eq!(
        ta.len(),
        2,
        "winner plus one conflict copy: {:?}",
        ta.keys().collect::<Vec<_>>()
    );
    let mut contents: Vec<&[u8]> = ta.values().map(|v| v.as_slice()).collect();
    contents.sort();
    assert_eq!(
        contents,
        vec![b"edited on A".as_slice(), b"edited on B".as_slice()]
    );
    assert!(ta.keys().any(|k| k.contains(".conflict-")));
}

#[test]
fn restored_device_is_fenced() {
    let lab = lab();
    let (mut a, _key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    fs::write(lab.a_dir.join("one.txt"), b"one").unwrap();
    a.push("docs").unwrap();
    // Snapshot A's home (like a backup), then keep working.
    let snapshot = lab.a_home.with_file_name("a-home-backup");
    copy_dir(&lab.a_home, &snapshot);
    fs::write(lab.a_dir.join("two.txt"), b"two").unwrap();
    a.push("docs").unwrap();
    drop(a);
    // Restore the backup and try to continue: the mailbox already holds newer
    // batches of this device, so the restored copy must refuse to sign more.
    fs::remove_dir_all(&lab.a_home).unwrap();
    copy_dir(&snapshot, &lab.a_home);
    let mut restored = open(&lab.a_home);
    fs::write(lab.a_dir.join("three.txt"), b"three").unwrap();
    let pull = restored.pull("docs");
    let fenced = match pull {
        Ok(r) => !r.forked_devices.is_empty(),
        Err(_) => true,
    };
    assert!(fenced, "a restored device must be detected as forked");
    assert!(
        restored.push("docs").is_err(),
        "a forked device must not append to its ledger"
    );
}

fn copy_dir(from: &Path, to: &Path) {
    for e in walkdir::WalkDir::new(from)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let rel = e.path().strip_prefix(from).unwrap();
        let dest = to.join(rel);
        if e.file_type().is_dir() {
            fs::create_dir_all(&dest).unwrap();
        } else {
            fs::create_dir_all(dest.parent().unwrap()).unwrap();
            fs::copy(e.path(), &dest).unwrap();
        }
    }
}

#[test]
fn untrusted_replica_holds_copies_without_keys() {
    use varsto_core::replica::Replica;
    let lab = lab();
    let (mut a, _key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    fs::write(lab.a_dir.join("secret.txt"), b"top secret content").unwrap();
    fs::write(lab.a_dir.join("big.bin"), pseudo_random(60_000, 5)).unwrap();
    a.push("docs").unwrap();
    // User B gets only the replica token and the shared storage.
    let token = a.replica_token().unwrap();
    let b_home = lab.a_home.with_file_name("replica-home");
    let b_disk = lab.a_home.with_file_name("replica-disk");
    let target = StorageSpec::LocalDir {
        name: "b-disk".into(),
        path: b_disk.clone(),
        cold: false,
        carrier: false,
    };
    let mut r = Replica::init(&b_home, "userB", &token, lab.storage.clone(), target).unwrap();
    let rep = r.run_once().unwrap();
    assert!(rep.objects_copied > 3);
    assert_eq!(rep.objects_corrupt, 0);
    assert!(rep.chunks_verified >= 2);
    // Nothing on B's disk or in B's home is plaintext.
    for root in [&b_disk, &b_home] {
        for e in walkdir::WalkDir::new(root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let data = fs::read(e.path()).unwrap();
            assert!(
                !data.windows(10).any(|w| w == b"top secret"),
                "plaintext leaked into {}",
                e.path().display()
            );
        }
    }
    // The owner's bookkeeping now counts B's verified copies.
    a.pull("docs").unwrap();
    let st = a.status().unwrap();
    assert_eq!(st.replicas.len(), 1);
    assert_eq!(
        st.folders[0].chunks_verified_elsewhere,
        st.folders[0].chunks
    );
    // A second run copies nothing new.
    let rep2 = r.run_once().unwrap();
    assert_eq!(rep2.objects_copied, 0);
}

#[test]
fn shared_folder_between_two_users() {
    let lab = lab();
    let (mut a, _key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("project", &lab.a_dir).unwrap();
    a.add_folder("private", &lab.a_home.with_file_name("a-private"))
        .unwrap();
    fs::write(
        lab.a_home.with_file_name("a-private").join("mine.txt"),
        b"private to A",
    )
    .unwrap();
    fs::write(lab.a_dir.join("plan.txt"), b"shared plan").unwrap();
    a.sync(None).unwrap();
    let token = a.share_create("project").unwrap();
    // User C accepts with only the token and the shared storage.
    let mut c =
        Engine::accept_share(&lab.b_home, "c-laptop", PASS, &token, lab.storage.clone()).unwrap();
    c.chunker = ChunkerParams::SMALL;
    assert!(c.is_member());
    assert_eq!(c.folders().len(), 1, "a member sees only the shared folder");
    c.attach_folder("project", &lab.b_dir, false).unwrap();
    let pull = c.pull("project").unwrap();
    assert_eq!(pull.files_updated, 1);
    assert_eq!(
        fs::read(lab.b_dir.join("plan.txt")).unwrap(),
        b"shared plan"
    );
    fs::write(lab.b_dir.join("notes.txt"), b"from C").unwrap();
    c.push("project").unwrap();
    a.pull("project").unwrap();
    assert_eq!(fs::read(lab.a_dir.join("notes.txt")).unwrap(), b"from C");
    assert_eq!(a.status().unwrap().members.len(), 1);
    // C's bookkeeping converges with A's for the shared folder.
    let cs = c.status().unwrap();
    assert_eq!(cs.folders[0].chunks_without_storage_copy, 0);
    // The member cannot create folders or issue replica tokens.
    assert!(c.add_folder("x", &lab.b_home.with_file_name("x")).is_err());
    assert!(c.replica_token().is_err());
}

#[test]
fn carrier_disk_only_carries_what_is_missing_and_empties_itself() {
    let lab = lab();
    // Two devices with no shared hot storage, only a removable disk marked as carrier.
    let usb = StorageSpec::LocalDir {
        name: "usb".into(),
        path: lab.a_home.with_file_name("usb"),
        cold: false,
        carrier: true,
    };
    let (mut a, key) = Engine::init(&lab.a_home, "home-pc", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(usb.clone()).unwrap();
    a.add_folder("docs", &lab.a_dir).unwrap();
    fs::write(lab.a_dir.join("report.txt"), pseudo_random(50_000, 9)).unwrap();
    a.push("docs").unwrap();
    let usb_objects = |p: &Path| {
        walkdir::WalkDir::new(p.join("chunks"))
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .count()
    };
    assert!(
        usb_objects(&lab.a_home.with_file_name("usb")) > 0,
        "the carrier holds the chunks in transit"
    );
    // The disk travels to the second device.
    let mut b = Engine::join(&lab.b_home, "office-pc", PASS, &key, usb.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("docs", &lab.b_dir, false).unwrap();
    b.sync(None).unwrap();
    assert_eq!(tree(&lab.a_dir), tree(&lab.b_dir));
    // Back at the first device: it learns that the office holds the chunks and empties the disk.
    a.sync(None).unwrap();
    assert_eq!(
        usb_objects(&lab.a_home.with_file_name("usb")),
        0,
        "delivered chunks are pruned from the carrier"
    );
    // A new file at home gets onto the disk again; unchanged ones do not.
    fs::write(lab.a_dir.join("new.txt"), b"new").unwrap();
    let push = a.push("docs").unwrap();
    assert_eq!(push.chunks_uploaded, 1);
    assert!(
        a.fsck(false).unwrap().claims_without_object == 0,
        "pruned carrier objects are not reported as missing"
    );
}

#[test]
fn selective_sync_uses_placeholders() {
    let lab = lab();
    let (mut a, key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("photos", &lab.a_dir).unwrap();
    fs::write(lab.a_dir.join("one.jpg"), pseudo_random(30_000, 1)).unwrap();
    fs::write(lab.a_dir.join("two.jpg"), pseudo_random(30_000, 2)).unwrap();
    a.push("photos").unwrap();
    let mut b = Engine::join(&lab.b_home, "phone", PASS, &key, lab.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("photos", &lab.b_dir, true).unwrap();
    b.pull("photos").unwrap();
    assert!(lab.b_dir.join("one.jpg.varsto-placeholder").exists());
    assert!(!lab.b_dir.join("one.jpg").exists());
    let files = b.list_files("photos").unwrap();
    assert!(files.iter().all(|f| f.state == "placeholder"));
    // Fetch one file; the placeholder disappears and the file is kept.
    b.fetch_file("photos", "one.jpg").unwrap();
    assert_eq!(
        fs::read(lab.b_dir.join("one.jpg")).unwrap(),
        fs::read(lab.a_dir.join("one.jpg")).unwrap()
    );
    assert!(!lab.b_dir.join("one.jpg.varsto-placeholder").exists());
    // A placeholder is not a deletion: syncing B must not delete anything at A.
    b.sync(None).unwrap();
    a.sync(None).unwrap();
    assert!(lab.a_dir.join("two.jpg").exists());
    // Updates to a fetched (pinned) file are downloaded; updates to placeholders stay placeholders.
    fs::write(lab.a_dir.join("one.jpg"), pseudo_random(30_000, 11)).unwrap();
    fs::write(lab.a_dir.join("two.jpg"), pseudo_random(30_000, 12)).unwrap();
    a.push("photos").unwrap();
    b.pull("photos").unwrap();
    assert_eq!(
        fs::read(lab.b_dir.join("one.jpg")).unwrap(),
        fs::read(lab.a_dir.join("one.jpg")).unwrap()
    );
    assert!(!lab.b_dir.join("two.jpg").exists());
    // Free up space: the file becomes a placeholder again.
    b.free_file("photos", "one.jpg").unwrap();
    assert!(!lab.b_dir.join("one.jpg").exists());
    assert!(lab.b_dir.join("one.jpg.varsto-placeholder").exists());
    let st = b.status().unwrap();
    assert!(st.folders[0].selective);
    assert_eq!(st.folders[0].placeholders, 2);
}

#[test]
fn thumbnails_are_generated_once_and_shared_encrypted() {
    let lab = lab();
    let (mut a, key) = Engine::init(&lab.a_home, "laptop", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("photos", &lab.a_dir).unwrap();
    let img = image::RgbImage::from_fn(640, 480, |x, y| {
        image::Rgb([(x / 3) as u8, (y / 2) as u8, 120])
    });
    img.save(lab.a_dir.join("cat.png")).unwrap();
    fs::write(lab.a_dir.join("notes.txt"), b"no thumbnail for text").unwrap();
    let push = a.push("photos").unwrap();
    assert_eq!(push.thumbnails, 1);
    assert_eq!(a.push("photos").unwrap().thumbnails, 0, "generated once");
    // Storage holds the thumbnail encrypted: not a JPEG in clear text.
    let thumbs: Vec<_> = walkdir::WalkDir::new(lab.a_home.with_file_name("storage").join("thumbs"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();
    assert_eq!(thumbs.len(), 1);
    let blob = fs::read(thumbs[0].path()).unwrap();
    assert_ne!(
        &blob[..2],
        &[0xff, 0xd8],
        "stored thumbnail must be ciphertext"
    );
    // Another device shows the preview without fetching the picture itself (selective sync).
    let mut b = Engine::join(&lab.b_home, "phone", PASS, &key, lab.storage.clone()).unwrap();
    b.chunker = ChunkerParams::SMALL;
    b.attach_folder("photos", &lab.b_dir, true).unwrap();
    b.pull("photos").unwrap();
    assert!(!lab.b_dir.join("cat.png").exists());
    let t = b
        .thumbnail("photos", "cat.png")
        .unwrap()
        .expect("thumbnail available");
    assert_eq!(&t[..2], &[0xff, 0xd8], "decrypted thumbnail is a JPEG");
    let decoded = image::load_from_memory(&t).unwrap();
    assert!(decoded.width() <= 256);
    assert!(b.thumbnail("photos", "notes.txt").unwrap().is_none());
    let files = b.list_files("photos").unwrap();
    assert!(files.iter().any(|f| f.path == "cat.png" && f.media));
}

#[test]
fn sealed_share_token_opens_only_on_the_requesting_device() {
    use varsto_core::vault::{SealedShareToken, ShareRequest};
    let lab = lab();
    let (mut owner, _key) = Engine::init(&lab.a_home, "owner", PASS).unwrap();
    owner.chunker = ChunkerParams::SMALL;
    owner.add_storage(lab.storage.clone()).unwrap();
    owner.add_folder("docs", &lab.a_dir).unwrap();
    fs::write(lab.a_dir.join("plan.txt"), b"shared through a sealed token").unwrap();
    owner.push("docs").unwrap();

    // Recipient creates a request code before it has any vault.
    let code = ShareRequest::code_for(&lab.b_home).unwrap();
    assert!(code.starts_with("vsr1."));
    let plain = owner.share_create("docs").unwrap();
    let sealed = plain
        .seal(&ShareRequest::parse_code(&code).unwrap())
        .unwrap();
    let encoded = sealed.encode();
    assert!(SealedShareToken::is_sealed(&encoded));
    assert!(
        !encoded.contains(&plain.key_hex),
        "folder key must not appear in the sealed token"
    );

    // A different device cannot open it.
    let other = tempfile::tempdir().unwrap();
    ShareRequest::code_for(other.path()).unwrap();
    assert!(ShareRequest::open_token(other.path(), &encoded).is_err());

    // The requesting device opens it and syncs the folder.
    let opened = ShareRequest::open_token(&lab.b_home, &encoded).unwrap();
    assert_eq!(opened.key_hex, plain.key_hex);
    let mut member =
        Engine::accept_share(&lab.b_home, "friend", PASS, &opened, lab.storage.clone()).unwrap();
    ShareRequest::clear(&lab.b_home);
    member.chunker = ChunkerParams::SMALL;
    member.attach_folder("docs", &lab.b_dir, false).unwrap();
    member.pull("docs").unwrap();
    assert_eq!(
        fs::read(lab.b_dir.join("plan.txt")).unwrap(),
        b"shared through a sealed token"
    );
}
