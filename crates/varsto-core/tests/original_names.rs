// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! File names are kept as they are (spec: "Paths" and "Local names"):
//! names with `:`, `\`, `?`, control characters, trailing dots, Windows
//! device names, emoji and combining characters travel between devices
//! unchanged; a device whose filesystem does not take a name writes it
//! under a mapped local name and reads it back without seeing a change.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use varsto_core::chunking::ChunkerParams;
use varsto_core::names::LocalRules;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

/// Every name a Linux filesystem takes that Windows does not, and some
/// that only look unusual.
const NAMES: &[&str] = &[
    "12:30.jpg",
    "back\\slash.txt",
    "what?.txt",
    "star*.txt",
    "say \"hi\".txt",
    "<tag>.txt",
    "pipe|pipe.txt",
    "trailing dot.",
    "trailing space ",
    "CON.txt",
    "nul",
    "bell\u{7}.txt",
    "😀 emoji.txt",
    "cafe\u{301}.txt",
    "caf\u{e9}.txt",
    "a:b/c?.txt",
    "-rf",
];

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
                .to_str()
                .unwrap()
                .to_string();
            if rel.starts_with(".varsto") {
                continue;
            }
            out.insert(rel, fs::read(e.path()).unwrap());
        }
    }
    out
}

struct Lab {
    _tmp: tempfile::TempDir,
    storage: StorageSpec,
    root: PathBuf,
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

    fn dir(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    /// Device A with folder `docs` holding `names`, pushed; device B
    /// joined (with `rules` for its filesystem) and attached, not pulled.
    fn pair(&self, names: &[&str], rules: Option<LocalRules>) -> (Engine, Engine) {
        let (mut a, key) = Engine::init(&self.dir("a-home"), "linux", PASS).unwrap();
        a.chunker = ChunkerParams::SMALL;
        a.add_storage(self.storage.clone()).unwrap();
        let a_dir = self.dir("a-docs");
        a.add_folder("docs", &a_dir).unwrap();
        for (i, n) in names.iter().enumerate() {
            let p = a_dir.join(n);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, format!("content {i} of {n}")).unwrap();
            // One modification time for all: a pull takes the newest files
            // first, so equal times keep the order by path the checks
            // below expect.
            fs::File::options()
                .write(true)
                .open(&p)
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000))
                .unwrap();
        }
        let push = a.push("docs").unwrap();
        assert_eq!(push.files_changed, names.len() as u64);
        let mut b = Engine::join(
            &self.dir("b-home"),
            "other",
            PASS,
            &key,
            self.storage.clone(),
        )
        .unwrap();
        b.chunker = ChunkerParams::SMALL;
        b.set_local_rules(rules);
        b.attach_folder("docs", &self.dir("b-docs"), false).unwrap();
        (a, b)
    }
}

fn listed(e: &Engine) -> Vec<String> {
    let mut v: Vec<String> = e
        .list_files("docs")
        .unwrap()
        .into_iter()
        .map(|f| f.path)
        .collect();
    v.sort();
    v
}

fn sorted(names: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = names.iter().map(|s| s.to_string()).collect();
    v.sort();
    v
}

#[test]
fn original_names_round_trip_between_linux_devices() {
    let lab = Lab::new();
    let (mut a, mut b) = lab.pair(NAMES, Some(LocalRules::POSIX));
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.files_updated, NAMES.len() as u64);
    assert!(
        pull.files_unavailable.is_empty(),
        "{:?}",
        pull.files_unavailable
    );
    assert!(pull.renamed_locally.is_empty());
    // Byte for byte the same names (no normalisation either: both forms
    // of "café" are there) and contents.
    assert_eq!(tree(&lab.dir("a-docs")), tree(&lab.dir("b-docs")));
    assert_eq!(listed(&b), sorted(NAMES));
    // Nothing looks changed afterwards.
    assert_eq!(b.push("docs").unwrap().files_changed, 0);

    // B changes and deletes files with such names; A follows.
    fs::write(lab.dir("b-docs").join("12:30.jpg"), b"edited on b").unwrap();
    fs::remove_file(lab.dir("b-docs").join("CON.txt")).unwrap();
    fs::write(lab.dir("b-docs").join("new\ttab:.txt"), b"new").unwrap();
    assert_eq!(b.push("docs").unwrap().files_changed, 3);
    let pull = a.pull("docs").unwrap();
    assert_eq!((pull.files_updated, pull.files_deleted), (2, 1));
    assert_eq!(tree(&lab.dir("a-docs")), tree(&lab.dir("b-docs")));
    assert_eq!(a.push("docs").unwrap().files_changed, 0);
    // Moving a file to such a name works too.
    a.move_file("docs", "-rf", "x:y/z?.txt").unwrap();
    b.pull("docs").unwrap();
    assert!(lab.dir("b-docs").join("x:y/z?.txt").is_file());
    assert!(!lab.dir("b-docs").join("-rf").exists());
}

const WINDOWS: LocalRules = LocalRules {
    windows_names: true,
    case_insensitive: true,
};

#[test]
fn windows_names_are_mapped_and_read_back_unchanged() {
    let lab = Lab::new();
    let (mut a, mut b) = lab.pair(NAMES, Some(WINDOWS));
    let b_dir = lab.dir("b-docs");
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.files_updated, NAMES.len() as u64);
    assert!(
        pull.files_unavailable.is_empty(),
        "{:?}",
        pull.files_unavailable
    );
    // Written with the private-use mapping.
    let on_b = tree(&b_dir);
    for local in [
        "12\u{f03a}30.jpg",
        "back\u{f05c}slash.txt",
        "what\u{f03f}.txt",
        "trailing dot\u{f02e}",
        "trailing space\u{f020}",
        "CO\u{f04e}.txt",
        "nu\u{f06c}",
        "bell\u{f007}.txt",
        "a\u{f03a}b/c\u{f03f}.txt",
        "😀 emoji.txt",
    ] {
        assert!(
            on_b.contains_key(local),
            "{local:?} not in {:?}",
            on_b.keys()
        );
    }
    for local in on_b.keys() {
        assert!(
            !local
                .chars()
                .any(|c| matches!(c, ':' | '\\' | '?' | '*' | '"' | '<' | '>' | '|')),
            "{local:?}"
        );
    }
    // The vault paths are the original ones, and a scan sees no change.
    assert_eq!(listed(&b), sorted(NAMES));
    assert_eq!(b.push("docs").unwrap().files_changed, 0);

    // A changes a mapped file: B updates it in place, without a copy.
    fs::write(lab.dir("a-docs").join("12:30.jpg"), b"edited on a").unwrap();
    a.push("docs").unwrap();
    b.pull("docs").unwrap();
    assert_eq!(
        fs::read(b_dir.join("12\u{f03a}30.jpg")).unwrap(),
        b"edited on a"
    );
    assert_eq!(tree(&b_dir).len(), NAMES.len());

    // A person on Windows makes a file whose name holds an escape: it is
    // stored under the decoded name. Deleting a mapped file deletes the
    // original one.
    fs::write(b_dir.join("made\u{f03f}.txt"), b"on windows").unwrap();
    fs::remove_file(b_dir.join("CO\u{f04e}.txt")).unwrap();
    assert_eq!(b.push("docs").unwrap().files_changed, 2);
    let pull = a.pull("docs").unwrap();
    assert_eq!((pull.files_updated, pull.files_deleted), (1, 1));
    assert_eq!(
        fs::read(lab.dir("a-docs").join("made?.txt")).unwrap(),
        b"on windows"
    );
    assert!(!lab.dir("a-docs").join("CON.txt").exists());
    assert_eq!(b.push("docs").unwrap().files_changed, 0);

    // The interface's paths are vault paths; the disk path is the local one.
    let entry = b
        .list_files("docs")
        .unwrap()
        .into_iter()
        .find(|f| f.path == "12:30.jpg")
        .unwrap();
    assert_eq!(entry.state, "local");
    assert_eq!(entry.disk, b_dir.join("12\u{f03a}30.jpg"));
    assert_eq!(b.read_file("docs", "12:30.jpg").unwrap(), b"edited on a");
    let (_, path) = b.locate_path(&b_dir.join("12\u{f03a}30.jpg")).unwrap();
    assert_eq!(path, "12:30.jpg");
}

#[test]
fn case_collisions_get_a_local_name_and_lose_nothing() {
    let lab = Lab::new();
    let names = ["Photo.JPG", "photo.jpg", "Dir/x.txt", "dir/y.txt"];
    let insensitive = LocalRules {
        windows_names: false,
        case_insensitive: true,
    };
    let (mut a, mut b) = lab.pair(&names, Some(insensitive));
    let pull = b.pull("docs").unwrap();
    assert_eq!(pull.files_updated, 4);
    assert_eq!(
        pull.renamed_locally,
        vec!["photo.jpg -> photo (2).jpg".to_string()]
    );
    let on_b: Vec<String> = tree(&lab.dir("b-docs")).into_keys().collect();
    assert_eq!(
        on_b,
        ["Dir/x.txt", "Dir/y.txt", "Photo.JPG", "photo (2).jpg"]
    );
    assert_eq!(listed(&b), sorted(&names));
    assert_eq!(b.push("docs").unwrap().files_changed, 0);
    // Editing the renamed copy edits the vault file it stands for.
    fs::write(lab.dir("b-docs").join("photo (2).jpg"), b"edited").unwrap();
    fs::write(lab.dir("b-docs").join("Dir/y.txt"), b"edited y").unwrap();
    assert_eq!(b.push("docs").unwrap().files_changed, 2);
    a.pull("docs").unwrap();
    assert_eq!(
        fs::read(lab.dir("a-docs").join("photo.jpg")).unwrap(),
        b"edited"
    );
    assert_eq!(
        fs::read(lab.dir("a-docs").join("dir/y.txt")).unwrap(),
        b"edited y"
    );
    assert_eq!(
        fs::read(lab.dir("a-docs").join("Photo.JPG")).unwrap(),
        b"content 0 of Photo.JPG"
    );
}

#[test]
fn paths_that_leave_the_folder_are_still_refused() {
    let lab = Lab::new();
    let (mut a, _) = Engine::init(&lab.dir("a-home"), "linux", PASS).unwrap();
    a.add_storage(lab.storage.clone()).unwrap();
    a.add_folder("docs", &lab.dir("a-docs")).unwrap();
    for bad in ["../evil", "/abs", "a/../../x", "a\0b", "", "a//b", "."] {
        assert!(a.write_file("docs", bad, b"x").is_err(), "{bad:?}");
        assert!(a.mkdir("docs", bad).is_err(), "{bad:?}");
    }
    assert!(!lab.dir("evil").exists());
    assert!(a.write_file("docs", "ok:name?.txt", b"x").is_ok());
    assert!(lab.dir("a-docs").join("ok:name?.txt").is_file());
}
