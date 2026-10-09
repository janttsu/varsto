// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! A transferrer with a destination carries what that device lacks, even
//! when other devices already hold it, and empties as the destination
//! receives it. Transferrer and cold storage exclude each other.

use std::fs;
use std::path::Path;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn dir(name: &str, path: &Path, carrier: bool, cold: bool) -> StorageSpec {
    StorageSpec::LocalDir {
        name: name.into(),
        path: path.to_path_buf(),
        cold,
        carrier,
        place: String::new(),
    }
}

fn objects(path: &Path) -> usize {
    walkdir::WalkDir::new(path.join("chunks"))
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .count()
}

#[test]
fn transferrer_carries_what_its_destination_lacks() {
    let t = tempfile::tempdir().unwrap();
    let p = |n: &str| t.path().join(n);
    for d in ["nas", "usb", "a", "b", "c"] {
        fs::create_dir_all(p(&format!("dirs/{d}"))).unwrap();
    }
    let nas = dir("nas", &p("dirs/nas"), false, false);
    let (mut laptop, key) = Engine::init(&p("laptop"), "laptop", PASS).unwrap();
    laptop.add_storage(nas.clone()).unwrap();
    // Cold and transferrer at once is refused.
    assert!(laptop
        .add_storage(dir("both", &p("dirs/usb"), true, true))
        .unwrap_err()
        .to_string()
        .contains("not both"));
    laptop.add_folder("docs", &p("dirs/a")).unwrap();
    fs::write(p("dirs/a/one.txt"), b"first").unwrap();
    laptop.sync(None).unwrap();

    // The work PC uses the folder (it attached it once, online) ...
    let mut work = Engine::join(&p("work"), "work-pc", PASS, &key, nas.clone()).unwrap();
    work.attach_folder("docs", &p("dirs/c"), false).unwrap();
    work.sync(None).unwrap();
    // ... and the phone holds everything that comes next.
    let mut phone = Engine::join(&p("phone"), "phone", PASS, &key, nas.clone()).unwrap();
    phone.attach_folder("docs", &p("dirs/b"), false).unwrap();

    fs::write(p("dirs/a/two.bin"), vec![9u8; 60_000]).unwrap();
    laptop.sync(None).unwrap();
    phone.sync(None).unwrap();
    laptop.sync(None).unwrap();

    // Without a destination a transferrer takes nothing: the phone has it all.
    let usb = dir("usb", &p("dirs/usb"), true, false);
    laptop.add_storage(usb.clone()).unwrap();
    laptop.sync(None).unwrap();
    assert_eq!(objects(&p("dirs/usb")), 0);

    // For the work PC it carries what the work PC lacks.
    let names = laptop.set_carrier_for("usb", &["WORK-PC".into()]).unwrap();
    assert_eq!(names, vec!["work-pc".to_string()]);
    laptop.sync(None).unwrap();
    let carried = objects(&p("dirs/usb"));
    assert!(carried > 0, "the transferrer carries the new blocks");
    assert!(laptop.status().unwrap().carrier_for["usb"] == vec!["work-pc".to_string()]);

    // The disk is plugged into the work PC: the files arrive and the disk
    // empties, both on the work PC and when the laptop next sees it.
    work.add_storage(usb).unwrap();
    work.sync(None).unwrap();
    assert_eq!(fs::read(p("dirs/c/two.bin")).unwrap(), vec![9u8; 60_000]);
    laptop.sync(None).unwrap();
    assert_eq!(
        objects(&p("dirs/usb")),
        0,
        "emptied once the work PC holds the blocks"
    );
    assert!(
        laptop.set_carrier_for("nas", &["work-pc".into()]).is_err(),
        "only transferrers"
    );
    assert!(laptop.set_carrier_for("usb", &["nobody".into()]).is_err());
}
