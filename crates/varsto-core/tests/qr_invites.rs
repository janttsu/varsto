// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! QR invitations (`docs/spec/alpha-0-format.md` section 51): a share driven
//! end to end through `varsto://` links that went through QR codes (encoded,
//! rendered, decoded again), with the sizes the spec records.

use std::fs;
use std::path::PathBuf;
use varsto_core::chunking::ChunkerParams;
use varsto_core::qr::{self, Link, Scanned};
use varsto_core::storage::StorageSpec;
use varsto_core::vault::ShareRequest;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

fn storage(root: &std::path::Path) -> StorageSpec {
    StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    }
}

/// Show `uris` as QR codes and read them back, as a camera would.
fn through_camera(uris: &[String]) -> Vec<String> {
    uris.iter()
        .map(|u| {
            let (side, px) = qr::to_luma(u, 2).unwrap();
            let mut got = qr::decode_luma(side, side, &px).unwrap();
            assert_eq!(got.len(), 1);
            got.remove(0)
        })
        .collect()
}

#[test]
fn a_share_through_qr_links() {
    let tmp = tempfile::tempdir().unwrap();
    let root: PathBuf = tmp.path().to_path_buf();
    let (a, _) = Engine::init(&root.join("a-home"), "laptop", PASS).unwrap();
    let mut a = a;
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage(&root)).unwrap();
    a.add_folder("project", &root.join("a-docs")).unwrap();
    fs::write(root.join("a-docs/plan.txt"), b"shared by QR").unwrap();
    a.sync(None).unwrap();

    // The recipient shows its request as QR codes (it carries two hybrid
    // public keys, more than one code holds); the owner scans them in any
    // order.
    let home = root.join("robin-home");
    let code = ShareRequest::code_for_named(&home, Some("Robin")).unwrap();
    let words = ShareRequest::fingerprint_for(&home).unwrap();
    let req_link = Link::from_text(&code).unwrap();
    let parts = req_link.to_uris(qr::PART_CHARS, qr::PART_CHARS).unwrap();
    assert!(parts.len() > 1);
    let mut read = through_camera(&parts);
    read.reverse();
    let got = qr::assemble(&read).unwrap();
    assert_eq!(got, req_link);
    assert!(matches!(qr::parse(&parts[0]).unwrap(), Scanned::Part(_)));
    // The owner sees the same six words for the scanned link.
    let seen = Engine::share_request_info(&got.text()).unwrap();
    assert_eq!(seen.fingerprint, words);
    assert_eq!(seen.name, "Robin");
    let added = a
        .share_add(
            "project",
            &got.text(),
            Some(&words),
            varsto_core::share::ShareRole::Editor,
        )
        .unwrap();

    // The recipient accepts from the storage, comparing the owner's words.
    let mut m = Engine::accept_share(
        &home,
        "robin",
        PASS,
        Some(&added.owner_fingerprint),
        storage(&root),
    )
    .unwrap();
    m.chunker = ChunkerParams::SMALL;
    m.attach_folder("project", &root.join("robin-docs"), false)
        .unwrap();
    m.sync(None).unwrap();
    assert_eq!(
        fs::read(root.join("robin-docs/plan.txt")).unwrap(),
        b"shared by QR"
    );

    // Share tokens are gone: their old text forms are refused with a reason.
    let err = Link::from_text("vst2.AAAA").unwrap_err();
    assert!(format!("{err:#}").contains("tokens are gone"), "{err:#}");

    // Sizes recorded in the spec (section 51).
    let report = |what: &str, text: &str, link: &Link| {
        let uri = link.to_uri().unwrap();
        let parts = link.to_uris(0, qr::PART_CHARS).unwrap();
        let p = qr::to_svg(&parts[0]).unwrap();
        println!(
            "{what}: text {} chars, link {} chars; as parts {} code(s), first version {} ({} modules, ECC {})",
            text.len(),
            uri.len(),
            parts.len(),
            p.version,
            p.modules,
            p.ecc
        );
    };
    report("request code (name Robin)", &code, &req_link);
    let pair = Link::Pair {
        code: "123456789".into(),
        addresses: vec!["192.168.1.20:41234".into()],
        rendezvous: Some([0x5a; 16]),
        rendezvous_url: None,
    };
    report("pairing", "123-456-789", &pair);
}
