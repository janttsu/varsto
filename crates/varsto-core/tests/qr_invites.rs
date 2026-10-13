// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! QR invitations (`docs/spec/alpha-0-format.md` section 43): a share driven
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

    // The recipient shows its request as a QR code; the owner scans it.
    let home = root.join("robin-home");
    let code = ShareRequest::code_for_named(&home, Some("Robin")).unwrap();
    let words = ShareRequest::fingerprint_for(&home).unwrap();
    let req_link = Link::from_text(&code).unwrap();
    let req_uri = req_link.to_uri().unwrap();
    let scanned = through_camera(std::slice::from_ref(&req_uri));
    assert_eq!(scanned, vec![req_uri.clone()]);
    // The owner sees the same six words for the scanned link.
    let seen = Engine::share_request_info(&scanned[0]).unwrap();
    assert_eq!(seen.fingerprint, words);
    assert_eq!(seen.name, "Robin");
    let (sealed, _) = a
        .share_create_sealed("project", &scanned[0], Some(&words))
        .unwrap();

    // The owner shows the token, split into parts; the recipient scans them
    // in any order.
    let token_link = Link::from_text(&sealed.encode()).unwrap();
    let parts = token_link.to_uris(0, qr::PART_CHARS).unwrap();
    assert!(parts.len() > 1);
    let mut read = through_camera(&parts);
    read.reverse();
    let got = qr::assemble(&read).unwrap();
    assert_eq!(got, token_link);
    // The single-code form opens just the same.
    let token_uri = token_link.to_uri().unwrap();
    let single = through_camera(std::slice::from_ref(&token_uri));
    let token = ShareRequest::open_token(&home, &single[0]).unwrap();
    assert_eq!(token.fingerprint, words);
    let mut m = Engine::accept_share(&home, "robin", PASS, &token, storage(&root)).unwrap();
    m.chunker = ChunkerParams::SMALL;
    ShareRequest::clear(&home);
    m.attach_folder("project", &root.join("robin-docs"), false)
        .unwrap();
    m.sync(None).unwrap();
    assert_eq!(
        fs::read(root.join("robin-docs/plan.txt")).unwrap(),
        b"shared by QR"
    );

    // Someone who photographs the token cannot open it on another device.
    let other = root.join("eve-home");
    ShareRequest::code_for_named(&other, Some("Eve")).unwrap();
    assert!(ShareRequest::open_token(&other, &token_uri).is_err());

    // A request link is not a token and the reverse.
    assert!(ShareRequest::open_token(&home, &req_uri).is_err());
    assert!(matches!(qr::parse(&parts[0]).unwrap(), Scanned::Part(_)));

    // Sizes recorded in the spec (section 43).
    let report = |what: &str, text: &str, link: &Link| {
        let uri = link.to_uri().unwrap();
        let img = qr::to_svg(&uri).unwrap();
        let parts = link.to_uris(0, qr::PART_CHARS).unwrap();
        let p = qr::to_svg(&parts[0]).unwrap();
        println!(
            "{what}: text {} chars, link {} chars, one code version {} ({} modules, ECC {}); as parts {} code(s), first version {} ({} modules, ECC {})",
            text.len(),
            uri.len(),
            img.version,
            img.modules,
            img.ecc,
            parts.len(),
            p.version,
            p.modules,
            p.ecc
        );
    };
    report("request code (name Robin)", &code, &req_link);
    report("sealed token vst2", &sealed.encode(), &token_link);
    let pair = Link::Pair {
        code: "123456789".into(),
        addresses: vec!["192.168.1.20:41234".into()],
    };
    report("pairing", "123-456-789", &pair);
}
