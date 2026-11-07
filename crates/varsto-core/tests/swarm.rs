// SPDX-License-Identifier: PolyForm-Shield-1.0.0
//! Readers help each other: a device that pulled a folder serves the
//! blocks it wrote to another device pulling the same folder right away,
//! before its next snapshot (`p2p::FreshPieces`), so the second one does
//! not need the writer for them.

mod common;

use common::p2p::{meet, publish, Serving};
use std::fs;
use varsto_core::chunking::ChunkerParams;
use varsto_core::storage::StorageSpec;
use varsto_core::Engine;

const PASS: &str = "correct horse battery staple";

#[test]
fn a_reader_serves_the_blocks_it_just_pulled_to_another_reader() {
    // The serving cache of re-encrypted objects is one per process: here
    // it would let B answer with what the writer encrypted. Off, so B
    // serves only what it holds.
    std::env::set_var("VARSTO_P2P_CACHE_MB", "0");
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let storage = StorageSpec::LocalDir {
        name: "box".into(),
        path: root.join("storage"),
        cold: false,
        carrier: false,
        place: String::new(),
        min_free: None,
    };
    // The writer: a few small files and one of several blocks.
    let (mut a, key) = Engine::init(&root.join("a-home"), "writer", PASS).unwrap();
    a.chunker = ChunkerParams::SMALL;
    a.add_storage(storage.clone()).unwrap();
    a.add_folder("docs", &root.join("a-docs")).unwrap();
    let big: Vec<u8> = (0..300_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    fs::write(root.join("a-docs/big.bin"), &big).unwrap();
    for i in 0..5 {
        fs::write(
            root.join(format!("a-docs/small-{i}.txt")),
            format!("small file {i}\n").repeat(50 + i),
        )
        .unwrap();
    }
    a.push("docs").unwrap();
    let join = |who: &str, a: &mut Engine| {
        let mut e = common::join_approved(
            &root.join(format!("{who}-home")),
            who,
            PASS,
            &key,
            storage.clone(),
            a,
        );
        e.chunker = ChunkerParams::SMALL;
        e.attach_folder("docs", &root.join(format!("{who}-docs")), false)
            .unwrap();
        e
    };
    let mut b = join("reader-b", &mut a);
    let mut c = join("reader-c", &mut a);
    // Only peers hold the blocks from now on.
    common::lose_all_objects(&root.join("storage"));

    // The writer and reader B serve, as the service runs them: B's
    // snapshot is built before its pull, so it holds none of the files.
    let serving_a = Serving::start(&mut a);
    let serving_b = Serving::start(&mut b);
    publish(&c, 9);
    serving_a.refresh(&mut a);
    serving_b.refresh(&mut b);
    b.set_snapshot_sink(Some(serving_b.sink()));
    meet(&mut b);
    meet(&mut c);

    let rep_b = b.pull("docs").unwrap();
    assert!(rep_b.files_unavailable.is_empty(), "{rep_b:?}");
    assert!(rep_b.chunks_from_peers >= 2);
    assert!(b.fresh_pieces() > 0);

    // The writer goes away before C pulls: every block has to come from B.
    drop(serving_a);
    let rep_c = c.pull("docs").unwrap();
    assert!(rep_c.files_unavailable.is_empty(), "{rep_c:?}");
    assert_eq!(rep_c.chunks_from_peers, rep_b.chunks_from_peers);
    assert_eq!(fs::read(root.join("reader-c-docs/big.bin")).unwrap(), big);
    for i in 0..5 {
        assert_eq!(
            fs::read_to_string(root.join(format!("reader-c-docs/small-{i}.txt"))).unwrap(),
            format!("small file {i}\n").repeat(50 + i)
        );
    }
    // B's next snapshot covers the files; the fresh set is emptied.
    serving_b.refresh(&mut b);
    assert_eq!(b.fresh_pieces(), 0);
}
