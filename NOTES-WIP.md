# format2-blocks: work in progress
- Done: nonce from packed bytes (item 1), zstd 3 + probe (item 2), keyed chunker + size tiers (item 3), packs for every block with ledger places, encrypted indexes/tombstones, GC, per-pack verify, S3 multipart, pools/replicas/P2P adapted (item 4, WIP), spec section 62 + CHANGELOG/README (item 5).
- Just fixed: readers now fetch from packs the storage listing has not shown yet (cross-device pull was failing); changes test passes again.
- Not done: full test suite after that fix (last run 77 failures, most from the listing bug; pool, repair, scrub, strongroom, two_devices tests may still need helper/expectation updates); gates (fmt, clippy, `cargo update -p rustls --precise 0.23.46`, audit, deny); lab not run.
- Next: rerun `cargo test --workspace`, fix remaining tests (tests/common uses packs::debug_registry), run gates, rebase on main, mark PR #36 ready.
