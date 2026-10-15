# format2-records: work in progress (paused 2026-10-15)
1. Rebase onto origin/main 651a3fd (format2-blocks merged): done, conflicts resolved (spec 61 before 62, CHANGELOG, README, lib.rs, engine.rs).
2. record_shim.rs replaced by record::Records (signed envelope, kinds pack-index and tombstones, writers from registry and members; engine pack_records/pack_tombstone_key): done in the last commit, builds; 3 packs::tests fail (tombstone tests at packs.rs ~1496, 1572, 1632: check writer keys/scope in the test helper `records()` and PackStore reads), not yet investigated.
3. Then: full `cargo test --workspace --no-fail-fast -- --test-threads=2` (last full run before this rebase: 687 passed, 0 failed).
4. Then gates: fmt, clippy -D warnings, cargo audit, cargo deny check; remove this file, push, update PR #35 body (record_shim item done).
