# Format 2 records and keys: work in progress
- Done (committed, fully tested): format 2 design + version bump; SignedRecord envelope for every record, ledger-announced acceptance, legacy keys removed.
- Done in this WIP commit (targeted tests pass, clippy/fmt/audit/deny clean; full suite last seen with only 2 CLI tests failing, fixed since by pulling grants before attach): folder keys as grants with request/approve/deny, own-device roles, re-key after revocation; pairing --folders, org approve --folders; recovery key escrow, join --recovery-words; spec section 61 and corrections, CHANGELOG, README, docs/recovery.md, lab scenarios folder-approval and format2-recovery; rustls 0.23.46.
- Not done: removal of plain/vst1 share tokens and token expiry (O8); signed participants list in folder records; lab scenarios not run.
- Next: run the full workspace tests, split this WIP commit into items 3-6 if wanted, rebase on origin/main, remove this file, mark PR #35 ready.
