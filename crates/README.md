# crates

Rust workspace.

| Crate | Purpose |
|---|---|
| `varsto-core` | chunking, cryptography, storage backends, ledger, manifests and the sync engine |
| `varsto-cli` | the `varsto` binary: command line, background service with the local control API (`service.rs`), tray and desktop interface, MCP server (`mcp.rs`) |
| `varsto-ffi` | C ABI over the core and service for the Android and iOS shells in `apps/` |

All three exist as of 0.0.1-alpha.9; the mobile shells themselves live under `apps/`.

Build and test from the repository root: `cargo build`, `cargo test --workspace`, `cargo clippy --workspace --all-targets`, `cargo fmt --all --check`.
