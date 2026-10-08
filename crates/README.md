# crates

Rust workspace.

| Crate | Purpose |
|---|---|
| `varsto-core` | chunking, cryptography, storage backends, ledger, manifests and the sync engine |
| `varsto-cli` | the `varsto` command-line tool |

Planned: daemon with the local control API, MCP server, mobile bindings.

Build and test from the repository root: `cargo build`, `cargo test --workspace`, `cargo clippy --workspace --all-targets`, `cargo fmt --all --check`.
