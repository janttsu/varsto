# Varsto

> **Alpha software — do not use for production data.**
> Varsto is in early development. Bugs can cause data loss or corruption, file formats and protocols may change without a migration path, and the cryptography has not been independently audited yet.
> Do not use it as the only copy of anything. You are responsible for keeping your own backups and for checking that you can restore from them.
> Each released storage-format version keeps a reader; see [docs/spec/format-versions.md](docs/spec/format-versions.md).

*"Varsto" is a working name and may change before the first public release.*

Varsto is an end-to-end encrypted file sync, sharing and backup app that **does not sell storage**. You bring the storage; the app does the rest.

## Goals

- **Bring your own storage.** S3-compatible keys, any rclone-compatible remote, a local folder, or removable disks (for example old hard drives in a USB dock). Cold storage such as Glacier is understood and used for rarely accessed data.
- **No one to trust, and no shortcuts.** All content, file names and metadata are encrypted on your devices, and keys stay with you. External disks and cloud providers see opaque blocks only. Designed for post-quantum security (hybrid classical + post-quantum). Security is never traded for speed: there is no weaker "fast mode". Hardware security keys (FIDO2 / YubiKey), special-protected folders, and a recovery kit you store physically in several places. See [docs/architecture/security-principles.md](docs/architecture/security-principles.md).
- **No tracker, no account, no vendor cloud.** Devices find each other on the local network, through a rendezvous record in your own storage, and as a fallback through a DHT. Designed to avoid single points of failure.
- **Fast, block-level sync.** Files are split into blocks; only changed blocks move. Peer-to-peer transfer between your own devices, also offline over a LAN, with the cloud brought up to date when you are back online.
- **Safety nets.** Version history, trash (optionally on cold storage), durability policies with alerts, geographic location awareness, and provider-independent recovery. What the design tolerates, and what it does not, is listed in [docs/failure-model.md](docs/failure-model.md).
- **Clients.** Linux, Windows, macOS, Android, iOS; a CLI for Linux and macOS; an MCP server so you can manage and organise files by talking to a local or cloud AI of your choice.

None of this is finished. See [docs/architecture](docs/architecture/README.md) for the design principles and [docs/spec](docs/spec/README.md) for the status of the format and protocol specifications.

## Status

Alpha-0: the first vertical slice works on Linux from the command line. It chunks and encrypts files, stores them in a local-directory storage (a disk, a removable disk or a network mount), keeps a signed per-device ledger in that storage, and syncs a folder between devices that are never online at the same time, with conflict copies and a trash. See [docs/spec/alpha-0-format.md](docs/spec/alpha-0-format.md) for what it does and does not do. There is no sharing, no peer-to-peer transfer, no post-quantum hybrid yet, no mobile app and no audit.

### Quick start (alpha-0, Linux)

```bash
cargo build --release                      # produces target/release/varsto
export VARSTO_PASSPHRASE='a long passphrase'
varsto --home ~/.varsto-laptop init --name laptop            # prints the vault key once
varsto --home ~/.varsto-laptop storage add-local box /mnt/box
varsto --home ~/.varsto-laptop folder add docs ~/Documents/synced
varsto --home ~/.varsto-laptop sync

# on another device that can reach the same storage:
varsto --home ~/.varsto-desk join --name desk --vault-key <hex> --storage-path /mnt/box
varsto --home ~/.varsto-desk folder attach docs ~/synced
varsto --home ~/.varsto-desk sync
varsto --home ~/.varsto-desk status --json
varsto --home ~/.varsto-desk fsck --verify
```

Test data only. Keep your own backups.

## Repository layout

| Path | Purpose |
|---|---|
| `crates/` | Rust workspace: `varsto-core` (library) and `varsto-cli` (the `varsto` binary) |
| `docs/` | Architecture, specifications, testing guides |
| `tests/` | Test matrix and shared test assets |
| `scripts/test/` | Scripts used by the testing instructions |
| `website/` | Static project website (template) |
| `brand/` | Product name and brand settings in one place |

## Licence

Varsto is **source-available, not open source**. It is licensed under the [PolyForm Shield License 1.0.0](LICENSE): you may use it for any purpose, privately or in a company, except for providing a product that competes with it. It may not be sold, repackaged or rebranded as a competing product; redistribution of unmodified copies under the licence is allowed. The name and logo are covered separately by [TRADEMARK.md](TRADEMARK.md). Storage formats and protocols are intended to be openly specified so that your data stays recoverable.

## Contributing, security and testing

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [TESTING.md](TESTING.md)
