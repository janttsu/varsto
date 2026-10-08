# Varsto

> **Alpha software — do not use for production data.**
> Varsto is in early development. Bugs can cause data loss or corruption, file formats and protocols may change without a migration path, and the cryptography has not been independently audited yet.
> Do not use it as the only copy of anything. You are responsible for keeping your own backups and for checking that you can restore from them.
> Each released storage-format version keeps a reader; see [docs/spec/format-versions.md](docs/spec/format-versions.md).

*"Varsto" is a working name and may change before the first public release.*

Varsto is an end-to-end encrypted file sync, sharing and backup app that **uses your own devices and storage services of your choice**. You bring the storage; the app does the rest.

## Goals

- **Bring your own storage.** S3-compatible keys, any rclone-compatible remote, a local folder, or removable disks (for example old hard drives in a USB dock). Cold storage such as Glacier is understood and used for rarely accessed data.
- **No one to trust, and no shortcuts.** All content, file names and metadata are encrypted on your devices, and keys stay with you. External disks and cloud providers see opaque blocks only. Designed for post-quantum security (hybrid classical + post-quantum). Security is never traded for speed: there is no weaker "fast mode". Hardware security keys (FIDO2 / YubiKey), special-protected folders, and a recovery kit you store physically in several places. See [docs/architecture/security-principles.md](docs/architecture/security-principles.md).
- **No tracker, no account, no vendor cloud.** Devices find each other on the local network, through a rendezvous record in your own storage, and as a fallback through a DHT. Designed to avoid single points of failure.
- **Fast, block-level sync.** Files are split into blocks; only changed blocks move. Peer-to-peer transfer between your own devices, also offline over a LAN, with the cloud brought up to date when you are back online.
- **Safety nets.** Version history, trash (optionally on cold storage), durability policies with alerts, peer-to-peer transfer between your devices on the LAN and over the internet, zstd compression before encryption, geographic location awareness, and provider-independent recovery. What the design tolerates, and what it does not, is listed in [docs/failure-model.md](docs/failure-model.md).
- **Clients.** Linux, Windows, macOS, Android, iOS; a CLI for Linux and macOS; an MCP server so you can manage and organise files by talking to a local or cloud AI of your choice.

None of this is finished. See [docs/architecture](docs/architecture/README.md) for the design principles and [docs/spec](docs/spec/README.md) for the status of the format and protocol specifications.

## Status

Alpha (0.0.1-alpha.4): the core works on Linux, macOS and Windows (macOS and Windows builds are cross-compiled and not yet tested there) as a background service with a tray or menu-bar app, a local desktop interface, a command line, and an Android shell (sideloadable APK). Implemented: encrypted chunked sync through any directory, S3-compatible bucket or rclone remote, signed per-device ledger and convergence between devices that are never online together, conflict copies and trash, selective sync with placeholders, transferrer disks, untrusted replica devices, folder sharing with another user by key (sealed to a post-quantum request code), encrypted thumbnails, self-update, hybrid Ed25519 + ML-DSA-65 signatures, an MCP server with per-folder grants, durability policies with alerts, peer-to-peer transfer between your devices on the LAN and over the internet, zstd compression before encryption, and Varsto's own last-accessed record with cost advice from open price data. It chunks and encrypts files, stores them in a local-directory storage (a disk, a removable disk or a network mount), keeps a signed per-device ledger in that storage, and syncs a folder between devices that are never online at the same time, with conflict copies and a trash. See [docs/spec/alpha-0-format.md](docs/spec/alpha-0-format.md) for what it does and does not do. There is no sharing, no peer-to-peer transfer, no post-quantum hybrid yet, no mobile app and no audit.

### Quick start (alpha-0)

```bash
cargo build --release                      # produces target/release/varsto
varsto desktop                             # local graphical interface in your browser (127.0.0.1 only)
export VARSTO_PASSPHRASE='a long passphrase'
varsto --home ~/.varsto-laptop init --name laptop            # prints the vault key once
varsto --home ~/.varsto-laptop storage add-local box /mnt/box
varsto --home ~/.varsto-laptop storage add-s3 cloud --endpoint https://s3.fr-par.scw.cloud --region fr-par --bucket my-bucket --access-key-id AK... --secret-access-key ...
varsto --home ~/.varsto-laptop storage add-rclone hetzner storagebox:varsto   # any rclone remote
varsto --home ~/.varsto-laptop folder add docs ~/Documents/synced
varsto --home ~/.varsto-laptop sync
varsto tray                                # Linux/Windows: tray icon + background service (macOS: Varsto.app)
varsto update --check                      # self-update from the download page

# on another device that can reach the same storage:
varsto --home ~/.varsto-desk join --name desk --vault-key <hex> --storage-path /mnt/box
varsto --home ~/.varsto-desk folder attach docs ~/synced
varsto --home ~/.varsto-desk sync
varsto --home ~/.varsto-desk status --json
varsto --home ~/.varsto-desk fsck --verify

# peer-to-peer: devices exchange encrypted blocks directly (LAN automatically; internet with a reachable address)
varsto --home ~/.varsto-laptop p2p enable --port 17893 --public 203.0.113.5:17893
varsto --home ~/.varsto-laptop p2p status

# a durability policy: two cloud copies, one at home, verified within 30 days; exit code 0/1/2/3
varsto --home ~/.varsto-laptop policy set docs --min-copies 2 --place cloud=2 --place home=1 --verified-within-days 30
varsto --home ~/.varsto-laptop policy check

# let an AI assistant see one folder (read-only) and ask it where the idle files are cheapest to keep
varsto --home ~/.varsto-laptop mcp grant docs
varsto --home ~/.varsto-laptop mcp          # MCP over stdio; point Claude Desktop, Claude Code or any MCP client at this command

# selective sync, transferrer disks, replicas and sharing:
varsto folder attach docs ~/synced --selective && varsto folder files docs && varsto folder fetch docs big.mp4
varsto storage add-local stick /media/usb --carrier       # carries only what the other device lacks
varsto replica token                                      # give to an untrusted backup device
varsto --home ~/.varsto-replica replica init --name nas --token <t> --source /mnt/shared --target /mnt/nas/varsto
varsto share create docs                                  # token for another Varsto user
varsto --home ~/.varsto-shared share accept --name laptop --token <t> --storage-path /mnt/shared
```

Test data only. Keep your own backups.

## Repository layout

| Path | Purpose |
|---|---|
| `crates/` | Rust workspace: `varsto-core` (library), `varsto-cli` (the `varsto` binary: CLI, service, tray, desktop interface), `varsto-ffi` (C ABI for mobile) |
| `apps/` | `macos` (menu-bar app, Swift), `android` (foreground service + WebView), `ios` (SwiftUI shell, build on a Mac) |
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
