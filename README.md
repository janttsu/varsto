# Varsto

> **Alpha software — do not use for production data.**
> Varsto is in early development. Bugs can cause data loss or corruption, file formats and protocols may change without a migration path, and the cryptography has not been independently audited yet.
> Do not use it as the only copy of anything. You are responsible for keeping your own backups and for checking that you can restore from them.
> Each released storage-format version keeps a reader; see [docs/spec/format-versions.md](docs/spec/format-versions.md).

*"Varsto" is a working name and may change before the first public release.*

Source: <https://github.com/janttsu/varsto> (issues and pull requests welcome). Website: <https://varsto.net>.

Varsto is an end-to-end encrypted file sync, sharing and backup app that **uses your own devices and storage services of your choice**. You bring the storage; the app does the rest.

## Goals

- **Bring your own storage.** S3-compatible keys, any rclone-compatible remote, a local folder, or removable disks (for example old hard drives in a USB dock). Cold storage such as Glacier is understood and used for rarely accessed data.
- **No one to trust, and no shortcuts.** All content, file names and metadata are encrypted on your devices, and keys stay with you. External disks and cloud providers see opaque blocks only. Designed for post-quantum security (hybrid classical + post-quantum). Security is never traded for speed: there is no weaker "fast mode". Hardware security keys (FIDO2 / YubiKey), special-protected folders, and a recovery kit you store physically in several places. See [docs/architecture/security-principles.md](docs/architecture/security-principles.md).
- **No tracker, no account, no vendor cloud.** Devices find each other on the local network, and through a rendezvous record in your own storage (there is no DHT). Designed to avoid single points of failure.
- **Fast, block-level sync.** Files are split into blocks whose size follows the file; only changed blocks move, and the blocks of small files travel together in packs, so a folder of thousands of notes is a few objects on the storage, not thousands. Peer-to-peer transfer between your own devices, also offline over a LAN, with the cloud brought up to date when you are back online.
- **Safety nets.** Version history, trash (optionally on cold storage), a marker in every synced folder so an unmounted disk never reads as "everything deleted", a mass-deletion guard that holds large deletions until you confirm them, send-only and receive-only folders per device, encrypted off-site backups of any directory (read-only snapshots kept on your storages only, each for the days you choose), durability policies with alerts, peer-to-peer transfer between your devices on the LAN and over the internet, zstd compression before encryption, Strongroom folders that open only with a FIDO2 security key (libfido2 tools), a printable recovery kit (24 words, 2-of-3 shares) with a personal recovery package checklist ([docs/recovery.md](docs/recovery.md)), place labels on storages and disk groups (geographic sites are planned), and provider-independent recovery. What the design tolerates, and what it does not, is listed in [docs/failure-model.md](docs/failure-model.md).
- **Clients.** Linux, Windows, macOS, Android, and iOS as a Simulator build only (not run on a real device yet); a command line on Linux, macOS and Windows; an MCP server so you can manage and organize files by talking to a local or cloud AI of your choice ([docs/mcp.md](docs/mcp.md)).

None of this is finished. See [docs/architecture](docs/architecture/README.md) for the design principles and [docs/spec](docs/spec/README.md) for the status of the format and protocol specifications.

## Status

Alpha (0.0.1-alpha.13): the core works on Linux, macOS and Windows (since alpha.9 the macOS and Windows packages are built and tested on GitHub-hosted runners on every change, the Windows one on Windows Server 2025; they have not been through the manual checklists on real machines yet) as a background service with a tray or menu-bar app, a local desktop interface, a command line, and an Android shell (sideloadable APK). The iOS app (`apps/ios`, `crates/varsto-ffi`) is built and launched on the iOS Simulator in CI but has not run on a real device yet; there is no vendor relay for vaults without a reachable device, and no audit yet. See [docs/spec/alpha-0-format.md](docs/spec/alpha-0-format.md) for what it does and does not do.

**Released in 0.0.1-alpha.13** (spec sections 1 to 31): small blocks stored in packs (fewer objects and requests on buckets), the interface, tray and website in English, Finnish and Swedish, organizations for business use (administrators, device approval, removing a person, a signed log), peer-to-peer and the background service on by default, a default durability policy, block sizes that follow the file size, encrypted chunked sync through any directory, S3-compatible bucket or rclone remote, signed per-device ledger and convergence between devices that are never online together, conflict copies and a local trash copy of deleted files, selective sync with placeholders, transferrer disks, untrusted replica devices, folder sharing with another user by key (sealed to a post-quantum request code), encrypted thumbnails, self-update, hybrid Ed25519 + ML-DSA-65 signatures, an MCP server with per-folder grants, durability policies with alerts, peer-to-peer transfer between your devices on the LAN and over the internet (QUIC with hole punching, and a relay through one of your own reachable devices when punching fails; tested on localhost and on the maintainer's own networks only), zstd compression before encryption, Strongroom folders that open only with a FIDO2 security key (libfido2 tools), a printable recovery kit (24 words, 2-of-3 shares), a pool of removable disks that are filled, checked, ejected and recognized when they come back (with "attach this disk" prompts for files that are on a disk that is away), Varsto's own last-accessed record with cost advice from open price data, and backups: read-only snapshots of a directory kept on the storages only (never on your other devices), deleted from them once their retention in days has passed, and restored only into a directory you name.

**On main, after 0.0.1-alpha.13, not in a release yet** (spec sections 32 to 59): live activity between devices, the bit-rot check (scrub), whole drives for disk pools (`disk init`, `disk insert`, verified writes), backups with restic (one device keeps every folder as a full plaintext copy and backs it up into a restic repository outside the vault, restorable with restic alone), file analyses and `varsto search`, scoped MCP keys, ledger rebuild after losing ledger copies, media-aware parallel verification and hardware-decoded thumbnails, disk bookkeeping and the suggestion of the next disk to dock, the recovery package guide and the progress bar, imports of git-annex repositories (disk by disk, read-only), cloud drives through rclone (Dropbox, OneDrive and others, with the provider's hashes checked) and local folders (optionally emptied once their files are safe), the vault-wide trash, storage quotas and draining a storage, local debug logs, original names with local name mapping, folder safety (a marker in every synced folder, the mass-deletion guard, send-only and receive-only folders), ignore rules, file metadata (permissions, symbolic links, extended attributes, ownership), version history of overwritten files, QR invitations and `varsto://` links, router port mapping for peer-to-peer, minimum free disk space, the event stream for the interface, read-only members of shared folders, organization rules on which device platforms may belong, the change history of files (`varsto changes`), and staged moves to disk pools (`varsto move`, resumable jobs that go on disk by disk).

### Quick start

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
varsto install                             # Linux: varsto on PATH, tray at login, menu entry. Background sync (systemd user unit / macOS launch agent) is set up by any command once a vault exists; varsto uninstall turns it off
varsto tray                                # Linux/Windows: tray icon + background service (macOS: Varsto.app)
varsto update --check                      # self-update from the download page (also checked automatically)
varsto transfers --watch                   # uploads, downloads and peer traffic running now

# on another device that can reach the same storage:
varsto --home ~/.varsto-desk join --name desk --vault-key <hex> --storage-path /mnt/box
varsto --home ~/.varsto-desk folder attach docs ~/synced
varsto --home ~/.varsto-desk sync
varsto --home ~/.varsto-desk status --json
varsto --home ~/.varsto-desk fsck --verify

# recovery kit: the vault key as 24 words (and 2-of-3 shares) for paper or metal
varsto --home ~/.varsto-laptop recovery kit --shares
# what else to keep if every device is lost (storage keys, disks, security keys) and the restore steps
varsto --home ~/.varsto-laptop recovery guide --format html --output recovery-guide.html   # after 0.0.1-alpha.13, not in a release yet

# a Strongroom: the folder key exists only while your security key is touched (needs fido2-cred/fido2-assert)
varsto --home ~/.varsto-laptop strongroom create taxes ~/Taxes
varsto --home ~/.varsto-laptop strongroom unlock taxes --minutes 15

# peer-to-peer is on by default (port 17893): devices exchange encrypted blocks directly (LAN
# automatically; internet through NAT, with one of your own reachable devices as the relay when
# hole punching fails); `varsto p2p disable` turns it off
varsto --home ~/.varsto-server p2p enable --public 203.0.113.5:17893   # reachable: relays for the others
varsto --home ~/.varsto-laptop p2p status   # NAT guess, public address, path to every peer
varsto --home ~/.varsto-laptop p2p traffic --watch   # live speed, totals and path per peer

# a durability policy: two cloud copies, one at home, verified within 30 days; exit code 0/1/2/3.
# A folder without its own policy uses the default: 1 copy on any storage, 1 in external storage,
# 1 on your own devices or disks, verified by another device within 30 days.
varsto --home ~/.varsto-laptop policy set docs --min-copies 2 --place cloud=2 --place home=1 --verified-within-days 30
varsto --home ~/.varsto-laptop policy check

# let an AI assistant read and analyze one folder (--analyse: it records what each file contains,
# synced encrypted to your devices; --write: it may also reorganize). See docs/mcp.md.
# Analyses, scoped keys (--create-key) and `varsto search` are on main after 0.0.1-alpha.13, not in a release yet
varsto --home ~/.varsto-laptop mcp grant docs --analyse
varsto --home ~/.varsto-laptop mcp          # MCP over stdio; point Claude Desktop, Claude Code or any MCP client at this command
varsto --home ~/.varsto-laptop mcp config --client opencode --create-key --folders docs --analyse   # a scoped key and a ready config
varsto --home ~/.varsto-laptop search receipt 2026   # find files by their analysis, tags and path

# a lost or stolen device: remove it from another device (new vault keys for everything written
# afterwards) and order it to wipe itself when it next reaches a storage; then print a new recovery kit
varsto --home ~/.varsto-laptop device list
varsto --home ~/.varsto-laptop device revoke phone --wipe --yes
varsto --home ~/.varsto-laptop org create --name "Acme" --user alice   # business use: administrators, approvals, a signed log
varsto --home ~/.varsto-laptop org remove-user bob --wipe --yes       # every device of a person, in one step

# a backup: read-only snapshots of a directory, kept on the storages only, each for 90 days
varsto --home ~/.varsto-laptop backup add photos ~/Pictures --retention-days 90   # takes the first snapshot; then daily
varsto --home ~/.varsto-laptop backup list && varsto --home ~/.varsto-laptop backup snapshots photos
varsto --home ~/.varsto-laptop backup restore photos 2026-10-01 --to ~/Restored   # or a number, or latest
# restic (after 0.0.1-alpha.13, not in a release yet): this device mirrors every folder under /srv/varsto-mirror and backs it up daily
varsto --home ~/.varsto-server restic setup --root /srv/varsto-mirror --repo sftp:nas:/restic --password-file ~/.restic-pass --init
varsto --home ~/.varsto-server restic run && varsto --home ~/.varsto-server restic restore-hint   # the hint: restore without Varsto

# imports (after 0.0.1-alpha.13, not in a release yet), one folder per source: git-annex repositories disk by disk, cloud drives through rclone, local folders
varsto import git-annex /media/disk-03/photos     # then the disk it suggests next; see docs/import-git-annex.md
varsto import dropbox mydropbox:                  # also onedrive, or rclone <remote:path>; see docs/import-cloud.md
varsto import dir /media/old-drive --remove-source  # removes source files once stored and the policy is met; docs/import-local.md
varsto import status && varsto import verify photos

# a pool of removable disks: fill, check, eject, retire; files on a disk that is away say "attach disk data-01 (shelf)"
varsto storage add-pool shelf --place shelf
varsto disk add /media/me/data-01 --pool shelf --label data-01
varsto disk list && varsto disk check data-01 --full && varsto disk eject data-01

# selective sync, transferrer disks, replicas and sharing:
varsto folder attach docs ~/synced --selective && varsto folder files docs && varsto folder fetch docs big.mp4
varsto paths free ~/synced/big.mp4 && varsto open-placeholder ~/synced/big.mp4.varsto-placeholder  # what the file-manager actions run
varsto verify-release varsto-<version>-x86_64-unknown-linux-musl.tar.gz --github  # check a download against the signed SHA256SUMS
varsto storage add-local stick /media/usb --carrier       # a transferrer: carries only what the other device lacks
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
