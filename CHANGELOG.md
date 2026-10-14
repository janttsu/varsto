# Changelog

All notable changes to Varsto. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are the
git tags `v<version>`. Each released version also has a blog post under
`website/src/posts/`, and the storage format is described section by section
in [docs/spec/alpha-0-format.md](docs/spec/alpha-0-format.md) (referred to
below as "spec").

Every version so far is an alpha: not for production data, formats may still
change, and there is no compatibility between alphas unless a section says so.

Tags `v0.0.1-alpha.3` and `v0.0.1-alpha.9` do not exist: those versions were
folded into the next tag (alpha.3 into alpha.4, alpha.9 into alpha.10). The
spec still names them because sections were written as the work was done.

## Unreleased

On `main` after 0.0.1-alpha.13; spec sections 32 to 59.

### Hardening

- The STUN side channel of the peer socket is bounded and only accepts the
  answer to an open request (spec 59).
- The browser opens the interface with a one-time start code instead of the
  session token; the token is accepted in headers only; downloads and the
  viewer use per-file tickets; API answers are never cached (spec 59).
- Strongroom: a key given by hand must match the key commitment published
  with the folder (`check_hex`), and the libfido2 tools always ask for the
  PIN (`strongroom --uv` also requires user verification) (spec 17, 59).
- Device passphrases need at least 12 characters, and no secret is taken from
  the command line any more: `join --vault-key/--words`,
  `--s3-secret-access-key`, `storage add-s3 --secret-access-key`,
  `mcp --key`, the shares of `recovery combine` and `org admin --root-words`
  are replaced by prompts, files, environment variables and standard input;
  the macOS keychain gets the passphrase on standard input (spec 28, 59).
- Updater: the manifest must be signed (`manifest.json.minisig`), a signed
  list older than the last accepted one is refused, the GitHub cross-check is
  required unless `update --allow-single-source` is given, and a version not
  newer than the running binary is never installed (spec 59).
- Reads from storages are bounded (a chunk at most 16 MiB and 64 bytes, a
  record 256 MiB, S3 and rclone refuse longer answers before reading them),
  pack indexes are validated, and a panic while checking one object ends only
  that object (spec 59).
- restic repository logins (`rest:https://user:password@host`) are cut from
  logs, status and the kit note, the password command shows its first word
  only, and a support bundle carries a redacted `config.json` (spec 59).
- MCP: a key's last use is kept apart from the keys, so a use cannot undo a
  revocation; `varsto mcp` needs a key while the service runs; a scoped key
  sees only its folders in `/api/status` (spec 59).
- A malformed `%` escape in a request no longer kills the API worker thread.

### Added

- Live activity between devices (spec 32).
- Bit-rot check (scrub) with restores from good copies (spec 33).
- Whole drives for disk pools: init, insert, unmount, verified writes (spec 34).
- Backups with restic: a plaintext mirror on one device, backed up into a
  restic repository outside the vault's storages (spec 35).
- File analyses (spec 36) and MCP keys (spec 37).
- Losing ledger copies and rebuilding them (spec 38).
- Media-aware parallel verification and hardware-decoded thumbnails (spec 39).
- Disk bookkeeping and the next disk to dock (spec 40).
- Recovery package guide and the progress bar at the top (spec 41).
- Importing git-annex repositories, cloud drives and local directories
  (spec 42).
- Trash: deleted files kept vault-wide (spec 43).
- Storage quotas and draining a storage (spec 44).
- Local debug logs, on by default, with secret scrubbing (spec 45).
- Original names and local name mapping (spec 46).
- Folder safety: the folder marker, the mass-deletion guard, send-only and
  receive-only folders (spec 47).
- Ignore rules (spec 48).
- File metadata: permissions, symbolic links, extended attributes, ownership
  (spec 49).
- Version history of files (spec 50) and the change history `varsto changes`
  (spec 57).
- QR invitations and `varsto://` links (spec 51).
- Router port mapping for peer-to-peer: PCP, NAT-PMP, UPnP IGD (spec 52).
- Minimum free disk space: writes pause before a disk runs full (spec 53).
- Event stream for the interface, `GET /api/events` (spec 54).
- Read-only members of shared folders (spec 55).
- Organizations: which device platforms may belong (spec 56).
- Help page in the interface, in English, Finnish and Swedish.
- CI quality gates: `cargo fmt --check`, `cargo clippy -D warnings`,
  `cargo audit` and `cargo deny check` (`deny.toml`).
- Website: comparison pages for Cryptomator, rclone and restic/borg.
- Recovery kit: a "Key check" line and `varsto recovery combine --check`,
  which refuses a key rebuilt from a share of another kit; two shares with
  the same index are refused.
- `storage add-s3 --insecure-http` (`join --s3-insecure-http`): an `http://`
  endpoint outside this computer is refused without it.
- Staged moves to disk pools: `varsto move <folder> --from <storage> --to <pool>` records a
  resumable job that moves what fits on the attached disks, waits for the next
  disk and goes on by itself; `--path`, `--keep-source`, `move status|pause|resume|cancel`,
  disk groups, `disk suggest` and the `move.waiting` and `move.done` events (spec 59).

### Changed

- Hardening: key files and the device directory are created with private
  modes from the first byte; session tokens and MCP key digests are compared
  in constant time; key strings are wiped on drop and never shown in Debug
  output; the Strongroom key wrap binds the vault id; the software security
  key is built only with the `software-key` feature; a replica skips junk
  names under `chunks/`; Shamir shares come from `blahaj` instead of `sharks`
  (RUSTSEC-2024-0398), with the same share encoding.

- The design documents mark what is built and what is not; the top-level
  documents separate released features from unreleased ones.
- Faster syncs: the Lamport clock is kept in memory and reserved in
  `clock.json` in blocks of 1000 values (spec 6); storages are opened once
  per sync, S3 conditional writes are probed once and skip the HEAD before
  PUT, uploads go to several storages side by side (spec 12); a sync scans
  each folder once; release builds use thin LTO and mimalloc.

### Security

- Ledger authorization and gap handling (spec 58): replicas and members of
  shared folders count only for their own claims and folder, checkpoints
  speak only for their signer, a withheld batch holds back the ones after it
  and is reported, junk under a device's ledger name no longer fences it
  (`varsto ledger clean-junk`), and revocations follow the order of the key
  epochs (`varsto device resolve-epoch` when two share a number).

## [0.0.1-alpha.13] - 2026-10-13

### Added

- Backups (spec 31): pick a folder on any device and Varsto keeps encrypted,
  read-only snapshots of it on external storages only, never on devices, for
  a number of days (90 by default), then deletes the expired ones. Daily,
  weekly or manual snapshots; restores into a directory you name, from the
  interface (`Backups` page) or `varsto backup …`.
- Lab scenario for backups.

### Changed

- Older versions do not understand backups: every device of a vault must be
  on alpha.13 before a backup is added.

## [0.0.1-alpha.12] - 2026-10-12

### Added

- Packs for small blocks (spec 30): blocks up to 128 KiB travel together in
  packs of about 4 MiB, one storage object per pack, read with ranged
  requests. Used on S3 buckets, rclone remotes and directories; cold storage,
  disk pools and transferrer disks keep single objects.
- The interface, tray, menu bar, mobile shells and the website in Finnish and
  Swedish; English stays the default.
- Website: Contribute page, sitemap, canonical and social tags.

### Fixed

- S3: a ranged read answered with status 200 and just the range is accepted.
- Packs: a read that misses reloads the pack indexes; deletions by another
  device are seen before a write is skipped.
- Storages without packs write each block on its own, so a full or missing
  disk is reported as such.
- S3: a clock behind is corrected as well as one ahead (servers answering
  400 as well as 403).

### Changed

- No compatibility with alpha.11 and earlier: a device on an older version
  does not see blocks in packs.

## [0.0.1-alpha.11] - 2026-10-12

### Added

- Background by default: service, peer-to-peer, updates and thumbnails
  (spec 29); block sizes chosen by file size; a default durability policy.
- New files go peer to peer during their upload.
- Command line beside the background service: folders, unlocking, clock.
- Website: comparison pages (Syncthing, Resilio Sync, MEGA, Filen, Tresorit,
  git-annex).

### Fixed

- `varsto update` never says "up to date" while a newer version exists.

## [0.0.1-alpha.10] - 2026-10-12

Includes the work labelled 0.0.1-alpha.9 in the spec and the blog, which was
never tagged on its own.

### Added

- Data placement: per-folder placement, moving data between storages, disk
  groups (spec 23).
- Shared folders: confirming the requester by fingerprint, removing members
  with share epochs, Strongroom re-key (spec 24).
- Manifest listing and pruning (spec 25); automatic repair (spec 26).
- Signed releases: `SHA256SUMS` signed with an offline release key; the
  updater refuses an unsigned release and compares with the GitHub release
  as a second channel; `varsto verify-release`.
- File-manager integration on Linux (Nautilus, Dolphin, Nemo) and Windows
  (Explorer).
- Organizations: administrators, approvals, removing a person (spec 27).
- Hardening against other devices, storages and peers (spec 28), after a
  security review of alpha.10.
- Test lab: a small internet in virtual machines with end-to-end scenarios;
  a scale scenario (20 000 small files and 1 GiB).
- Website: benchmarks (Paris, Amsterdam, Warsaw; a home behind NAT), the
  forum, the move to varsto.net.
- CI: every platform built, tested and photographed on GitHub-hosted runners.

### Changed

- Peer-to-peer downloads keep up to eight blocks in flight, fetch small files
  ahead and share one connection per peer; serving blocks no longer starts a
  full sync; QUIC and TCP are tried in the order that measured faster.
- Push writes objects from eight uploader threads; one zstd context per
  thread.
- Moving data writes a ledger entry that alpha.8 and earlier cannot read:
  update every device first. From this version on, unknown entries are
  skipped.

### Fixed

- S3: response bodies up to 2 GiB (large ledger batches and file lists);
  sync from a device whose clock is off.
- Linux keyring: never wait forever for `secret-tool`; the install always
  restarts the service unit.
- Thumbnails: decode limits and an ffmpeg timeout.

## [0.0.1-alpha.8] - 2026-10-09

### Added

- Automatic verification, storage prices and placement suggestions (spec 20).
- Removing a device: revocation, key epochs and remote wipe (spec 21).
- Ledger upkeep: signed checkpoints, acknowledgements and pruning; one batch
  per action; a cached view so a sync applies only new batches (spec 22).
- Folders kept encrypted on a phone hold encrypted blocks, never plaintext;
  in-app viewer and camera upload on Android.
- "Where your data is" map, live peer-to-peer traffic view, download progress.
- Strongroom: backup security keys and converting existing folders.
- Remove a storage safely; detach or remove folders; unique top-level names;
  transferrer disks with a destination device.
- Linux: installs itself at the first start; background sync for
  command-line users.
- MCP: the assistant can never delete or replace files.

## [0.0.1-alpha.7] - 2026-10-09

### Added

- Pair a device with a one-time code from the interface or the command line
  (SPAKE2; `varsto pair offer` and `varsto pair join`).
- macOS: Finder actions for placeholders (download, free up space,
  double-click to open); the app installs from a disk image.
- Peer-to-peer through NAT: STUN, QUIC with pinned certificates, relay
  through one of your own reachable devices (spec 15, NAT traversal).
- Disk pool: a storage made of removable disks (spec 19).
- Phones: add files and subfolders, open a file in another app, a per-folder
  mode for plain files in internal storage.
- Durability policies edited in one table; file details name the storages;
  joining accepts the 24 recovery words.

## [0.0.1-alpha.6] - 2026-10-08

### Added

- The source is public on GitHub under the PolyForm Shield License 1.0.0;
  history rewritten before publication.
- macOS and iOS apps built on GitHub Actions; Linux, Windows and Android on
  throw-away cloud machines; cross-platform integration test through S3.
- Native macOS app with its own window, menu-bar item and the command line in
  the bundle (Apple Silicon).
- Files-first interface: folder tree, Files view with state squares and a
  details pane, phone mode, light and dark themes, device reset, placement
  suggestions from open price data.
- New logo and app icons; illustrations rendered in Blender.

## [0.0.1-alpha.5] - 2026-10-08

### Added

- Recovery kit: the vault key as 24 words with 2-of-3 shares (spec 18).

## [0.0.1-alpha.4] - 2026-10-08

Includes the work labelled 0.0.1-alpha.3 in the spec, which was never tagged
on its own.

### Added

- Post-quantum hybrid cryptography: ML-KEM for sharing keys, Ed25519 +
  ML-DSA-65 signatures; sealed share tokens (spec 11).
- Remote storages: S3-compatible buckets and rclone remotes (spec 12).
- Last-accessed times and the MCP server with per-folder grants and cost
  advice (spec 13).
- Durability policies with alerts (spec 14).
- Peer-to-peer block transfer (spec 15) and compression before encryption
  (spec 16, format version 1).
- Strongroom folders opened with a FIDO2 security key (spec 17).

## [0.0.1-alpha.2] - 2026-10-08

### Added

- Background service, tray and menu-bar apps; self-update (spec 10).
- Selective sync and placeholders; transferrer disks; untrusted replicas;
  shared folders; encrypted thumbnails; mobile shells; folders kept encrypted
  on a device (block cache).
- Website: Features, Use cases and Screenshots pages.

## [0.0.1-alpha.1] - 2026-10-08

### Added

- The local desktop interface and macOS app bundle packaging.

## [0.0.1-alpha.0] - 2026-10-08

The first vertical slice: a command-line tool with a small local interface,
one storage backend (a directory), and the smallest set of mechanisms that
make the core idea real (spec 1 to 9).

### Added

- Content-defined chunking and deterministic chunk encryption keyed by the
  chunk's own keyed hash, so equal content deduplicates without coordination.
- Chunks, folder manifests and ledger batches written to a local-directory
  storage with put-if-absent semantics.
- Manifest merging with version vectors: concurrent edits keep both versions
  as a conflict copy, a deletion never beats a concurrent edit, deleted files
  go to a local trash.
- A device restored from an old backup is detected and refused as a signer.
- `fsck --verify` re-hashes every referenced object and reports claims the
  storage cannot back.

[0.0.1-alpha.13]: https://github.com/janttsu/varsto/releases/tag/v0.0.1-alpha.13
[0.0.1-alpha.12]: https://github.com/janttsu/varsto/releases/tag/v0.0.1-alpha.12
[0.0.1-alpha.11]: https://github.com/janttsu/varsto/releases/tag/v0.0.1-alpha.11
[0.0.1-alpha.10]: https://github.com/janttsu/varsto/releases/tag/v0.0.1-alpha.10
[0.0.1-alpha.8]: https://github.com/janttsu/varsto/releases/tag/v0.0.1-alpha.8
[0.0.1-alpha.7]: https://github.com/janttsu/varsto/releases/tag/v0.0.1-alpha.7
[0.0.1-alpha.6]: https://github.com/janttsu/varsto/releases/tag/v0.0.1-alpha.6
[0.0.1-alpha.5]: https://github.com/janttsu/varsto/releases/tag/v0.0.1-alpha.5
[0.0.1-alpha.4]: https://github.com/janttsu/varsto/releases/tag/v0.0.1-alpha.4
[0.0.1-alpha.2]: https://github.com/janttsu/varsto/releases/tag/v0.0.1-alpha.2
[0.0.1-alpha.1]: https://github.com/janttsu/varsto/releases/tag/v0.0.1-alpha.1
[0.0.1-alpha.0]: https://github.com/janttsu/varsto/releases/tag/v0.0.1-alpha.0
