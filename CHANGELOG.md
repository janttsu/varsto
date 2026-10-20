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

- One storage that cannot be reached no longer fails a whole sync (spec 79.1). The first network error of a storage (refused or reset connection, timeout, unknown host, HTTP 502/503/504, an rclone remote that cannot be dialled) marks it down for the rest of the run and every later call to it answers at once; between runs it rests (30 seconds, doubling up to 10 minutes, kept in `state/storage-health.json`) unless `retry_storages_now` is called. The membership, ledger, folder records, uploads (one thread per storage of a target set), downloads (the next storage is asked), record writes (the storages that answer decide the number), thumbnails (best effort, never before the upload), snapshots and organization records go on with the storages that answer; a folder that fails is reported in its sync report (`error`) and the other folders still sync; what a storage missed is copied there once it answers. `status` lists the storages that are down or resting (`storages_down`), and the upkeep after a sync reuses the sync's ledger pull.
- A bad network costs seconds, not minutes: S3 calls get 5 s name resolution, 10 s connect, time limits that grow with the body (the old 600 s global limit made a 64 MiB pack fail below about 0.9 Mbit/s), three tries with backoff for reads, deletes and content-addressed or put-if-absent writes, and multipart uploads from 8 MiB where only a failed part is sent again (no one-request fallback); the conditional-writes probe no longer fails the write when the network is down. rclone calls pass `--contimeout`, `--timeout`, `--retries 1` and `--low-level-retries 2` and a stuck `rclone` is killed through its own process handle after a wall-clock limit. Failures of the network are a distinct error (`storage::is_network_error`). Typed host names resolve with a timeout, and joining checks the bundled storages in parallel with a short budget (spec 79.2).
- Joining by pairing no longer needs a storage to answer: when the new device cannot reach any S3 or rclone storage of the vault (a bad connection, a firewall), the pairing carries every vault key epoch (sealed to the new device like the vault key), the device is set up at once with the storage settings, and `state/pending-join.json` makes the next sync finish joining: check the vault and the key against the first storage that answers, add the storages, read the records and publish the enrolment. Until then a sync says "joining is not finished". A directory or disk pool that does not exist on the new device is still refused (spec 68).
- Storage format 3 ([docs/spec/format-3-design.md](docs/spec/format-3-design.md), spec 77; `FORMAT_VERSION` 3): a pack-level ledger, signed records, folder block maps, base + delta manifests, approval of joining devices and recovery escrow. The ledger claims packs of a few fixed sizes (256 KiB to 64 MiB, random padding, so a storage sees size classes only) instead of every block; each folder keeps a signed block map (block to pack and offset) per writing device; every published object other than a pack is a signed record that names the key it is sealed with; manifests, trash lists and snapshots are a base plus small deltas; folder keys reach a device only as a grant that an owner approved by hand (or that a pairing offer named), and every folder key epoch has a recovery copy under a second set of 24 recovery words; peers talk TLS only, with tokens bound to the connection, and compare ledger heads, so a storage that withholds or rolls back batches gets a warning (`varsto status`, the Help page, a notification); unreferenced blocks are freed by dead marks that every writing device acknowledges before a pack is dropped or rewritten. **Vaults from alpha.15 and earlier must be recreated (no upgrade path).** A format 3 build refuses a format 2 vault when it opens it, joins through its storage or adds its storage to a new vault, and says what to do (`varsto reset --yes`, `varsto init`, sync the files into the new vault); alpha.15 refuses a format 3 vault ("newer than this version of Varsto reads") and stays the tool to read an old one. The format reaches the daily channel first; the next release carries it ([docs/spec/format-versions.md](docs/spec/format-versions.md)).
- What changes when you use format 3: `varsto init` prints a kit with two word sets, the vault words and the recovery words. `varsto folder add` asks for the recovery words (a hidden prompt, `VARSTO_RECOVERY_WORDS`, `--recovery-file`, or the copy `varsto unlock --with-recovery-key` gave the background service) to make the folder's recovery copy; `varsto recovery escrow` writes a missing one later, and `varsto status` warns until then. A device that joins with the vault words sees folder names and holds no content: it asks with `varsto folder request`, an owner compares the six words and approves with `varsto folder approve` (also `requests`, `deny`, `members`, `role`), and the background service never approves; `varsto join --recovery-words` opens every folder that has a recovery copy. Pairing shows six words on both devices; the offering device asks whether they match and names the folders the new device may open (`varsto pair offer --folders A,B --role editor`). Sharing a folder with another person's device no longer uses a sealed token: `varsto share create` shows the owner's six words and `varsto share accept --owner-words` takes them. `varsto folder remove <folder> <device>` and `varsto device revoke` start a new folder epoch the removed device never gets. `varsto fsck`, `repair`, `scrub` and `trash upkeep` work on packs (`fsck --fix` copies missing packs whole); a deleted file's blocks are freed once every writing device has synced ("deleted blocks are freed once desktop has synced"). The interface follows in English, Finnish and Swedish: the recovery words in the add-folder form, the folder access card, the first-run page with the recovery kit, the rollback warning.
- Lab (`scripts/test/lab`): every scenario checks format 3 artefacts (packs of exact size classes, signed records, recovery copies) and goes through request and approval where a device needs a folder; `upgrade-from-alpha-14` is now `upgrade-from-alpha-15` (an alpha.15 vault is refused, an alpha.15 binary refuses a format 3 vault, and the way forward works); new scenarios `format3-scale`, `approval-flow`, `recovery-escrow`, `rollback-warning`, `member-removal`, `gc-settling` and `mailbox-offline-disk`; `ledger-rollback` is in the default set again. `scenarios.py --list` prints the scenarios and `--check` is a self-check that needs no VM.
- The daily channel record (`update-channel.json`) now carries the SHA-256 of the installed binary: `varsto --version` and `varsto status` name the daily build only when the running binary is that one, so a binary installed by hand never shows a stale build id, and `varsto update --daily` on such a copy installs the newest daily build instead of saying it is up to date (spec 67).
- Design of storage format 3 ([docs/spec/format-3-design.md](docs/spec/format-3-design.md)): the ledger claims packs instead of blocks, each folder keeps a signed block map (block to pack and offset), every record is a signed envelope with a signed key id, folder keys travel only as approved grants with recovery escrow, manifests, trash and snapshots become base + delta records, packs are padded to size classes, and peers exchange ledger heads to detect a storage that withholds or rolls back batches. Built by the entries below and switched on by the format 3 entry at the top of this list.
- `varsto service remember` now works without a desktop session (over SSH, on servers). It tries the desktop keyring, then `systemd-creds encrypt --user` (an encrypted `passphrase.cred` in the device directory, read by the service at start, survives a restart), then the Linux kernel keyring (until the computer restarts), and says which one it used; when none works the error lists what was tried. New `varsto service forget` removes the passphrase from whichever store holds it, and `varsto service status` shows where it is remembered (spec 72).
- A device that has joined shows on the other devices within seconds (device list, peers and the first peer-to-peer path) instead of at their next sync: the service watches for new devices and rendezvous records with short gaps that back off, announces itself before its first sync and empties cached reads on the change (spec 73). A device is never its own peer: requests carrying its own id or certificate are refused and nothing is counted for itself in the traffic view.
- Peer-to-peer: the reachability self-probe works again. It dialled the device's own certificate, which a device refuses since it may never be its own peer, so a device behind a forwarded or public port was never marked reachable unless its address was configured; the probe is now a dedicated exchange (spec 73). A request retried after a kept TCP connection dropped now carries a fresh token instead of one the peer may already have spent.
- Storage format 3, signed record envelope. The `format3` cargo feature of varsto-core (passed through by varsto-cli and varsto-ffi; on by default since the format 3 switch) adds `record`: the `SignedRecord` envelope with its kind table, stream names and `key_id` grammar, size-class padding, multi-part records, the acceptance rule and refusal counts, a writer and a stream reader (`docs/spec/format-3-design.md`, section 5). The format 3 switch (top of this list) uses it for every published object.
- Storage format 3, folder membership. `membership3` in varsto-core adds `device` records (K6 and K8 public keys, device id = BLAKE3 of K6), `folder` records with owner-only updates and per-device merge by stamp, `grant` records sealed to a device's K8 (folder keys and vault keys), folder epochs as signed `share-epoch` records with "two epochs under one number" held back until resolved, vault epochs and revocations as signed records, `request` records with a six-word fingerprint over K6 and K8, and recovery escrow of every folder epoch under the recovery key and K3₀ (`docs/spec/format-3-design.md`, sections 5 and 6). Data model; the commands and pages follow in the entries below.
- Spec: section 77 describes format 3 (enabled by the format 3 switch).
- Storage format 3, peers and transport (`docs/spec/format-3-design.md` section 8, spec 75). Peer records as signed records with the TLS certificate pin, head list and pushed storages; servers admit only certificates of accepted peer records (never their own); TLS 1.3 over TCP with the same pins (a plain HTTP client gets a TLS alert); request tokens keyed with the TLS exporter of the connection instead of a vault key; signed LAN beacons with sequence numbers; a pairing hello with the joining device's keys, name and six-word fingerprint, approval at the offering device and the vault key sealed to the joiner's KEM key; head exchange with signed batch envelopes as proofs, batch fetch from peers and the rollback warning rule. Used by the format 3 switch.
- Storage format 3, folder membership for people (`docs/spec/alpha-0-format.md` section 76). `varsto folder request | requests | approve | deny | members | role | remove <folder> <device> | resolve-epoch` and `varsto recovery escrow`, `recovery kit --recovery-words` (both word sets) and a `varsto status` warning for folders without a recovery copy; the same as local API routes (`/api/folder/requests`, `approve` which refuses without `fingerprint_confirmed`, `deny`, `members`, `role`, `remove` with a device, `resolve-epoch`, `/api/recovery/escrow`), the events `folder.request` and `folder.changed`, a Folder access card on the Files page (fi, sv) and the pairing question on the offering device (`/api/pair/start` with `format: 3`, `/api/pair/answer`). Approval always shows the device name and its six words and needs a yes; the background service only lists and announces requests. Builds without the `format3` feature (a development option) answer these commands and routes with "not available in this build".
- A push builds one pack per target set instead of one per storage: the storages a block goes to (cold storages apart) get the same pack under the same id, as storage format 3 asks (spec 62, 77.2). A storage of the set that already holds a member builds its own pack; a pool without a disk takes nothing and does not stop the others.
- The unsigned iOS `.ipa` joins the release download set (`publish-ci-release.sh` adds it to `SHA256SUMS` and `manifest.json`) and gets a download card on the website.

## [0.0.1-alpha.15] - 2026-10-16

Spec sections 62 to 71. Storage format 2: vaults of alpha.14 and earlier are not read and must be recreated; every device must run alpha.15. This is still an alpha: not for production data. Two findings of the security review (file lists and share epochs accepted on the folder key alone) wait for the records layer of the next format and are not closed here.

### Changed

- Format 2 blocks (spec 62): chunk nonces follow the packed bytes, chunks are
  compressed with zstd level 3 after a 64 KiB probe, the chunker's Gear table
  is keyed per folder with new block sizes by file size, and every block of
  every storage is stored in packs (64 MiB, 256 MiB on cold storages) with
  encrypted pack indexes, places in the ledger and rewriting of mostly dead
  packs. Tombstone lists are kept per folder under the folder's metadata key,
  so members of a shared folder read them, and a tombstone of another device
  never kills a block the ledger still claims. Pushes, moves, repairs,
  storage removals and Strongroom conversions collect blocks across files
  into packs; imports pack each content. Reads of packs are bounded by the
  pack target plus one block. The storage format version is now 2: vaults of
  format 1 (0.0.1-alpha.14 and earlier) are not read. Alpha.15 refuses them
  when it opens one or joins through its storage, with a message that says to
  recreate the vault (`varsto reset --yes`, `varsto init`, sync the files
  again); alpha.14 refuses a format 2 vault. Keep the alpha.14 binary to read
  an old vault.
- Windows: the portable zip is gone; install with the setup program
  (`Varsto-<version>-setup.exe`), which is now the only Windows download, also
  on the daily channel. `varsto update` and `varsto update --daily` always
  install through it; an old portable copy is told to download and run the
  installer once, and updates continue automatically after that (spec 65).
- Disk initialisation (`disk init`) uses one drive layout (spec 66): GPT only,
  one partition starting at 1 MiB, a partition type per filesystem, with
  command builders for Linux, macOS and Windows.
- Messages use real singular and plural forms instead of "(s)".
- `varsto service remember` over SSH without a desktop keyring now fails at
  once with an explanation (use `VARSTO_PASSPHRASE` or `varsto unlock`).
- Camera upload folders on phones are send-only, the encrypted default is
  explained, and such a folder cannot be turned selective.
- A folder without a placement is written to the fewest storages that keep
  its policy.
- Interface: the Finnish and Swedish translations cover the rest of the
  interface (composite lines, plurals, organization header, path labels,
  ledger batch counts); the coverage test now also checks the static page,
  sentences in the scripts and the composite patterns.

### Added

- Windows (spec 65): `varsto-window.exe` shows the interface in a native
  WebView2 window (saved size and position, one window per user, tray starts
  it, browser fallback), a single tray per session, and the Inno Setup
  installer (upgrade in place, repair, uninstall that keeps the data folder,
  WebView2 check). Windows copies installed by the setup program check for
  updates daily (`varsto config auto-update`, interface switch), install the
  signed setup program silently, and show toast notifications.
- `varsto update --daily` and `--check --daily` (spec 67): installs the newest
  daily build from `daily/latest/`, whose checksum list is signed with a
  separate daily key (`daily-key.pub`); the updater checks the signature, the
  channel, the signing time and the build age, and a daily signature never
  validates a release or the other way round. Daily builds are automated by
  `daily.yml` (all platforms when main moved, a signed rolling pre-release)
  and shown on a static daily page of the website.
- Files page: a folder overview (name, size, files, mode, last change) and a
  colour-coded safety indicator per folder, also in the navigation: 100 % in
  external storage, 100 % on your own disks only, partly protected (with the
  percentage) or only on devices. It is computed from the ledger and carried
  in `protection` of every folder in `/api/status` (spec 63). File lists have
  a compact (default) and a comfortable density, kept in the browser.
- Visualization page (spec 64): an isometric live board of devices, storages,
  the disk pool and the cloud with animated flows (bytes per second, folder,
  estimated finish), verification and repair rings, protection per folder,
  the offline disk stack with the docked disk's phase (a SATA dock sprite),
  cost estimates and alerts. Full screen (button or F) fills the display at
  its native size, including 16:9 and 4K, with real full screen in the
  browser and in the Android, macOS and Windows shells; Esc, the button and
  Back leave it. Background follows the theme or is Light or pure black.
  Flow labels keep their place and particles are calmer. New `GET /api/viz`
  snapshot; sprites from `website/tools/render/viz_sprites.py`.
- iOS: an unsigned `.ipa` for AltStore, SideStore and Sideloadly, built by
  `apps/ios/make-ipa.sh` or the manually started GitHub workflow `ios-ipa.yml`
  (also on `ios-v*` tags); app icon asset catalog, iPad orientations, version
  numbers in `Info.plist`; build, install and cost notes (GitHub, Scaleway Mac
  mini) in `docs/ios-build.md`. The Rust core is linked statically and the
  build checks the executable.
- Pairing (spec 68): the offer lists every usable local address, best first
  (private, then public, then tunnel addresses; loopback, link-local and
  container bridges skipped), and carries them all in the pairing link. Joining
  tries the typed address, the link's addresses, then a search of the local
  network from every interface, with visible progress and an error that names
  what was tried and why it failed.
- Forwarding (spec 70): a device attached to a folder, also with selective
  sync and holding no files, carries blocks other devices wrote to the
  storages it can write when the folder's copy rules still need them (checked
  by hash, written as packs, read back and claimed); leases on the storages
  keep two forwarders from writing the same blocks. New `varsto forward`,
  `/api/forward` and a forward activity kind. The attach dialog asks for full
  or selective sync and the direction; `POST /api/folder/attach` and
  `varsto folder attach` take a mode (`--mode send-only|receive-only`).
- Android and phones: photos and videos already on the phone are backed up,
  newest first, when a camera folder is added.
- Website: a French translation of every translated page and a language
  switcher; all screenshots are refreshed on every build, in English, Finnish
  and Swedish, plus a full-screen visualization shot; deploying refuses pages
  that still say no binaries are published.

### Fixed

- Draining and placement: a storage that a folder is written to cannot be
  drained, a folder cannot be placed on a drained storage, stale storage
  locations leave the view after a drain, and the Placement dialog shows the
  folder's real placement with places tied to the ticked storages.
- Storages: every device lists the vault's storages, and the same bucket,
  remote or directory cannot be added twice. Phones add S3 and rclone
  storages only (a local directory is refused by design); peers are no longer
  listed as storages.
- Thumbnails are made for storages added later, and an early, bounded thumbnail
  pass runs for existing folders before the upload.
- Overview counts, paths and device names in the interface.
- Printing the recovery package works in the interface and in the macOS
  window; clicking the macOS Dock icon keeps the window.
- Android: Back goes through the page first (it closes a dialog or returns to
  the previous view before leaving the app), and the on-screen keyboard
  shrinks the page instead of covering fields.
- Verification: blocks stored within the larger of the verification window
  and 24 hours are "verification pending" instead of a violation; copy-count
  rules are unchanged.
- Responsiveness (spec 71): read-only API routes are answered on their own
  threads and, while a sync holds the state, from the last kept answer marked
  stale; the upkeep after a sync lets go of the state between steps;
  `Engine::status` reads the ledger once (6.2 s to 0.7 s on a vault of 50 000
  files). The page asks each background read once at a time, draws the summary
  once, draws file lists 300 rows at a time without redrawing equal answers,
  and is never reloaded when the service is busy or restarts.
- `varsto reset` clears the vault marker and restarts a running service;
  `varsto update` starts a running service again after replacing the binary.
- Smaller: the musl fallback build works when `musl-gcc` is absent; two test
  races in CI.

## [0.0.1-alpha.14] - 2026-10-14

Spec sections 32 to 60. Storage format 1 unchanged; every device must run alpha.14 (the ledger view cache and the record checks changed).

### Hardening

- The STUN side channel of the peer socket is bounded and only accepts the
  answer to an open request (spec 60).
- The browser opens the interface with a one-time start code instead of the
  session token; the token is accepted in headers only; downloads and the
  viewer use per-file tickets; API answers are never cached (spec 60).
- Strongroom: a key given by hand must match the key commitment published
  with the folder (`check_hex`), and the libfido2 tools always ask for the
  PIN (`strongroom --uv` also requires user verification) (spec 17, 60).
- Device passphrases need at least 12 characters, and no secret is taken from
  the command line any more: `join --vault-key/--words`,
  `--s3-secret-access-key`, `storage add-s3 --secret-access-key`,
  `mcp --key`, the shares of `recovery combine` and `org admin --root-words`
  are replaced by prompts, files, environment variables and standard input;
  the macOS keychain gets the passphrase on standard input (spec 28, 60).
- Updater: the manifest must be signed (`manifest.json.minisig`), a signed
  list older than the last accepted one is refused, the GitHub cross-check is
  required unless `update --allow-single-source` is given, and a version not
  newer than the running binary is never installed (spec 60).
- Reads from storages are bounded (a chunk at most 16 MiB and 64 bytes, a
  record 256 MiB, S3 and rclone refuse longer answers before reading them),
  pack indexes are validated, and a panic while checking one object ends only
  that object (spec 60).
- restic repository logins (`rest:https://user:password@host`) are cut from
  logs, status and the kit note, the password command shows its first word
  only, and a support bundle carries a redacted `config.json` (spec 60).
- MCP: a key's last use is kept apart from the keys, so a use cannot undo a
  revocation; `varsto mcp` needs a key while the service runs; a scoped key
  sees only its folders in `/api/status` (spec 60).
- Names of devices and people cannot hold control, zero-width or direction
  characters (checked when made and when read from a code), and the command
  line shows names escaped (spec 60).
- Disk pool markers carry a MAC under the vault's key: a disk that only
  repeats the public fields is not adopted and gets no writes until
  `varsto disk add` takes it in (spec 60).
- Peer transport: a router mapping is published only after our own probe
  reached us, TCP request heads have a 5 second deadline and an address may
  hold at most 8 unfinished ones, QUIC has limits on incoming connections
  and streams (spec 60).
- Temporary files beside a folder's files are created exclusively under a
  random name with mode 0600, and manifests, trash records and notes cannot
  name Varsto's own files (`.varsto*`, `.varsto-placeholder`, `.varsto-link`).
- A malformed `%` escape in a request no longer kills the API worker thread.

### Added

- Windows installer (`Varsto-<version>-setup.exe`, Inno Setup, spec 63):
  per-user in `%LOCALAPPDATA%\Programs\Varsto` without administrator rights
  (or for all users with elevation), Start menu and desktop shortcuts with the
  Varsto icon, the background service and tray at login, an uninstaller that
  keeps the data folder unless asked, and a check for the Microsoft Edge
  WebView2 Runtime. Running the installer again upgrades or repairs the
  installation in place: it closes the window, tray and service, replaces the
  files and starts Varsto again; a downgrade needs a confirmation (and is
  refused when silent). The portable zip stays, now with the window program.
  [docs/windows.md](docs/windows.md).
- Varsto's own window on Windows (`varsto-window.exe`, WebView2 through `wry`
  and `tao`): the local interface in a native window with the Varsto icon, one
  window per user (a second launch focuses it), size and position remembered,
  closing it leaves the service and tray running, and the tray's "Open Varsto"
  opens it. Without WebView2 the interface opens in the default browser and a
  message says how to install the runtime. Linux and macOS are unchanged.
- Automatic updates: the service looks for a new version once a day and, on
  Windows, installs it by itself (the installed copy downloads the signed
  `Varsto-<version>-setup.exe`, checks it like every archive and runs it
  silently from a private folder); elsewhere it shows a notification. Switch
  it off in the interface (Settings, Service) or with
  `varsto config auto-update off`. New command `varsto config`.
- Windows notifications from the service (toast), for example "update
  available".
- Tray: one tray per device directory and Windows session.

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

[0.0.1-alpha.15]: https://github.com/janttsu/varsto/releases/tag/v0.0.1-alpha.15
[0.0.1-alpha.14]: https://github.com/janttsu/varsto/releases/tag/v0.0.1-alpha.14
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
