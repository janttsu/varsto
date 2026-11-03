---
title: Alpha.16: storage format 3, folder access by approval and a rendezvous service
date: 2026-11-03
summary: A new storage format with a pack-level ledger, signed records and recovery words, so existing vaults must be recreated; folders are opened to a device by an owner's approval; devices find each other through an optional rendezvous service; joining and membership changes work offline; and imports from torrents and YouTube.
---
Alpha.16 changes the storage format again. That is the main thing to know before updating: vaults made by alpha.15 or earlier cannot be opened by this version and have to be recreated. The rest of the release is a long list of changes in how devices join, find each other and cope with a bad network, a new Import page, and a large set of fixes and hardening from a review of the new format.

## Recreating a vault

There is no migration. Alpha.16 refuses an older vault when it opens it or when a device joins through its storage, and the message says what to do. Alpha.15 refuses a format 3 vault in the same way, so the two versions cannot share a vault in either direction. Every device of a vault must run alpha.16. Keep your files where they are, then:

1. Keep the alpha.15 binary around if you may need to read the old vault.
2. `varsto reset --yes` on the device, then `varsto init`. It prints a kit with two sets of words: the vault words and, new in format 3, the recovery words. Store both.
3. Add the storages again, add the folders (the recovery words are asked for here) and sync.

## Android: uninstall the old APK first

The Android package is now a release-signed APK (`varsto-<version>-android.apk`), not a debug build, so a later release installs over it as an update. It is signed with a new key. An installation of an earlier debug APK (alpha.15, or an older daily build) cannot be updated to it: Android refuses the update. Uninstall the old app first and then install the new one. Uninstalling removes that device's copy of the vault, so make sure the vault has another device or a storage before you do. The daily Android download stays a debug build under the name `varsto-daily-android-debug.apk`.

## Storage format 3

Format 3 is described in section 77 of the spec and in the format 3 design document. What it changes for a user:

- The ledger no longer lists every block. It claims packs of a few fixed sizes (256 KiB to 64 MiB, padded), so a storage sees size classes and not how many blocks or files there are.
- Every published object other than a pack is a signed record that names the key it is sealed with. Manifests, trash lists and snapshots are a base plus small deltas, and each folder keeps a signed block map per writing device.
- A folder key reaches a device only as a grant that an owner approved. A device that joins with the vault words sees folder names and holds no content; it asks with `varsto folder request`, an owner compares six words shown on both devices and approves with `varsto folder approve` (also `requests`, `deny`, `members`, `role`). The background service never approves. The interface has a Folder access card on the Files page.
- Every folder key epoch has a recovery copy under the recovery words. `varsto folder add` makes it, `varsto recovery escrow` writes a missing one later, and `varsto status` warns until then. `varsto join --recovery-words` opens every folder that has a recovery copy.
- Peers talk TLS only, with tokens bound to the connection, and compare ledger heads, so a storage that withholds or rolls back batches is noticed and the Help page and a notification say so.
- Removing a device now sticks: a revoked device is not granted the next folder key, and its records stop counting at the removal.

## Finding each other: the rendezvous service

Devices can find each other across networks through an optional rendezvous service, by default `https://varsto.net/rv`. A device leaves its sealed peer record there, reads the vault's records, learns its own public address and, when no address answers, reaches a peer through a coordinated hole punch or, as the last route, an end-to-end encrypted relay (shown as `relayed via rendezvous`). A joining device that finds nothing on its network can look up an offer by code or link and pair through the relay. The service sees tags, IP addresses and byte counts, never vault identity or content. `varsto p2p rendezvous set <url> | on | --off | status` or the Peers page changes it, and the server can be self-hosted (`varsto-rendezvous`, a static Linux binary in the daily build; the default UDP port is 3334). Everything also works without it.

## A bad network and working offline

- One storage that cannot be reached no longer fails a whole sync. It is marked down for the run and rests between runs, and the other storages carry on; what it missed is copied there later.
- S3 and rclone calls have time limits that fit the size of the transfer, retries and resumable multipart uploads, so a slow link costs seconds, not minutes.
- Peer-to-peer works without any storage, from a saved peer directory, so LAN sync works with no internet.
- Joining by pairing no longer needs a storage to answer, and membership changes (adding a folder, approving, changing a role, sharing) are kept on the device first and sent when a storage answers. `varsto status` says "N changes waiting to upload".
- Local actions (imports, the Trash page, thumbnails, file writes) finish while a storage is down and report "upload pending".
- The interface, tray, command line and MCP no longer freeze while a sync waits on a dead link.

## Imports

- One Import page for every source (a folder or disk, a git-annex repository, a cloud drive through rclone, a torrent, YouTube), with a list of the imports in progress.
- `varsto import torrent` imports torrents larger than the disk in batches that keep a free-space reserve; a file leaves the download disk only once its blocks are on a storage and the folder's policy holds.
- `varsto import youtube` archives channels, playlists and videos into folders with yt-dlp, with polite defaults and a free-space reserve.

## Disks and servers

- `varsto mailbox` stages blocks from a docked disk for a pool disk or storage that is away, in a durable, hash-checked outbox, so a block only on disk A reaches disk B when B is docked.
- `varsto service remember` works without a desktop session (over SSH, on servers) through `systemd-creds` or the kernel keyring; `varsto service forget` removes it.
- `varsto service stop` now stays stopped, and a self-update still restarts the service.

## Fixes and hardening

- Pull no longer overwrites a file edited after the scan, and one bad file no longer stops a folder's pull or push. An unreadable file or directory is counted instead of making files under it look deleted.
- Membership: removal of a device holds for later joiners and for folders that were not re-keyed, and only an administrator's epoch, revocation or wipe is adopted.
- Drain, storage removal and the tidy after a disk insert keep any pack that may be the only copy. Repair, push after a missing batch and attach after detach are corrected.
- S3 range reads no longer make `fsck` call every pack short.
- The visualization shows a loading note or an empty-vault note instead of the example scene, and thumbnails show in the page.
- TLS handshakes have a deadline that holds, and an address can hold at most 64 unfinished ones. A stalled local client can no longer freeze the local API. The rendezvous server has a rate limit per request class and bounded memory for lookups. Dependency advisories reported by `cargo audit` are patched.
- The GitHub workflows run with read-only permissions except where they publish.

## Compatibility

Every device of a vault must run alpha.16. Alpha.15 cannot read an alpha.16 vault and alpha.16 cannot read an alpha.15 vault. Update all devices together and recreate the vault as described above. This is still an alpha: not for production data. The full list is in the changelog.
