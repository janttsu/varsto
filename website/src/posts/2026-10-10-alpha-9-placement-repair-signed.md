---
title: Alpha.9: data where you want it, repair by itself, signed updates, and every platform built in the open
date: 2026-10-10
summary: Folders can be placed on chosen storages and moved between them, lost copies are repaired automatically, updates are signed with an offline key, peer-to-peer downloads fetch many blocks at once, and every package is now built, tested and photographed on GitHub's runners.
---
Alpha.9 is about the long run: deciding where data lives, getting it back to the copies your policy asks for without being told, and trusting the update that brings the next version.

## Data where you want it

Each folder can now have a placement: the storages its blocks go to. Data can be moved from one storage to another (a whole folder, or only files idle for a number of days), block by block, each block written and read back on the new storage before the old copy is deleted, and an interrupted move simply continues when run again. A pool of removable disks can ask for copies on disks kept in different places, such as one at home and one at work, and Varsto fills each disk with what its place still lacks.

## Repair by itself

When a copy goes missing, a storage is removed or a verification fails, the device that holds the data puts the block back where the folder's policy and placement want it, from its own files, the encrypted block cache, another storage or a peer. The repair queue is visible in the interface and with `varsto repair`.

## Signed updates

Every release's checksum list is now signed with the project's release key, which never leaves the maintainer's machine, and the updater refuses a release that is not signed with it. It also compares the checksum with the one attached to the GitHub release, a second channel. `varsto verify-release` checks a download by hand, and so does `minisign`. [RELEASING.md](https://github.com/janttsu/varsto/blob/main/RELEASING.md) explains the scheme.

## Faster peer to peer

Downloads keep up to eight blocks in flight, fetch small files ahead across a folder and share one connection per peer; a device that serves blocks no longer starts a full sync of its own every few seconds. The [benchmarks](../benchmarks/) compare Paris, Amsterdam and Warsaw, peer to peer against an S3 bucket.

## Built in the open

Every platform is now built and tested on GitHub's runners on every change: the Linux and Windows packages (the Windows one tested on Windows Server 2025, including the Explorer menu entries), the Android app in the emulator, the macOS disk image and the iOS app on Apple Silicon. The same runs take the [screenshots](../screenshots/), so the pictures on this site follow the newest build.

## And more

Sharing records who asked for access by fingerprint, removing a member moves the share to new keys, and a Strongroom can be re-keyed; files can be downloaded or freed from the file manager on Linux (Nautilus, Dolphin, Nemo) and Windows (Explorer); folder rows keep their two main buttons and put the rest in a menu; the macOS app and the phone apps say when a newer version waits on the download page instead of calling themselves up to date; and large ledger batches no longer fail on S3.

## Update every device before moving data

Moving data writes a new kind of ledger entry that alpha.8 and earlier cannot read: their syncs would fail from the first move on. Update all your devices first. From this version on, unknown entries are skipped, so later additions will not break it. Clients up to alpha.8 check only the checksum when they update; this release is the first whose updater insists on the signature.

## Still alpha

The cryptography has not been audited, the format may still change, and a bug can destroy data. Use test data and keep your own backups.
