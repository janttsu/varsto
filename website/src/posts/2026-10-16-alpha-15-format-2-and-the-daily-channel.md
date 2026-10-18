---
title: Alpha.15: storage format 2, a Windows installer and a daily channel
date: 2026-10-16
summary: A new storage format that fixes two findings of the security review, so existing vaults must be recreated; Windows gets a setup program, a native window and automatic updates; and a signed daily build channel.
---
Alpha.15 changes the storage format. That is the main thing to know before updating: vaults made by alpha.14 or earlier cannot be opened by this version and have to be recreated. The rest of the release is a long list of fixes and interface work, a proper Windows installation, and a daily build channel for people who want to test the newest code.

## Format 2 and what it means

The security review behind alpha.14 found two problems in how blocks were stored that could not be fixed without changing the format. Format 2 fixes them:

- The nonce of an encrypted block is now derived from the exact bytes that are encrypted (after compression), not from the plaintext. Before, the nonce depended on a compression result that was not guaranteed to be the same across zstd versions.
- The chunker is keyed per folder. Cut points used to be a public function of the file content, so a storage that knew a file could recognise it from the sizes of its blocks. Now the same file in two folders is cut at different places.
- Every block is stored in a pack (64 MiB, 256 MiB on cold storages) and no block is an object of its own, so a storage sees pack sizes and not the sizes or number of blocks inside them. Packs have encrypted indexes, and deleted blocks are tracked per folder and rewritten away.
- Compression is zstd level 3 after a quick probe: text compresses almost as well as before and is several times faster to write.

What format 2 does not fix: file lists and share epochs are still accepted on the folder key alone, because closing that needs signed manifests and share epochs, which belong to the records layer of the next format. Until that exists, a holder of a folder's key can still change what that folder shows, and untrusted replicas and shared folders should be treated that way. Both critical findings remain open in alpha.15.

**Recreating a vault.** There is no migration. Alpha.15 refuses an older vault when it opens it or when a device joins through its storage, and the message says what to do. Keep your files where they are, then:

1. Keep the alpha.14 binary around if you may need to read the old vault.
2. `varsto reset --yes` on the device, then `varsto init`.
3. Add the storages again and sync the folders.

Alpha.14 refuses a format 2 vault in the same way, so the two versions cannot share a vault in either direction.

## Windows: the installer, a native window and automatic updates

The portable zip is gone. Windows now has one download, `Varsto-<version>-setup.exe`: it upgrades in place, can repair an installation, and its uninstaller keeps your data folder. The interface opens in a native window (WebView2) with its size and position remembered, one window per user, and the tray starts it. Copies installed by the setup program check for updates once a day, verify the signed setup program and install it silently. If you still run an unzipped portable copy, `varsto update` tells you to run the installer once; updates continue by themselves after that.

## Everything else since alpha.14

- A folder overview with a safety indicator per folder: 100 % in external storage, 100 % on your own disks only, partly protected, or only on devices.
- A live visualization of devices, storages, disks and the cloud with animated flows, and real full screen in the browser and in the Android, macOS and Windows shells (Esc leaves it).
- Forwarding: a device attached to a folder, even with selective sync, can carry other devices' blocks to the storages it can write, so a phone's photos reach a bucket that only the laptop has credentials for. The attach dialog now asks for full or selective sync and the direction.
- Pairing offers every usable local address, best first, and joining falls back across them and a search of the local network, with visible progress and an error that names what was tried.
- New data gets a grace period before verification reports a violation: blocks stored within the larger of the verification window and 24 hours show as "verification pending".
- The interface stays usable during long syncs: reads are answered from the last kept answer when the service is busy, lists are drawn incrementally, and the page is never reloaded.
- Fixes: draining and placement now refuse contradictory choices, thumbnails for storages added later, phones accept S3 and rclone storages only, photos and videos already on a phone are backed up newest first, printing the recovery package, the macOS Dock icon, Android Back and the keyboard, `reset` and service restarts, and drive initialisation with a modern GPT layout.
- An unsigned iOS `.ipa` for AltStore, SideStore and Sideloadly.
- The website has a French translation, and the Finnish and Swedish pages show screenshots of the interface in their own language.

## The daily channel

`varsto update --daily` installs the newest daily build of the main line. Daily builds are made for all platforms whenever the main branch moves and are published at varsto.net/daily/. The checksum list is signed with a daily key that is separate from the release key: the updater trusts each key for its own channel only, so a daily signature never validates a release, and the other way round. It also refuses lists that are stale, from the future, or older than the build you run. The background updater and the interface stay on releases; the daily channel is only ever started by hand.

Daily builds are development builds. They are not for production data, and a daily build can carry a storage format change before any release does.

## Compatibility

Every device of a vault must run alpha.15. Alpha.14 cannot read an alpha.15 vault and alpha.15 cannot read an alpha.14 vault, and neither reads the other's packs or tombstone lists. Update all devices together and recreate the vault as described above.
