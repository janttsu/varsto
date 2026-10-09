---
title: Alpha.7: pair devices with a code, Finder actions, and a real NAT path
date: 2026-10-09
summary: Devices now pair from the interface with a one-time code, Finder can download a placeholder or free up space with a right-click, the macOS app installs from a disk image, devices reach each other through NAT, and removable disks can form a pool.
---
Alpha.7 is mostly the result of using the alpha on real devices for a day: a Samsung phone, a Mac and a test bucket. Each section below started as something that did not work the way it should.

## Pair a device with a code

Adding a device used to mean copying a 64-character vault key and typing the settings of a storage both devices can reach. Now the device that already has the vault shows **Add a device** under Devices: a code of nine digits that works once, for ten minutes. On the new device you choose **Pair with your other device**, type the code, a name and a passphrase, and that is all.

The two devices find each other on the local network, run SPAKE2 keyed by the code (a wrong guess cannot be checked offline, and three wrong codes close the offer), confirm the key in both directions, and only then does the vault key travel, with the storage settings and their secrets, sealed under the shared key. The new device joins through the first storage it can reach. If it is not found on the network, the address shown under the code works too. The same flow exists on the command line: `varsto pair offer` and `varsto pair join`.

## Finder knows about placeholders

On macOS, right-click files for **Download with Varsto** or **Free up space with Varsto**, and double-click a placeholder to download the file and open it. Freeing space is refused unless every block is on a storage *and* the file on disk is the version that was synced; before this release a file edited after the last sync could have been replaced by its placeholder. The macOS download is now a disk image: open it and drag Varsto to Applications.

## Devices reach each other through NAT

Peer-to-peer transfer used to work on the LAN and through forwarded ports. Now devices learn their public address with STUN, punch through NAT over QUIC with a certificate pinned per device, and fall back to relaying through one of your own reachable devices. It was tested between a home network and a cloud machine behind its own NAT, both ways, and with UDP blocked to force the relay.

## Pools of removable disks

A storage can be a pool of removable disks: Varsto fills them by free space with a reserve, knows which disk holds which block, asks you to attach a specific disk when it needs one, and counts an offline disk as a copy as of its last check.

## Smaller things

- Durability policies are edited for every folder in one table on desktop, and the full rule and its reasons are visible.
- On a phone you can add files and subfolders, open a file in another app or share it, and keep a folder as plain files in internal storage instead of encrypted.
- The file details say whether this device has the file and which storages hold it.
- The window follows a pause or a sync started from the menu bar.
- Joining accepts the 24 recovery words as well as the hex key.

## Still alpha

The warning on every page stands: the cryptography has not been audited, the format may still change, and a bug can destroy data. Use test data and keep your own backups.
