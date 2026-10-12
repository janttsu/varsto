---
title: Alpha.12: small files in packs, and Varsto in Finnish and Swedish
date: 2026-10-12
summary: Small encrypted blocks are now written in packs, so a folder of 20,000 small files becomes 79 objects on a bucket instead of 20,000. The interface, tray, menu bar, mobile shells and this website are available in Finnish and Swedish as well as English.
---
Alpha.12 has two themes: fewer objects on your storage, and the interface in more languages.

## Small blocks in packs

Until now every encrypted block was its own object on the storage. That is simple and robust, but a folder of many small files, such as notes, source code or a photo library's sidecar files, turns into tens of thousands of tiny objects. Many providers charge per request, some per object, and listing and checking them all is slow.

From this version, blocks up to 128 KiB are collected into packs of about 4 MiB or 256 members. A pack is written with an index that names its members and where each one starts, and a member is read with a ranged request, so reading one small file still downloads only its own bytes. Large blocks are still written one by one. Packs are used on S3 buckets, rclone remotes and directories; cold storage, disk pools and transferrer disks keep single objects.

In the lab, a folder of 20,000 small files went to the bucket as 79 packs instead of 20,000 objects. Every member was checked against its name after the run.

Deleting a block that lives in a pack writes a small deletion marker, and the pack itself goes once every member is gone. Repair, verification, replicas, data moves and storage removal all understand packs. The storage format is described in section 30 of the [format specification](../docs/alpha-0-format.html).

There is no compatibility with older versions: a device on alpha.11 or earlier does not see blocks in packs. Update every device.

## Fixes found on the way

The lab runs found problems that unit tests had missed:

- `rclone serve s3` answers a ranged read with status 200 and only the requested bytes. Varsto now accepts that as well as the usual 206, so packs read correctly from such servers.
- A device that had just read the pack indexes did not look again for packs another device wrote moments later. A read that misses now reloads the indexes at once.
- A device could trust a pack index after another device had deleted members from it. Before deciding that a block already exists and need not be written, Varsto now checks that it is still in its pack.
- Disk pools and other storages without packs write their blocks one at a time again, so a full or missing disk is reported as such instead of failing the whole push.
- An S3 server with the clock more than a few minutes off is now corrected in both directions, also when it answers with status 400 instead of 403.

## Finnish and Swedish

The desktop interface, the tray and the macOS menu bar, the Android and iOS shells, and this website are now available in Finnish and Swedish. English stays the default. The language is chosen in the interface's settings or at the bottom of the sidebar, and the tray and the apps follow the same choice. The command line, the documentation and everything in the repository stay in English.

Translations of the safety-critical texts, such as those about deleting, revoking devices and recovery words, are marked for review by native speakers. Corrections are welcome.

## Building Varsto with us

The new [Contribute](../contribute/) page describes how Varsto is built and where help is wanted: a review of the cryptography and the storage format, Windows, iOS and Android, NAT traversal on networks other than the maintainer's, more S3 providers, packaging and translations.
