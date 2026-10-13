---
title: Alpha.13: backups that nothing can change
date: 2026-10-13
summary: Pick a folder on any device and Varsto keeps encrypted, read-only snapshots of it on your external storages, never on your devices, for as many days as you choose (90 by default). Restores go into a directory you name, from the app or the command line.
---
Synchronisation keeps every copy the same, which is exactly what you do not want when a file is deleted by mistake or encrypted by ransomware: the damage reaches every device. Alpha.13 adds backups, which work the other way round.

## How it works

You pick a folder on one device and give the backup a name. Varsto takes a snapshot of it: the file list and every block, encrypted like everything else it stores. Snapshots go only to external storages (S3 buckets, rclone remotes, NAS shares, directories and cold storage), never to transferrer disks and never to your other devices. Your other devices see that the backup exists and which snapshots it has, but they do not download its contents.

```
varsto backup add accounting ~/Accounting --retention-days 90
varsto backup list
varsto backup snapshots accounting
varsto backup restore accounting 2026-10-01 --to ~/restored
```

Snapshots are taken daily by default, weekly or only when you ask (`varsto backup take`). Blocks that did not change are stored once, however many snapshots use them.

## Read-only and kept for a set time

A snapshot is never edited after it is taken. Its expiry date is sealed inside it when it is written, so changing the retention later only affects new snapshots. Once a snapshot has expired, the device that made the backup deletes it from the storages. Only blocks that no remaining snapshot needs are deleted, and a day of grace allows for clocks that are a little off. If that device is gone, any other device of the vault does it a little later. Stopping a backup takes no new snapshots but deletes nothing early.

## Restoring

A restore always goes into a directory you name, and that directory must be empty unless you allow overwriting. You can pick the newest snapshot, a numbered one or the newest one on or before a date, and restore everything or only some paths. The app has a Backups page that does the same.

## Details and limits

The format is in section 31 of the [specification](../docs/alpha-0-format.html). In this first version, expiry follows each device's own clock, durability policies do not cover backups yet, and the data-locations view does not show them.

Older versions do not understand backups: update every device of a vault to alpha.13 before adding one.
