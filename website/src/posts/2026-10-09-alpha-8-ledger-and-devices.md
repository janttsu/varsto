---
title: Alpha.8: a ledger that stays small, removable devices, and phones that keep nothing in clear text
date: 2026-10-09
summary: The ledger now lists only what is new, keeps a cached view and prunes itself behind signed checkpoints; devices can be removed with new keys for everything written afterwards; phones keep encrypted folders as encrypted blocks; and the interface shows where your data is and how peer-to-peer traffic flows.
---
Alpha.8 came out of a long day of using alpha.7 on a Mac, a Linux desktop and a Samsung phone, and of asking what happens to the design after a few years of use.

## A ledger that stays small

Every device keeps a signed, encrypted log of facts: which block it stored where, which copy it verified, which file list it published. Until now every entry stayed forever, as its own object on every storage, and every sync listed all of them. Now a sync lists only what is new, the device keeps a cached, encrypted view instead of replaying everything, one sync writes one batch, and each device periodically writes a signed checkpoint. Once all your devices have acknowledged a checkpoint, the batches behind it are deleted, keeping the last few so that a device restored from an old backup is still caught. In a test vault with 20 000 batches, a sync with nothing new went from 668 ms to 28 ms and the ledger on storage from 171 MB to 5 MB. The [How it works](../how-it-works/) page explains the ledger.

## Removing a device

A lost phone or a laptop you no longer use can be removed from any other device (Settings or Peers, "Remove…", or `varsto device revoke`). Its later entries are ignored, your devices refuse its connections, and the vault moves to new keys that only your remaining devices receive, so nothing written afterwards opens with what the removed device holds. You can also order it to wipe itself the next time it reaches a storage. The device list shows each device's system, model, Varsto version and last sync.

## Phones keep encrypted folders encrypted

A folder kept "encrypted on this phone" now holds only encrypted blocks, the same bytes your storages hold. Selective sync works as everywhere else; files are shown in the app's own viewer, decrypted in memory, and handed to another app only when you ask, as a temporary copy that is removed when the vault locks. Android can upload new photos and videos to a folder of your choice.

## Seeing what happens

- **Where your data is**: a chart from folders to storages and devices, with how many copies everything has.
- **Peer-to-peer traffic**: which device sends what to which, over which path, at what speed.
- **Automatic verification**: another device re-reads your blocks on a schedule, so a policy such as "verified within 30 days" holds by itself.
- Buttons show at once that something started, and downloads show their progress.

## And more

Strongroom folders can be converted from existing ones and get a backup security key; storages can be removed after their blocks are copied where needed; folders can be detached or removed from the vault, and top-level names are unique; transferrer disks can be given a destination device; storage prices feed cost estimates and one-click freeing of idle files; the assistant (MCP) can never delete or overwrite files; and on Linux the first start installs Varsto for your user, with a background service that keeps syncing for command-line users too.

## Still alpha

The cryptography has not been audited, the format may still change, and a bug can destroy data. Use test data and keep your own backups.
