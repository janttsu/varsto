---
title: Alpha.17: notifications and a safer sync, on the same vaults
date: 2026-11-22
summary: Phone notifications, pulls that reuse blocks you already have, and a set of fixes for deletions, backups, credentials and the first connection. The storage format is unchanged, so alpha.16 vaults open as they are.
---
Alpha.17 does not change the storage format. A vault made by alpha.16 opens as it is, on every device that updates. There is nothing to recreate and no new set of words. This is still an alpha: not for production data. The full list is in the changelog.

## Notifications

A device can send alerts to your phone through ntfy, Pushover or Telegram. Add a channel in Settings or with `varsto notify`: each service has a short guide, a test message, and a choice of what it receives. You can leave folder, storage and device names out of the text. Alerts are on by default: storage problems, low space, fewer copies than a policy asks, damaged data, a failed or overdue backup, and a request waiting for you. Finished backups, new files and a daily summary are opt-in. The tokens stay on the device (`notify.json`, mode 0600) and are never synced. The messages are not end-to-end encrypted on the way through the service. A failed send waits and is tried again, also after a restart. Repeats of the same alert are dropped for six hours, and a channel gets at most 20 messages an hour. The settings work while the vault is locked.

## Pulls, peers and the first connection

A pull copies blocks this device already has instead of fetching them again. The unchanged blocks of a changed file come from its previous version on disk, a renamed or moved file comes from the old path or from trash, and duplicate files fetch each distinct block once. A block read locally is checked against its chunk id, and one that does not match is fetched. A device that has just put a file in place serves it to the others at once, not only after its own sync ends, and block requests are shared among the peers that hold them.

The first connection to a device that has not yet read this device's certificate is shown as connecting and tried again at once. A later refusal waits a few seconds and is shown as unreachable. A device that has never answered no longer waits a minute and then up to 15 minutes before the first real try. While that first sync is running, a folder that still lists no files is shown as fetching, not as an empty folder that is already done.

A peer that was answering and then fails rests a second, doubling per failure, instead of a minute, and a block no other peer has is asked of it once more. A sync right after a peer restarted asks it again: a newer peer record, a LAN beacon or an explicit sync ends the rest. Devices that are gone rest longer, and the head exchange asks up to eight of them at once.

## Deletions, packs and backups

A pull that fails no longer publishes deletions of files this device has not read. Local additions and edits are still pushed. The next pull fetches copies the other devices still have before a missing file can be published as deleted.

In a conflict that another device's version wins, the file here moves to its conflict copy only once the winner is downloaded. A file that grows or shrinks while the scan reads it waits for the next scan instead of being published with a size its blocks do not hold. With `permissions` off, a downloaded file gets this device's default mode.

Unclaimed packs are deleted after 48 hours, or after 24 hours when a local storage is under 10 % free, not after 7 days. A push, import or backup whose map record is not published deletes the packs it just wrote. A repair whose batch was not sealed does the same. A seal that fails after the map record was published keeps the packs. `varsto gc orphans` deletes unclaimed packs immediately.

Backup retention never removes the newest snapshot of a backup, whatever its age. Stopping the backup lets that last snapshot expire as before.

## Names, clocks and credentials

Two processes on one device, the command line and the background service, can no longer hand out the same Lamport value. Reserving one holds `state/clock.lock` across the read, the raise and the replace.

Two devices writing one vault or folder epoch number no longer stop signing until a manual choice. The device that sees both records keeps the greater issuer id. `varsto device resolve-epoch` and `varsto folder resolve-epoch` still replace that choice.

On a case-insensitive disk, two paths that differ only in case or Unicode normalisation get the same local names whichever is written first. The NFC spelling wins a tie, then the smaller original path keeps the plain name and the other is ` (2)`.

After a device is removed, `varsto status` and `varsto device list` name every storage whose credentials that device could still use to delete ciphertext. `varsto storage mark-rotated <name>` clears the warning once you have replaced the credentials at the provider. Varsto does not change them itself.

## Requests, the recovery kit and logs

`varsto share request` and `varsto org request` keep the request's private keys sealed under the device passphrase, not in a clear JSON file a copy of the device directory could be read from. The command and the "Show my request code" card ask for the passphrase, and accepting the request needs the same one. A request left in clear by alpha.16 is sealed the next time a command reads it.

`varsto recovery kit` prints the format 3 kit: the vault words and the recovery words. It used to print the format 2 text, which said the 24 vault words read everything in the vault. In format 3 they open device and folder names and the storage ledger only. A kit printed without the recovery words says so in capitals. `--shares` splits both word sets.

The log scrubber removes a secret the way debug output prints an optional or wrapped value, and the passphrase, the device signing key and the folder keys are registered with it on every unlock path. Before, the service could run for days with no passphrase registered.

## Phones and the default policy

Pausing the background service stops peer-to-peer as well: the listener, the LAN beacon, the rendezvous, the relay and the router mapping stay stopped until you resume. A pause you set survives a restart of the service. The short pause that `varsto disk` and an import take for their own duration is not saved.

Thumbnails in the file list show on phones again. When the engine is busy the service answers "busy" and the page retries, instead of treating that as "no thumbnail".

The default policy no longer reports a folder as violated in a vault that has no disk pool and no directory storage. The folder gets one warning that there is no copy on your own disks and how to add one. A policy you set on purpose that asks for a copy at home is still held to it. The same waiver applies to the import check that decides when a source may be removed, so that folder no longer waits forever for a copy on your own disks.

Fetching, freeing, writing and moving a file, and the other folder commands, take the same lock a sync does, so a command and the background service no longer undo each other's folder state. A download or a write that fails no longer leaves a `.varsto-tmp-…` or `.varsto-upload-…` file with part of the content in the folder.

Files that arrive from another device keep the modification time their writer recorded. They used to be dated when they were downloaded.

## Membership

A removed device's folder records, grants and escrow count only up to the first sequence number it had left empty, so it cannot fill a gap below its cut-off with a backdated record. A member device of another vault applies a removal from the folder epoch record. A folder the remover could not re-key is re-keyed at the next sync of an owner device that holds its key. What the removed device already holds, it keeps.

Joining a vault reads the organization's manifest and adopts vault epochs and revocations only from its administrators. A roster member's revocation no longer opens the vault for a device that is joining.

The activity log's "holds no key" line has the same access button as the folder row, so a phone can ask for the folder from that line. The restic mirror and the folders under it are created so only this user can reach them.

## Application ids

Application identifiers are `net.varsto.app` (Android and macOS), `net.varsto.app.ios` (iOS) and `net.varsto.app.alpha` (the unsigned macOS alpha). An already installed app keeps its previous identifier until it is installed again, and its vault is not moved.

## Compatibility

Alpha.17 reads and writes the same storage format as alpha.16. Update the devices when you like. They can share a vault across the two versions while you do. This is still an alpha: not for production data.
