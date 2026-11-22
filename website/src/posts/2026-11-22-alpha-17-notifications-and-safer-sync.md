---
title: Alpha.17: the vault stays, the quiet mistakes go
date: 2026-11-22
summary: No new storage format and no new words to write down. Alpha.17 is the release that stops a failed sync from deleting files, keeps the last backup, and tells your phone when something is actually wrong.
---
You can update this one without a ceremony. Alpha.17 opens an alpha.16 vault as it is. There is no new format, no second set of words, and nothing to recreate. What changes is the sort of mistake that used to happen while you were looking at something else.

A pull that never finished could still publish deletions of files this device had not read. The newest snapshot of a backup could age out and take the only restorable copy with it. The first meeting with another device could sit there for a quarter of an hour looking dead. Those are the things this release is for. It is still an alpha, and it is still not for data you cannot afford to lose. The long list is in the changelog. The parts you will actually notice are below.

## Your phone hears about it

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/notify-dark.webp"><img src="../assets/img/blog/notify-dark.png" alt="A laptop sends a low-space alert about the Documents folder to a phone. The vault itself stays on the computer." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/notify.webp"><img src="../assets/img/blog/notify.png" alt="A laptop sends a low-space alert about the Documents folder to a phone. The vault itself stays on the computer." width="640" height="320"></picture>
</figure>

A device can now tell your phone, through ntfy, Pushover or Telegram, when something wants a person. Add a channel in Settings or with `varsto notify`. Each service has a short guide and a test message, and you choose what it is allowed to say. Folder names, storage names and device names can stay out of the text.

The alerts that matter are on unless you turn them off: a storage in trouble, a disk running out of room, fewer copies than a policy asks for, damaged data, a backup that failed or is overdue, a request waiting for you. Finished backups, new files and a daily summary stay quiet until you ask for them. The tokens live on the device, in `notify.json`, and are never synced. The message itself is not end-to-end encrypted on the way through ntfy, Pushover or Telegram, which is worth knowing before you let it name a folder. A failed send waits and is tried again, including after a restart. The same alert is not repeated for six hours, and a channel gets at most twenty messages an hour. You can set this up while the vault is locked.

## A pull that already has the bytes

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/reuse-dark.webp"><img src="../assets/img/blog/reuse-dark.png" alt="Ciphertext blocks stay on the laptop. A single link carries only the missing blocks to a locked cloud." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/reuse.webp"><img src="../assets/img/blog/reuse.png" alt="Ciphertext blocks stay on the laptop. A single link carries only the missing blocks to a locked cloud." width="640" height="320"></picture>
</figure>

Most of a changed file was already here. Alpha.17 stops fetching those blocks again. The unchanged pieces of a changed file come from the previous version on disk. A rename or a move comes from the old path, or from the trash if that is where it went. Two copies of the same file fetch each distinct block once. Anything read locally is checked against its chunk id, and a block that does not match is fetched after all.

The other half of that is the device that just wrote the file. It serves each file it has put in place to the others immediately, not only after its own sync has ended, and the requests are shared among the peers that actually hold the blocks.

The first time this device meets another one, before that device has read this certificate, the path is shown as connecting and tried again at once. A later refusal waits a few seconds and is shown as unreachable. A device that has never answered no longer spends a minute, and then up to fifteen, before the first real try. While that first sync is still running, a folder with no files yet is shown as fetching. It is not an empty folder that is already done.

A peer that was answering and then fails rests a second, and the rest doubles, instead of a flat minute. A block nobody else has is asked of that peer once more. If the peer restarts, the next sync, a newer peer record or a LAN beacon ends the rest instead of reporting every file unavailable. Devices that are simply gone rest longer, and up to eight of them are asked together, so they cost one timeout instead of eight.

## What a failure is no longer allowed to do

A pull that fails no longer publishes deletions of files this device has not read. What you added or edited here is still pushed. The next pull fetches the copies the other devices still have before a missing file can be declared gone.

If another device's version wins a conflict, the file here moves aside only once the winner has actually arrived. A winner that could not be fetched used to leave the path empty, and the next push then published a deletion of it. A file that grows or shrinks while the scan is reading it waits for the next scan. It is not published with a size its blocks do not hold, which used to make every other device refuse the folder's whole list.

Unclaimed packs are deleted after 48 hours, or after 24 when a local storage is under 10 percent free. It was seven days. A push, an import or a backup whose map record never got published deletes the packs it just wrote, and so does a repair whose batch was not sealed. If the seal fails after the map record was published, the packs stay, because the claim is already in the ledger. `varsto gc orphans` deletes unclaimed packs now, if you would rather not wait.

The retention of a backup no longer eats the newest snapshot just because it is old. A lost source directory, or a device that never took a newer one, used to expire that snapshot on schedule and then collect its blocks, and there was nothing left to restore. Stopping the backup still lets the last snapshot expire. That part is unchanged, and it is the way you say you are done with it.

## Clocks, names, and a key that outlived the device

Two processes on one machine, the command line and the background service, can no longer reserve the same Lamport value and then both hand it out. The reservation holds a lock across the read, the raise and the replace.

Two devices writing the same vault or folder epoch number no longer stop signing until a person chooses. The device that sees both records keeps the one with the greater issuer id. `varsto device resolve-epoch` and `varsto folder resolve-epoch` still replace that choice when you want a different one.

On a disk that ignores case, two paths that differ only in case or in Unicode normalisation get distinct local names whichever one arrives first. The NFC spelling wins a tie. Then the smaller original path keeps the plain name, and the other becomes ` (2)`.

Removing a device does not, by itself, change the password at the storage provider. What it does now is refuse to forget. `varsto status` and `varsto device list` name every storage whose credentials that device could still use to delete ciphertext. When you have replaced them at the provider, `varsto storage mark-rotated <name>` clears the warning. Varsto does not rotate the secret for you.

## The words on paper, and the keys that used to sit in a file

`varsto recovery kit` prints the format 3 kit: the vault words and the recovery words. It used to print the format 2 text, which told you that the 24 vault words read everything in the vault. In format 3 they open device names, folder names and the storage ledger. Content needs the recovery words. A printout made without them now says so in capitals, instead of looking complete. `--shares` splits both sets.

A share request and an organization request used to keep their private keys in a clear JSON file. A copy of the device directory, taken while the request was waiting, could read them, and once the owner approved, open the folder with no passphrase at all. The keys are now sealed under the device passphrase. Showing the request code asks for it, and accepting the request asks again. A request that alpha.16 left in the clear is sealed the next time a command reads it.

Logs get the same treatment for the way a debug printer writes an optional value. A line like `password: Some("…")` used to be cut at the quote and leave the secret in the rest of the line. The passphrase is registered with the scrubber on every unlock path, including the service coming back from the keyring. Before, that service could run for days with nothing registered.

## A pause that means paused

<figure class="shot">
<picture class="theme-dark"><source type="image/webp" srcset="../assets/img/blog/pause-dark.webp"><img src="../assets/img/blog/pause-dark.png" alt="A paused phone between a home laptop and an office NAS. Both links are marked off." width="640" height="320"></picture>
<picture class="theme-light"><source type="image/webp" srcset="../assets/img/blog/pause.webp"><img src="../assets/img/blog/pause.png" alt="A paused phone between a home laptop and an office NAS. Both links are marked off." width="640" height="320"></picture>
</figure>

Pausing the background service used to stop syncing and leave the rest of the device talkative. The listener, the LAN beacon, the rendezvous, the relay and the router mapping now stop with it, and they stay stopped until you resume. A pause you set yourself survives a restart, which matters on a phone that stops and starts the service all day. The short pause that `varsto disk` or an import takes for its own sake is not saved. That one ends when the command ends.

Thumbnails in the file list show on phones again. When the engine was busy, the service used to answer "no thumbnail", and the page believed it. It now answers "busy", and the page tries again.

The default policy no longer calls a folder violated in a vault that has no disk pool and no directory storage. There is one warning, that nothing is on a disk of your own and how to add one. A policy you set on purpose, which really does ask for a copy at home, is still held to that. The same distinction applies when an import decides whether its source may be removed, so a folder in that vault no longer waits forever for a copy on a disk you do not have.

A command and the background service take the same lock for fetching, freeing, writing and moving a file, so they no longer undo each other's folder state. A download or a write that fails no longer leaves a `.varsto-tmp-…` or `.varsto-upload-…` file holding part of the content. Files that arrive from another device keep the modification time their writer recorded, instead of being stamped with the moment they were downloaded. Tools that trust the date, a build, a photo library, another backup, stop seeing every pulled file as new.

## A removed device stays removed

A removed device's folder records, grants and escrow count only up to the first sequence number it left empty. It cannot come back later and fill that gap with a backdated record. A member of another vault applies a removal it reads from the folder epoch. A folder the remover could not re-key is re-keyed at the next sync of an owner that still holds the key. What the removed device already has on its own disk, it keeps. That was always true, and it is still true.

Joining reads the organization's manifest and takes vault epochs and revocations only from its administrators. A revocation written by an ordinary member of the roster no longer opens the vault for a device that is joining.

The activity log's "holds no key" line has the same button as the folder row, so a phone can ask for access from that line instead of hunting for the folder. The restic mirror, and the folders attached under it, are created so only this user can read them.

## The name on the icon

The application ids are now `net.varsto.app` on Android and macOS, `net.varsto.app.ios` on iOS, and `net.varsto.app.alpha` for the unsigned macOS build. An app that is already installed keeps its previous id, and its vault is not moved, until you install it again. Installing the new package beside the old one does not replace it.

## If you are on alpha.16

Update whenever you like. The two versions can share a vault while you do. Nothing in this release asks you to reset, to print a new kit, or to uninstall an Android build that is already the release-signed one from alpha.16. If a share request or an organization request is still sitting in a clear file from alpha.16, the next command that reads it seals it. This is still an alpha.
