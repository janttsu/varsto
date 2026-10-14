# Recovery package

Your devices hold the keys to your vault. If one of them is lost, another one adds a new device with a pairing code and nothing else is needed. This page is about the other case: **every device is lost at once**, in a fire, a burglary or a flood. Then you restore from what you kept somewhere else: the *recovery package*.

Varsto makes a checklist of that package for your vault, with the restore steps for a new computer:

```sh
varsto recovery guide                                   # text in the terminal
varsto recovery guide --format html --output guide.html # a printable page with checkboxes
varsto recovery guide --format markdown                 # for your own notes
```

In the desktop interface the same checklist is under **Recovery package** (in the sidebar, under More on a phone, and linked from Settings). You can tick what you have done; the ticks stay in that browser only. **Print / save as PDF** and **Download as text** give you a copy to keep with the package.

The guide never contains a secret. It names the secrets (the recovery words, storage keys, passwords) and says where to keep them; the values themselves are never read into it. You can store the guide itself anywhere, but it tells whoever reads it which buckets and disks you use.

## What goes into the package

| What | Why | Without it |
| --- | --- | --- |
| **Recovery kit**: the vault key as 24 words (`varsto recovery kit`), or three shares of which any two rebuild it (`--shares`). | It is the only thing that opens the vault. There is no account, no reset and no copy anywhere else. | Nobody can read the vault, including the makers of Varsto. |
| **Storage credentials**: for each S3 bucket the endpoint, bucket and region (in the guide) plus the access key ID and secret key (keep them yourself); the login to the provider account. | A new device reads your encrypted data from the storages. Varsto keeps the secret key only in the encrypted secret store of each device. | You need the provider account to make new keys; without it the bucket cannot be reached. |
| **rclone configuration** (`rclone.conf`) for rclone remotes, kept like a password. | rclone, not Varsto, holds the remote's token. | Set the remote up again from the provider account. |
| **NAS and network shares**: where they are and how to reach them. A directory on a computer's own disk is lost with it. | A directory storage is only a recovery source if it survives. | Data that only that directory held is lost. |
| **Disk pools**: the disks themselves (by the names on their stickers), kept apart from your computers, the pool's exact name, and on Linux the `disks.conf` lines the guide prints. | The disks hold blocks that may be nowhere else. They are recognised by the vault key and the pool's name. | Files whose blocks were only on those disks cannot be restored. |
| **Strongroom security keys**: at least two enrolled FIDO2 keys in different places, and their PINs. | A Strongroom folder's key exists only wrapped for its security keys; the recovery words do not open it. | The folder cannot be opened by anyone. This is by design. |
| **Organization root words** (if the vault belongs to an organization), kept apart from the recovery kit. | They appoint and dismiss administrators. | Nobody can appoint a new administrator; the data stays readable with the recovery kit. |
| **restic password** and the repository's credentials (if you keep a restic backup). | The restic repository can be restored with restic alone, without Varsto. | restic cannot read the repository. |

Not needed: the passphrase of a device. A new device gets its own.

Folders that **someone else shares with you** are not in your package: their key came from the person who shared them. On a new device you send them a new request code (`varsto share request`) and they share the folder again.

## Where to keep it

- The recovery words on paper or metal, in at least two places away from your devices. Never as a photo, a cloud note or an e-mail.
- Shares, if you use them, each in a different place or with a different person you trust.
- Storage keys and passwords in a password manager you can open from a new computer without your old devices, or on paper with the words.
- Disks of a pool in more than one building if they are meant to survive a fire.

Test the package once a year: install Varsto on a spare computer or a virtual machine and join with the words, as the guide's restore steps say. Make the guide again whenever you add a storage, a disk or a Strongroom folder, and print a new recovery kit after removing a device (the vault key changes; an old kit still opens what was written before).

## The restore, in short

The guide gives the exact commands for your vault. In outline:

1. Install Varsto from the download page and check the download with `varsto verify-release`.
2. If you kept shares, rebuild the words: `varsto recovery combine --check <key check> "<index>: <words>" "<index>: <words>"` (the key check is printed on the kit; with it a share from another kit or a copying mistake is caught).
3. Join through a bucket or a directory that holds the vault: `varsto join --words "<24 words>" ...`.
4. Add the other storages under the same names (`varsto storage add-s3`, `add-rclone`, `add-local`, `add-pool`).
5. Connect the pool disks one at a time (`varsto disk insert` on Linux).
6. Attach the folders (`varsto folder attach <folder> <directory>`), unlock Strongroom folders with a security key, restore backups (`varsto backup restore`).
7. Files whose blocks are only on cold storage need a confirmed read (`varsto repair --from-cold` or `varsto move ... --confirm-cold-read`); archive classes need a restore request at the provider first.
8. Remove the lost devices (`varsto device revoke`), print a new recovery kit and make the guide again.

The limits are those of the [failure model](failure-model.md): if the recovery words and every share are lost, nothing can restore access.
