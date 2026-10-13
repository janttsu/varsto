# Importing from Dropbox, OneDrive and other cloud drives

Varsto imports a cloud drive through [rclone](https://rclone.org), which
knows Dropbox, OneDrive, Google Drive and dozens of other services. Varsto
runs your own `rclone` with your own rclone configuration; it never sees
your cloud password or tokens.

Each imported remote path becomes one Varsto folder. Run the same import
again whenever you like: changed files come over as new versions, unchanged
ones are skipped, and files you deleted in the cloud stay in Varsto (the
report lists them). That way you can keep importing until you stop using
the cloud drive.

## Dropbox

```sh
rclone config create mydropbox dropbox     # signs in in your browser, once
varsto import dropbox mydropbox:
varsto import dropbox mydropbox:Photos --folder "Dropbox photos"
```

Every file is checked against Dropbox's own content hash while it is
encrypted and uploaded.

## OneDrive

```sh
rclone config create myonedrive onedrive
varsto import onedrive myonedrive:
```

Files are checked against OneDrive's QuickXorHash.

## Any other rclone remote

```sh
rclone config                 # set up the remote
varsto import rclone gdrive:Documents
```

Varsto checks the provider's own hash where the remote has one (Google
Drive: SHA-256; S3 and similar: MD5; Backblaze B2, Box, pCloud: SHA-1).
`--hash-type` picks another (`--hash-type none` for none).

Google Docs, Sheets and Slides, Dropbox Paper documents and OneNote
notebooks have no fixed size: rclone cannot download them as files, so they
are listed in the report as not imported. Export them in the provider's app
(or with rclone's export options into another directory) if you need them.

## Options

- `--folder NAME`, `--dest DIR`, `--selective`, `--dry-run`, `--json`: as for
  other imports. Without `--dest` the folder is attached selectively (files
  are placeholders on this computer, the blocks are on your storages).
- `--transfers N`: parallel downloads (default 4).
- `--hash-type T`: `dropbox`, `quickxor`, `sha256`, `sha1`, `md5`, `blake3`
  or `none`.

## How it works

Varsto lists the remote with `rclone lsjson`, then downloads the files that
are new or changed in batches with one `rclone copy` per batch into a
temporary directory of the Varsto home, checks each file's hash, encrypts
and uploads it, and deletes the temporary copy. A file whose hash does not
match is downloaded once more; if it still does not match it is reported
and left out. Files whose names differ only in case are imported and noted
(they cannot sit side by side on Windows or macOS). Names Varsto cannot use
(with `:` or `\`, Windows reserved names) are reported.

`varsto import status` shows every imported folder with its last run.
