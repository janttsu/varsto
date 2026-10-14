# Downloading torrents larger than your disk

```sh
varsto torrent add show.torrent --folder show --storage cloud --free-min 15%
varsto torrent run show          # or let the background service do it
varsto torrent status show
```

Varsto can download a torrent that is far larger than the computer's disk
straight into one of your storages (an S3 bucket, an rclone remote, a disk
pool). A local **transmission-daemon** does the downloading; Varsto tells it
which files to fetch, a batch at a time, so that the download disk never
falls below a free-space reserve. Every batch goes into a Varsto folder,
encrypted, and each file is removed from the disk only once it is safely
stored. Then the next batch starts, until the whole torrent is in the
folder.

Linux only, on the command line. After 0.0.1-alpha.13; not in a release yet.

## Installing transmission-daemon

Debian and Ubuntu:

```sh
sudo apt install transmission-daemon
```

Arch Linux:

```sh
sudo pacman -S transmission-cli
```

Varsto deletes files the daemon wrote and reads them first, so **run the
daemon as your own user**, not as the packages' system user
(`debian-transmission` on Debian, `transmission` on Arch). The simplest way
is a user service:

```sh
sudo systemctl disable --now transmission-daemon   # the system-wide one, if it runs
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/transmission-daemon.service <<'EOF'
[Unit]
Description=transmission-daemon for Varsto torrent jobs

[Service]
ExecStart=/usr/bin/transmission-daemon --foreground --config-dir %h/.config/transmission-daemon
Restart=on-failure

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now transmission-daemon
```

Stop it, edit `~/.config/transmission-daemon/settings.json`, and start it
again (the daemon overwrites the file when it stops):

```json
"rpc-bind-address": "127.0.0.1",
"rpc-whitelist": "127.0.0.1",
"rpc-authentication-required": true,
"rpc-username": "me",
"rpc-password": "a long password",
"incomplete-dir-enabled": false,
"rename-partial-files": true,
"download-dir": "/data/torrents"
```

`incomplete-dir-enabled` must be off: with it, unfinished downloads are kept
on another disk that Varsto does not watch, and `torrent add` refuses to go
on. Put `download-dir` on the disk you want the download to use (or give
`--download-dir` per job).

## RPC settings

Varsto talks to the daemon over its RPC interface, JSON over HTTP on
`http://127.0.0.1:9091/transmission/rpc` by default. Change it with
`--rpc-url`, sign in with `--rpc-user` and `--rpc-password`, or set
`VARSTO_TRANSMISSION_URL`, `VARSTO_TRANSMISSION_USER` and
`VARSTO_TRANSMISSION_PASSWORD`. A job remembers the address and user name in
its file and the password in the device's encrypted secret store, so the
background service can drive it later. Keep the daemon on 127.0.0.1: its
RPC password is sent with every request in the clear.

## Adding a job

```sh
varsto torrent add <file.torrent | 'magnet:?xt=urn:btih:…'> --folder <name> \
    [--storage <name>]… [--free-min 15%] [--download-dir DIR] \
    [--min-copies 1 | --keep-policy] [--run]
```

- `--folder` names a new Varsto folder for the torrent's files. It is
  attached selectively under your folder root, so the files are placeholders
  on this computer and their blocks are only on the storages. The folder
  keeps the torrent's own layout (a multi-file torrent's top directory
  included).
- `--storage` (repeatable) sets the folder's placement: its blocks go only to
  these storages. Without it they go to every storage, as for any folder.
- `--free-min` is the reserve on the download disk: a share of the file
  system (`15%`, the default) or an amount (`50GB`). Varsto's own minimum
  free space (5 % unless a folder or directory storage on the same disk says
  more) always applies too; the larger one wins.
- `--download-dir` is where transmission downloads, default its own
  `download-dir`. Each job uses a directory of its own inside it, named after
  the torrent's info hash. A download directory inside a Varsto folder or
  inside Varsto's own device directory is refused.
- The new folder's durability policy is "1 copy on a storage"
  (`--min-copies N` for more). A file leaves the download disk only when the
  policy holds, and the default policy also asks for a copy on your own
  devices or disks checked by another device, which a download straight to a
  bucket never has; `--keep-policy` keeps it anyway (files then wait on the
  disk until it holds).
- The torrent is added to transmission stopped with every file unwanted. A
  torrent transmission has already is refused: remove it there first (keep
  its data) so that Varsto controls which files are fetched.

A magnet link has no file list until peers send it: the job starts the
torrent with its download speed limited to 50 kB/s, and as soon as the list
arrives it stops it and marks every file unwanted. transmission wants every
file of a magnet link the moment it knows them, so a few seconds of data may
arrive before Varsto takes over; that data counts against the reserve like
any other.

## Running

`varsto torrent run <job>` drives a job in the terminal until it is complete
(Ctrl-C stops it; running it again carries on), and the background service
steps every job after each of its syncs. Each step:

1. imports the files transmission has finished (every piece checked against
   the torrent's hashes) with the local-directory import
   ([import-local.md](import-local.md)), restricted to those files, and
   removes each one once every block of it is on a storage, one copy was
   read back intact and the folder's policy holds;
2. marks the removed files unwanted in transmission and has it re-check its
   data, so they are neither downloaded nor offered to other peers again;
3. when the batch is done, picks the next files in torrent order whose size
   (plus a piece on each side, because pieces that reach into neighbouring
   files are written whole) fits in the free space above the reserve, marks
   them wanted and starts the torrent.

If the free space falls below the reserve during a batch (something else
filled the disk), the torrent is stopped until there is room again for the
rest of the batch. If the next file alone does not fit, the job waits and
says how much room it needs; `varsto status` and the Help page show it.

A file transmission reports an error for is retried (the torrent is started
again after a minute), never skipped. A job carries on after a crash or a
restart: each step reads transmission's state and the folder's import book
again, so nothing is imported or removed twice, and nothing is removed that
transmission did not finish and Varsto did not verify on a storage.

## Status and other commands

```sh
varsto torrent list                    # every job, one line each
varsto torrent status [job]            # files, batch, reserve, errors
varsto torrent pause <job>
varsto torrent resume <job>
varsto torrent remove <job> [--keep-in-transmission]
```

A job is named by its info hash (the first 6 characters or more), its folder
or the torrent's name. `varsto status` lists the jobs that are not complete.
A job is `complete` when every file of the torrent is in the folder with the
content that was imported, was removed from the download disk by the
import's rule, and has every block on a storage. The job's directory is then
empty and removed. `remove` forgets the job and, unless
`--keep-in-transmission`, removes the torrent from transmission; it never
deletes the folder or files that were not stored yet.

## Seeding

transmission seeds only what is on the disk. A file Varsto stored and
removed is no longer offered: the job marks it unwanted and has transmission
re-check its data, which forgets the removed pieces. So a torrent downloaded
this way is seeded only while each batch is on the disk, and not after the
job is complete. If you want to keep seeding, keep the files: this tool is
for torrents you cannot keep on the disk at all.

## Later

The folder is an ordinary Varsto folder. To move it from the bucket to a
disk pool, or anywhere else, use `varsto move` (spec section 23).

## Limits

- Linux and the command line only. One transmission daemon per job, on the
  same computer (the download directory must be a local path both can use).
- The reserve is checked between steps (every few seconds with
  `torrent run`, after each sync in the service): a disk filled very fast by
  something else can go below it before the torrent is stopped.
- Pieces at the edges of a batch are written into the neighbouring files'
  places as well; the planner leaves room for them. When transmission
  re-checks its data after a removal it forgets pieces shared with removed
  files, and downloads them again with the next file that needs them.
- Files Varsto cannot store under their names (empty, `.` or `..`
  components, names starting with `.varsto`) make `torrent add` refuse the
  torrent.
- BitTorrent v2-only torrents and magnet links without a v1 info hash
  (`xt=urn:btih:`) are not supported.
