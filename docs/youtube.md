# Importing YouTube channels, playlists and videos

```sh
varsto import youtube https://www.youtube.com/@ExampleWorkshop --folder workshop
varsto import jobs status
```

Varsto lists the channel (or playlist, or a single video) with the
[yt-dlp](https://github.com/yt-dlp/yt-dlp) installed on this computer,
downloads the videos one at a time into a spool directory, stores each
finished video in a Varsto folder (encrypted on your storages, like any
other file) and removes it from the spool once the folder's durability
policy holds. The background service does this after every sync and every
20 seconds in between; `varsto import jobs run` does it in the terminal, and
the Import page of the interface starts a job and shows it while it runs.

**Only archive what you may keep a copy of.** YouTube's terms of service
limit downloading, and videos are protected by copyright. Use this for your
own uploads, content whose licence allows copies, or what the law where you
live lets you keep for yourself. The slow defaults below exist so that an
archive never looks like a flood of requests; do not turn them off to go
faster.

yt-dlp is not part of Varsto: install it from your distribution
(`pacman -S yt-dlp`, `apt install yt-dlp`, `brew install yt-dlp`) or from
its own releases, and keep it up to date (YouTube changes often). Varsto
runs `yt-dlp` from the `PATH`; `--ytdlp-path` or the environment variable
`VARSTO_YTDLP` name another one. The background service runs YouTube jobs on
desktops only (Linux, macOS, Windows), not on phones.

## What is downloaded, and how politely

A job does what this manual workflow does, and nothing faster:

```sh
yt-dlp --flat-playlist --print url "https://www.youtube.com/@ExampleWorkshop/videos" > urls.txt
# then, one video at a time:
yt-dlp --sleep-interval 25 --max-sleep-interval 65 --sleep-requests 2 \
       --limit-rate 600K --concurrent-fragments 1 \
       --ignore-errors --no-abort-on-error "<video address>"
```

- The channel is listed flat (video id, title, address: one page of
  requests, no video page is opened).
- Before each video yt-dlp reads its expected size (`filesize`, else
  `filesize_approx`), so that Varsto knows whether it fits on the disk.
- Then the video is downloaded alone, with yt-dlp's own pause of 25 to 65
  seconds before it, 2 seconds between requests, at most 600 kB/s and one
  fragment at a time. Its `.info.json` is kept with it.

Every setting can be changed per job when it is added:

| Option | Default | |
|---|---|---|
| `--rate R` | `600K` | yt-dlp's `--limit-rate` (`1.5M`, `none`) |
| `--sleep MIN-MAX` | `25-65` | seconds between videos |
| `--sleep-requests N` | `2` | seconds between requests |
| `--concurrent-fragments N` | `1` | |
| `--format F` | yt-dlp's best | yt-dlp's `--format`, e.g. `"bv*[height<=1080]+ba/b"` |
| `--cookies-from-browser B` | none | for videos that need a login you have |
| `--thumbnails` | off | keep the thumbnail too |
| `--subs LANGS` | none | keep subtitles (`en,fi`) |
| `--extra-arg=ARG` | none | any other yt-dlp argument, repeated; `-o`, `--paths`, `--exec`, `--batch-file` and the like are refused because Varsto decides where yt-dlp writes |
| `--refresh-hours N` | `24` | how often the channel is listed again for new videos (`0`: once) |

## Where the videos go

In the folder, each video is

```
<channel name>/<upload date> <title> [<video id>].<ext>
<channel name>/<upload date> <title> [<video id>].info.json
```

for example `Example Workshop/2024-03-05 Building a bench [aBcDeFgHi_-].mkv`.
The folder is attached selectively on the computer that downloads: the
videos are placeholders there and their blocks are on the storages; open
or pin them like any other file.

`--storage NAME` (repeatable) stores the folder on those storages only.
`--storage cheapest` picks the storage with the lowest price per GB-month
that Varsto knows (`varsto storage price`, or the built-in prices of
recognised providers); with no price known it asks you to name a storage.
Without `--storage` the folder's normal placement applies.

## Never twice

Every video is known by its YouTube id. Before a video is probed or
downloaded, Varsto looks the id up in the vault's index:

- every video any YouTube job stored, in any folder, on any device (the
  folder's import book lists them, and the books are synced);
- every file named `... [<id>].<ext>` in the folders attached on this
  computer;
- what `varsto import youtube-scan` registered.

A video found there is marked *already stored* (`import jobs status` says
where) and is not downloaded. Listing the channel again later adds only
new videos. A video you delete from the folder is not downloaded again
either.

If you have downloaded videos before, register them:

```sh
varsto import youtube-scan "Old videos"          # a Varsto folder: recorded with the folder, for every device
varsto import youtube-scan /media/disk/youtube   # a directory outside Varsto: recorded on this computer only
```

Both read only the names (yt-dlp's default `%(title)s [%(id)s].%(ext)s`);
nothing is downloaded, moved or imported. A folder that was scanned can be
the folder of a new job (`--folder "Old videos"`), so new videos land next
to the old ones.

## Disk space

The spool is `~/Downloads/varsto-youtube/<job id>` unless `--download-dir`
names another place (never inside a Varsto folder). It never takes the
download disk below a reserve: 15 % by default, `--free-min 20GB` or
`--free-min 10%` to change it (never less than Varsto's own minimum free
space on that disk). A video starts only when its expected size fits above
the reserve; otherwise the job *waits for space* (`import jobs status` says how
much is missing, and the service notifies once). When the disk fills during
a download, the download is stopped and continued later from where it was.

A video leaves the spool only after it is in the folder, every block of it
is on a storage, one copy was read back intact and the folder's policy
holds. A new folder gets the policy "one copy on a storage"
(`--min-copies N` for more, `--keep-policy` for the vault's default
policy, which may keep videos in the spool until another device has
checked them).

## Failures

A video that cannot be downloaded (private, removed, members only, not
available in your country, a network error) never stops the job: the
reason yt-dlp gave is recorded and the video is tried again an hour later,
then 4, 16 and 64 hours later, at most a week apart. After six failures it
is *given up*; `varsto import jobs resume <job>` or `varsto import jobs run <job>
--retry-failed` tries it again.

## Commands

```sh
varsto import youtube <address> [--folder NAME] [--storage S|cheapest]... [--free-min 15%] [--download-dir DIR] [options above]
varsto import jobs list                         # every import job, YouTube and torrents, one line each with its kind
varsto import jobs run [JOB] [--retry-failed]   # work in the terminal until each job waits
varsto import jobs status [JOB] [--videos]      # what each job does or waits for; --videos lists every video
varsto import jobs pause JOB | jobs resume JOB
varsto import jobs remove JOB                   # forget the job; the folder keeps its videos
varsto import youtube-scan FOLDER-OR-DIRECTORY
```

`varsto import jobs` is one command for every kind of import job: the
torrent jobs of [torrents.md](torrents.md) are in the same list. `JOB` is
`youtube:<id>`, or just the job's id (its first characters), its folder or
the channel address; when such a name fits a torrent job too, the command
asks for the `youtube:` form. Without a `JOB`, `run` works on every YouTube
job until it waits and steps every torrent job once. With `--json`, `list`
gives one uniform row per job (the rows of `GET /api/import/jobs`) and the
other commands the job itself with `job` (its id in the list) and `job_kind`.
`varsto status` shows a line per job that is not complete.

## From the interface

The Import page has YouTube among its sources: paste a channel, playlist or
video address; the page says which it is and lets you switch between "One
video" and "Whole channel or playlist" (a watch address with a playlist in
it can be either). Under Advanced are the polite defaults above (25-65 s
between videos, 2 s between requests, 600K, one fragment at a time), the
format, cookies from a browser, thumbnails, subtitles and how often to list
again. The job then shows under *In progress* with its state (listing,
downloading, waiting for space or for the policy, waiting to try failed
videos again and when), the videos stored and already stored (found in the
vault, not downloaded), the video in hand, and every failed video with
yt-dlp's reason; Pause, Resume, Try failed videos again and Remove act on it.

A single video address is one download (the job is complete once it is
stored); a channel or playlist address is every video in it, one at a time.

YouTube imports are imports like the others: `varsto import status
[FOLDER]` shows the folder's files and what is in, and `varsto import
verify FOLDER` says whether every video file the job imported is in the
folder with every block on a storage and the policy met. The folder's
import book is what keeps a video from being downloaded twice.

## Limits

- One video at a time per job; jobs run one after the other.
- A video's expected size comes from YouTube and may be off; the reserve
  is what keeps the disk safe.
- Live streams that have not ended, and premieres, fail until they are
  available and are tried again.
- Two computers may run a job for the same channel into the same folder;
  each checks the index before every video, but two that start the same
  video before either has stored it both download it.
