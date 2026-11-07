# Varsto peer-to-peer against Resilio Sync, 2026-11-07

One measurement on rented machines: is Varsto's peer-to-peer transfer more
efficient than Resilio Sync's in some cases? Short answer: on these machines
Varsto finished initial syncs of large, compressible and duplicated data
faster, also over a slow lossy link, and sent fewer bytes when the data
compresses. Resilio Sync was far better after a change (it sends what
changed; Varsto sends the whole changed files again), its readers share data
with each other, and it used less memory, most of all on the writer. Varsto
also showed two reliability problems on the way (see the findings). Details,
numbers and limits below; raw data in
[data/resilio-vs-varsto-2026-11.jsonl](data/resilio-vs-varsto-2026-11.jsonl).

## Results

Medians of two runs per tool (with two runs, the mean of the two). Time:
seconds to a verified folder. Wire: megabytes received plus sent on the
reader's public interface. CPU and RSS: the daemon on the reader and on the
writer. Varsto's runs that failed (below) are not in the medians.

| Scenario | Data | Tool | Time s | Wire MB | Reader CPU s | Reader peak RSS MiB | Writer CPU s | Writer peak RSS MiB |
|---|---|---|---|---|---|---|---|---|
| 1. Many small files | `files`, 10 000 files, 294 MB | Varsto | 45 (41, 49) | 324 | 12.2 | 392 | 7.4 | 1115 |
| | | Resilio | 30 and 315, see below | 313 | 10.3 | 87 | 7.4 | 94 |
| 2. Large incompressible | `pair`, 2 x 1 GiB | Varsto | 47 | 2182 | 13.1 | 559 | 10.9 | 416 |
| | | Resilio | 110 | 2249 | 19.2 | 580 | 24.8 | 181 |
| 3. Compressible text | `text`, 537 MB | Varsto | 21 | 175 | 2.3 | 132 | 10.0 | 494 |
| | | Resilio | 38 | 563 | 5.9 | 82 | 9.2 | 186 |
| 4. Duplicate content | `dup`, 816 MB, half copies | Varsto | 24 | 836 | 4.2 | 242 | 7.6 | 445 |
| | | Resilio | 75 | 857 | 10.1 | 130 | 11.6 | 225 |
| 5. Two readers at once | `pair`; Amsterdam | Varsto | 57 | 2208 | 14.1 | 563 | 28.0 | 629 |
| | | Resilio | 55 | 2576 | 20.6 | 676 | 31.4 | 388 |
| | `pair`; Warsaw | Varsto | 95 | 2200 | 14.2 | 542 | | |
| | | Resilio | 110 | 2255 | 22.3 | 586 | | |
| 6a. Initial sync before the changes | `mut`, 1.13 GiB | Varsto | 37 | 1150 | 6.9 | 585 | 11.9 | 541 |
| | | Resilio | 53 | 1270 | 11.2 | 575 | 14.3 | 194 |
| 6b. 1 MiB changed in place + 10 MiB appended | `mut` | Varsto | 57 (push 19 + pull 38) | 1148 | 7.3 | 585 | 6.4 | 541 |
| | | Resilio | 12 | 12 | 3.0 | 575 | 2.2 | 263 |
| 7. Directory with 1.13 GiB renamed | `mut` | Varsto | 50 (push 11 + pull 39) | 1146 | 7.1 | 585 | 6.4 | 541 |
| | | Resilio | 59 | 1282 | 11.3 | 584 | 13.9 | 263 |
| 8. Constrained link (40 ms, 1 % loss, 100 Mbit/s) | `files` | Varsto | 364 | 355 | 18.3 | 494 | 12.6 | 768 |
| | | Resilio | 607 | 322 | 28.7 | 71 | 21.6 | 76 |

Scenario 1, Resilio Sync: one run took 315 s because a single 27 KB file
stayed in its download state with no traffic for about 4.5 minutes after
every other file had arrived (its log shows the transfer "connected, net:
0%" once a second); the other run took 30 s. A median of these two means
nothing; the typical case is the 30 s run, which beat Varsto's 41-49 s.

The interface totals include link-layer headers, which the per-peer
iptables counters do not (about 1 % of a bulk transfer: 22 MB on Resilio
Sync's 2 GiB), and a little SSH. Beyond that, Varsto's totals include its
reads of the bucket's metadata: its interface total exceeds its peer
traffic by 12-43 MB per run, Resilio Sync's by 0.2-23 MB. Every run's
values, and the failed ones, are in the raw data and in the table under
"Every run".

## Where Varsto did better, and why

- **Large files (scenario 2), 2.3x faster.** Varsto pulled 2 GiB at about
  45 MB/s (close to the machines' 400 Mbit/s); Resilio Sync at about
  19 MB/s from one writer. Resilio Sync can go faster: with two readers its
  Amsterdam reader got the same 2.2 GB in 55 s. Why one reader is slower was
  not investigated; the writer's CPU was not the limit (25 CPU seconds in
  110 s on 2 cores).
- **Compressible data (scenario 3), 3.2x fewer bytes and 1.9x faster.**
  Varsto compresses every block with zstd before it encrypts it, and a
  peer serves the same compressed, encrypted objects the storages hold;
  Resilio Sync sends the files as they are. On
  incompressible data this gives nothing (scenario 2: 2182 MB against
  2249 MB for 2147 MB of files).
- **Lossy, slow link (scenario 8), 1.7x faster** with about 10 % more
  bytes. Varsto's route log shows TCP; which of its transports (TCP or uTP)
  Resilio Sync used was not recorded, and the reason for the difference was
  not isolated.
- **Duplicate content (scenario 4), 3x faster, but not fewer bytes.** See
  "Where Varsto did worse": neither tool skipped the copies on the wire.
- **Less CPU on the reader** in the initial syncs of scenarios 2-5, 6a and
  8 and in the rename (for example 13 against 19 s for 2 GiB, 2.3 against
  5.9 s for the text); about the same for the small files, and more for the
  change (7.3 against 3.0 s, as it fetched 100 times the bytes).

## Where Varsto did worse, and why

- **A small change sends the whole file again (scenario 6b): 1148 MB on the
  wire for 11 MiB changed, against Resilio Sync's 12 MB**, and 57 s against
  12 s. Varsto's push is economical: content-defined chunking found that
  only 3 blocks were new and uploaded 8.6 MB to the bucket. But the reader
  fetched all 144 blocks of the two changed files from the peer: its pull
  writes a changed file from fetched blocks only and does not reuse the
  blocks it already has on disk (`crates/varsto-core/src/engine.rs`, the
  download loop that calls `fetch_in_order`). A local trial with a 64 MiB
  file showed the same (13 of 13 blocks fetched for a 1 MiB change).
  Resilio Sync transfers the changed pieces only.
- **Duplicates are not skipped on the reader (scenario 4).** The push
  stored 408 MB for the 816 MB set (each block once), but the pull fetched
  every file's blocks, copies included (836 MB on the wire); in the `files`
  set, 10 000 blocks were fetched for 9 474 distinct ones. Resilio Sync did
  not skip them either (857 MB).
- **Renames are not detected on the reader (scenario 7).** The push sent
  nothing (no new blocks), but the reader fetched all 1.13 GiB again.
  Resilio Sync did the same here (1282 MB), so this is a draw on bytes. In
  the local trial Varsto also left the old, now empty directory behind.
- **Memory.** Varsto's writer service peaked at 416-1115 MiB (1.1 GiB in
  the `files` runs; the peak includes its start-up scan of all five
  folders), Resilio Sync's writer at 76-388 MiB. On
  the reader the two are close for big files, but Varsto used several times
  more for small or text files (392 against 87 MiB for `files`, 494 against
  71 MiB on the slow link).
- **Two readers do not help each other (scenario 5).** Each Varsto reader
  fetched everything from the writer (they exchanged 17 KB), so the writer
  sent 4.3 GB. Resilio Sync's Warsaw reader got about 0.8 GB of its 2.2 GB
  from Amsterdam and its writer sent about 3.6 GB. The times came out about
  the same (Amsterdam 57 against 55 s, Warsaw 95 against 110 s), because the
  writer's upload was not the limit here; with more readers or a slower
  writer uplink, Resilio Sync's swarming would count.
- **Small files when Resilio Sync does not stall (scenario 1):** 30 s
  against 41-49 s.

## Versions

| | |
|---|---|
| Varsto | 0.0.1-alpha.16, the published daily build 20261106-46adda3 (`varsto-daily-linux-x86_64.tar.gz`, SHA-256 `1586764462f9cc7091bb89653767b5fc592f14398ba0a45c3151bf9282a8b475`). The pull-request build that was asked for first (CI runs 42378887990, 42379173190, 42379813594, 42382193499 of PR #124) had no Linux package when the machines were set up, so every result is of the daily |
| Resilio Sync | 2.8.1 (1390), Linux x64, from `https://download-cdn.resilio.com/2.8.1.1390/linux/x64/0/resilio-sync_x64.tar.gz` (SHA-256 `5eb7c4d9fac3c4e4b7d8ccceee0a4912c31dd1663e6fb4d2d21fc7f7833b3f2e`). See "Why not Resilio Sync 3.1" |
| Scripts | `scripts/bench/resilio-vs-varsto.py` (driver, uses `p2p-bench.py`), `bench-tools.py`, `bench-node.sh`, `gen-data.py`, at the commit that adds this page |

## Machines and link

Three Scaleway POP2-2C-8G (2 vCPU AMD EPYC 7543, 8 GB, 40 GB block volume,
Ubuntu 24.04, kernel 6.8): the writer in Paris (fr-par-1), readers in
Amsterdam (nl-ams-1) and Warsaw (pl-waw-1). Measured once before the runs:

| Path | Round trip (ping, mean) | TCP, writer sends (iperf3 -R, 1 stream / 4 streams) |
|---|---|---|
| Paris - Amsterdam | 12.1 ms | 570 / 415 Mbit/s |
| Paris - Warsaw | 33.0 ms | 421 / 416 Mbit/s |
| Amsterdam - Warsaw | 21.8 ms | |

With four streams iperf3 reached about 415 Mbit/s; the fastest pull here
(Varsto, 2 GiB in 47 s) averaged 365 Mbit/s. One 256 MiB object from the
bucket in one stream: 93 MB/s in Paris, 112 MB/s in Amsterdam.

## Method

- **Same machines, same data, same direction.** The writer in Paris holds the
  data; the readers pull it. One tool runs at a time (the other one's
  daemons are stopped on all three machines), runs alternate between the
  tools (Varsto first in repetition 1, Resilio Sync first in repetition 2),
  and before every initial sync the page cache is dropped on all three
  machines and the reader starts with an empty folder and a new device
  (Varsto: a newly joined device; Resilio Sync: a new storage directory).
- **Data** (`gen-data.py`, 4.7 GiB in all, random content from the
  operating system): `files` 10 000 files, 294 MB, sizes log-normal around
  16 KiB, 5 % copies of earlier files; `pair` 2 x 1 GiB incompressible;
  `text` 128 log-like text files, 537 MB; `dup` 92 files, 816 MB, every
  file twice (unique files in `orig/`, the same bytes under other names in
  `copies/`); `mut` a 1 GiB random file and a 128 MiB log in `dir/`, for
  the change and rename steps. Every machine has the writer's list of path,
  size and SHA-256 of every file.
- **Varsto** runs in its p2p mode as in `p2p-bench.py`: the vault's bucket
  (Scaleway Object Storage, fr-par) keeps only ledger, manifests and device
  records; every block is deleted from it before the runs (`purge-chunks`),
  so every block has to come from the writer, and a run where not every
  block came from a peer counts as failed. Settings on every device:
  rendezvous service off (so no relay through it), router port mapping off,
  update check off, automatic verification, bit-rot check, forwarding and
  mailbox off; STUN on (see "Varsto findings"). LAN discovery has no switch
  in Varsto; its multicast beacons do not leave a machine's network, and the
  three machines are in three countries. The time is `POST /api/sync` on
  the reader's running service, from the request to the answer, after the
  folder was attached; the reader's join, folder approval and service start
  are not timed. From the third `large` run on, the reader's service is
  also restarted after the writer's two restarts (finding 2 below); the
  earlier runs that passed are kept.
- **Resilio Sync** runs from a configuration file (`rslsync --nodaemon
  --config`), one shared folder per data set on the writer (read-write
  secret) and on each reader the read-only secret of one folder, with
  `use_relay_server`, `use_tracker`, `search_lan` and `use_sync_trash`
  false, `use_upnp` false, a fixed `listening_port` and `known_hosts` with
  the writer's address (and the other reader's, with two readers). The
  writer indexed every folder once before the runs (21 s to idle); before
  each run it is started again and waited for until it uses no CPU and
  reads no disk for 5 s. The time runs from starting `rslsync` on the reader
  to the first poll (every 0.25 s) that sees every file at its size and no
  `*.!sync` temporary file; a SHA-256 check of every file follows (not
  timed), and the poll goes on if it fails. The raw data also has the time
  to 99 % of the bytes (`bytes99`); it was within 6 s of the completion in
  every run where it was recorded (from the second `files` run on).
- **Verification.** Both tools' results count only when every file's
  SHA-256 equals the writer's list.
- **Wire bytes** are counted at the reader: the received plus sent bytes of
  its public interface (`/proc/net/dev`) over the timed part, which for
  Varsto includes its requests to the bucket and for both a little SSH;
  "with peers" counts only the traffic with the other two machines
  (iptables counters by address).
- **CPU and memory** of the daemon: user plus system CPU seconds over the
  timed part (`/proc/<pid>/stat`), peak RSS (`VmHWM`) at the end of it. The
  writer's peak RSS covers its life since its last start, which includes its
  start-up scan of all five folders (Varsto's writer service is restarted
  twice before each run, Resilio Sync's once).
- **Changes after the initial sync** (set `mut`, after its initial sync, the
  reader's daemon still running): in the middle of `dir/big.bin` 1 MiB of
  new random bytes is written in place, and 10 MiB of log lines are
  appended to `dir/app.log` (11 MiB changed of 1.13 GiB); then `dir` is
  renamed to `dir-moved`. Resilio Sync: from the change on the writer to the
  reader's verified folder, its own detection of the change included (the
  writer's and reader's clocks agreed to within about 0.2 s, estimated over
  SSH and recorded with each run).
  Varsto: the writer's service is paused (it still serves blocks but does
  not push on its own), its `POST /api/sync` (the push) is timed, the
  bucket's new blocks are deleted (not timed), then the reader's `POST
  /api/sync` is timed; the time is the sum of the two. Varsto's own
  detection of the change and the reader's wait for its next sync are not
  in it.
- **Constrained link**: `tc netem delay 40ms loss 1% rate 100mbit` on the
  reader's incoming traffic (through an `ifb` device, so it shapes the
  direction in which the data arrives), removed after the run.
- At least two repetitions per scenario; the tables give medians (with two
  runs, the mean of the two); the single runs are in the raw data.

## Every run

| Scenario | Step | Tool | Rep | Reader | Time s | Wire MB | Reader CPU s | Verified | Note |
|---|---|---|---|---|---|---|---|---|---|
| files | initial | varsto | 1 | ams | 70.33 | 277.6 | 10.36 | DIFFERENT | 1154 files unavailable |
| files | initial | resilio | 1 | ams | 314.73 | 313.4 | 10.67 | identical |  |
| files | initial | resilio | 2 | ams | 29.64 | 313.5 | 9.94 | identical |  |
| files | initial | varsto | 2 | ams | 68.87 | 279.5 | 10.54 | DIFFERENT | 1164 files unavailable |
| files-defaults | initial | varsto | 9 | ams | 75.45 | 322.8 | 12.65 | identical |  |
| files-stun | initial | varsto | 8 | ams | 41.37 | 313.8 | 10.68 | identical |  |
| files | initial | varsto | 3 | ams | 41.24 | 315.3 | 10.72 | identical |  |
| files | initial | varsto | 4 | ams | 49.2 | 332.4 | 13.64 | identical |  |
| large | initial | varsto | 1 | ams | 47.46 | 2179.6 | 13.76 | identical |  |
| large | initial | resilio | 1 | ams | 118.09 | 2249.7 | 19.32 | identical |  |
| large | initial | resilio | 2 | ams | 102.58 | 2249.1 | 19.11 | identical |  |
| large | initial | varsto | 2 | ams | 10.3 | 13.0 | 0.51 | DIFFERENT | 4 files unavailable |
| large | initial | varsto | 3 | ams | 46.75 | 2183.4 | 12.34 | identical |  |
| text | initial | varsto | 1 | ams | 21.87 | 174.1 | 2.28 | identical |  |
| text | initial | resilio | 1 | ams | 45.88 | 562.7 | 5.93 | identical |  |
| text | initial | resilio | 2 | ams | 30.58 | 562.5 | 5.84 | identical |  |
| text | initial | varsto | 2 | ams | 19.21 | 176.3 | 2.33 | identical |  |
| dup | initial | varsto | 1 | ams | 19.72 | 834.5 | 4.15 | identical |  |
| dup | initial | resilio | 1 | ams | 69.93 | 856.6 | 10.01 | identical |  |
| dup | initial | resilio | 2 | ams | 80.7 | 857.3 | 10.16 | identical |  |
| dup | initial | varsto | 2 | ams | 28.68 | 837.7 | 4.33 | identical |  |
| two-readers | initial | varsto | 1 | ams | 59.18 | 2206.2 | 13.95 | identical |  |
| two-readers | initial | varsto | 1 | waw | 95.88 | 2201.9 | 15.38 | identical |  |
| two-readers | initial | resilio | 1 | ams | 57.56 | 2655.7 | 21.35 | identical |  |
| two-readers | initial | resilio | 1 | waw | 107.35 | 2254.1 | 22.34 | identical |  |
| two-readers | initial | resilio | 2 | ams | 53.05 | 2496.4 | 19.79 | identical |  |
| two-readers | initial | resilio | 2 | waw | 112.84 | 2256.0 | 22.29 | identical |  |
| two-readers | initial | varsto | 2 | ams | 54.52 | 2210.6 | 14.21 | identical |  |
| two-readers | initial | varsto | 2 | waw | 93.8 | 2198.8 | 13.01 | identical |  |
| change+rename | initial | varsto | 1 | ams | 41.36 | 1147.9 | 6.93 | identical |  |
| change+rename | change | varsto | 1 | ams | 59.84 | 1145.3 | 7.35 | identical | push 16.92 s + pull 42.92 s |
| change+rename | rename | varsto | 1 | ams | 43.78 | 1144.4 | 7.06 | identical | push 9.04 s + pull 34.74 s |
| change+rename | initial | resilio | 1 | ams | 53.3 | 1264.9 | 11.24 | identical |  |
| change+rename | change | resilio | 1 | ams | 10.89 | 12.1 | 3.02 | identical |  |
| change+rename | rename | resilio | 1 | ams | 61.99 | 1276.0 | 11.33 | identical |  |
| change+rename | initial | resilio | 2 | ams | 52.81 | 1275.7 | 11.17 | identical |  |
| change+rename | change | resilio | 2 | ams | 12.93 | 12.2 | 3.03 | identical |  |
| change+rename | rename | resilio | 2 | ams | 56.2 | 1288.8 | 11.37 | identical |  |
| change+rename | initial | varsto | 2 | ams | 32.0 | 1151.1 | 6.96 | identical |  |
| change+rename | change | varsto | 2 | ams | 53.14 | 1150.5 | 7.35 | identical | push 20.4 s + pull 32.75 s |
| change+rename | rename | varsto | 2 | ams | 55.65 | 1148.2 | 7.12 | identical | push 12.57 s + pull 43.08 s |
| netem | initial | varsto | 1 | ams | 362.73 | 353.8 | 18.39 | identical |  |
| netem | initial | resilio | 1 | ams | 608.56 | 321.5 | 28.8 | identical |  |
| netem | initial | resilio | 2 | ams | 606.04 | 321.5 | 28.61 | identical |  |
| netem | initial | varsto | 2 | ams | 364.98 | 356.5 | 18.13 | identical |  |

`files-stun` and `files-defaults` are the two diagnostic runs described
under "Varsto findings". Writer-side preparation, not timed in the runs:
Varsto's pushes of all five sets into the bucket took 94 s (`files` 5.9 s,
`pair` 48.6 s, `text` 9.0 s storing 160 MB, `dup` 7.0 s storing 408 MB,
`mut` 23.7 s); Resilio Sync indexed the five folders in 21 s (the data was
in the page cache after the pushes).

## Limits of this measurement

- Two repetitions, one machine type, one day. Differences of less than
  about a third between the tools should not be read as real.
- Resilio Sync 2.8.1 is the last 2.x release; the current stable is 3.1.2,
  which could not be run this way (below). 3.x may behave differently.
- Resilio Sync has no tracker or relay here and is given the peers'
  addresses; Varsto finds them through the bucket. Neither reflects the
  setup most users have.
- Varsto's time to propagate a change leaves out its detection and its
  reader's scheduling (both explicit here); Resilio Sync's includes them.
  For changes, compare the bytes more than the seconds.
- Varsto's timed pull also reads the folder's metadata from the bucket
  (manifests, ledger); Resilio Sync gets the equivalent from its peer.
  Both are inside the times and the interface bytes.
- The block volumes are network storage (about 430 MB/s sequential with
  `oflag=direct`); random reads of many small files are slow on them for
  both tools.

## Why not Resilio Sync 3.1

The current stable download (`stable/linux/x64/0/resilio-sync_x64.tar.gz`,
"Resilio Sync 3.1.2 (1076)") was tried first, with the same configuration
file. It never synced a folder from the file: both ends logged "Stop
synchronization" right after loading the folder and every minute after; the
reader never opened a connection to its `known_hosts` entry (no packet to
the port in `tcpdump`), with the read-only or the read-write secret, with
`known_hosts` as a list or a string, with `folder_defaults.known_hosts`,
after creating a user identity (`--identity`), and also with tracker, relay
and LAN search on. `use_known_hosts` is refused as an unknown key in a
shared folder. 2.8.1 with the identical file synced within seconds, so the
measurement uses 2.8.1. 3.x presumably wants its folders added and its
devices linked through the web interface or its identity; that was not
attempted.

## Varsto findings worth a bug report

These came up while setting the runs up; they are about this build, not
about the comparison.

1. **With STUN off, a large pull from a peer stops part-way.** With
   `varsto p2p enable --no-stun --public <ip>:<port>` on the reader (and
   rendezvous, port mapping, update check, verification, scrub, forwarding
   and mailbox off), both pulls of the 10 000-file set ended after 65-70 s
   with 8 846 files written and 1 154 and 1 164 files "chunk ... is not
   available on any readable storage", all from about `f008835` on (the
   order of the pull). The reader's debug log shows 8 846 `/p2p/object`
   requests, all answered 200, and none for the missing blocks: the reader
   gave up on them without asking the peer. With the same settings but STUN
   on on the reader, three runs completed (41, 41 and 49 s); with p2p-bench's settings
   (rendezvous and STUN on) one run completed (75 s). Not root-caused; a
   guess is that the peer drops out of `Peers::ordered()` (a route or
   back-off state) when no STUN answer exists. The results above use STUN
   on; set `BENCH_VARSTO_NO_STUN=1` to reproduce.
2. **A sync right after a peer restarted can fetch nothing.** If the
   reader's service tried the writer while it restarted, it keeps the
   writer "resting after a failure"; a `POST /api/sync` in that window
   (here once in 19 Varsto runs: `large`, repetition 2) fetched no block and
   reported every file unavailable instead of waiting or retrying. The
   driver now restarts the reader's service after the writer's.
3. The changed-file and rename behaviour above (the pull does not reuse
   local blocks) is the largest efficiency gap against Resilio Sync.
4. Every reader run tried every earlier benchmark device as a peer (their
   device records stay in the vault after the device is gone), up to 17
   dead peers per run; each costs a failed TLS handshake at the start.
