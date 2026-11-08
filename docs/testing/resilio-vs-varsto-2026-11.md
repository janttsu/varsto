# Varsto peer-to-peer against Resilio Sync, 2026-11-07 and 2026-11-08

One measurement on rented machines, made twice: is Varsto's peer-to-peer
transfer more efficient than Resilio Sync's in some cases? The first run
(2026-11-07) used the daily build 20261106-46adda3; the second
(2026-11-08) the daily 20261108-c50f260, which changed the pull (local
blocks are reused, readers serve finished files while they still pull,
requests are shared by peer speed, a failed request rests a peer only
briefly). Resilio Sync 2.8.1 ran on both days. The tables below put the
three side by side; the raw data is in
[data/resilio-vs-varsto-2026-11.jsonl](data/resilio-vs-varsto-2026-11.jsonl)
(11-07) and
[data/resilio-vs-varsto-2026-11-08.jsonl](data/resilio-vs-varsto-2026-11-08.jsonl)
(11-08).

**Short answer.** On these machines Varsto pulls faster than Resilio Sync
in every initial sync of large, compressible or duplicated data and over a
slow lossy link, and sends a third of the bytes for text. The new build
(c50f260) closed the gap that mattered most: after a small change the
reader now fetches only the changed blocks (22 MB with the peer instead of
1 148 MB), a renamed directory moves without data, duplicates are reused
from disk (half the bytes), and two readers can feed each other. What did not
change: the time to propagate a change is still three to five times
Resilio Sync's (the writer's own all-folders sync and the reader's
re-hashing of its local blocks cost more than the transfer), the writer's
service still needs several times Resilio Sync's memory, and on the 10 000
small files Resilio Sync is faster when it does not stall, which it did in
one run of two on both days. Of the two problems found on 11-07, the
STUN-off stall is gone and the back-off failure did not recur in 20 runs.

## Results, per scenario

Medians of two runs (with two runs, the mean of the two) of the verified
runs. Time: seconds to a folder where every SHA-256 matched the writer's.
Wire: megabytes received plus sent on the reader's public interface; "with
peers": only the traffic with the other two machines; "reused local":
bytes the new build took from blocks already on the reader's disk instead
of the network; "writer sent": the writer's bytes to the readers. CPU and
RSS: the daemon on the reader and on the writer. "Failed": runs whose
folder was not complete or not every block came from a peer (not in the
medians). The 11-07 Varsto and 11-08 rows were timed differently (see the
method: `POST /api/sync` on 11-07, attach-to-complete poll on 11-08, the
same poll as Resilio Sync's); the difference is well under a second.

**files, initial**

| Tool, day | Runs | Time s | Wire MB | With peers MB | Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Varsto 46adda3 (11-07) | 2 | 45.2 | 323.9 | 305.3 |  |  | 12.2 | 392 | 7.4 | 1115 | 2 |
| Varsto c50f260 (11-08) | 2 | 44.3 | 294.5 | 285.2 | 16.3 | 280.5 | 11.4 | 288 | 6.1 | 801 | 0 |
| Resilio 2.8.1 (11-07) | 2 | 172.2 | 313.4 | 310.3 |  |  | 10.3 | 87 | 7.4 | 94 | 0 |
| Resilio 2.8.1 (11-08) | 2 | 168.3 | 313.4 | 310.3 |  | 307.5 | 11.7 | 93 | 6.7 | 95 | 0 |

**large, initial**

| Tool, day | Runs | Time s | Wire MB | With peers MB | Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Varsto 46adda3 (11-07) | 2 | 47.1 | 2181.5 | 2166.9 |  |  | 13.1 | 559 | 10.9 | 416 | 1 |
| Varsto c50f260 (11-08) | 2 | 43.0 | 2178.8 | 2166.4 | 0.0 | 2224.7 | 14.2 | 565 | 12.4 | 450 | 0 |
| Resilio 2.8.1 (11-07) | 2 | 110.3 | 2249.4 | 2226.9 |  |  | 19.2 | 580 | 24.8 | 181 | 0 |
| Resilio 2.8.1 (11-08) | 2 | 108.9 | 2249.5 | 2227.0 |  | 2224.5 | 21.9 | 582 | 22.1 | 194 | 0 |

**text, initial**

| Tool, day | Runs | Time s | Wire MB | With peers MB | Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Varsto 46adda3 (11-07) | 2 | 20.5 | 175.2 | 161.3 |  |  | 2.3 | 132 | 10.0 | 494 | 0 |
| Varsto c50f260 (11-08) | 2 | 17.1 | 170.1 | 161.3 | 0.0 | 160.9 | 2.3 | 132 | 8.6 | 405 | 0 |
| Resilio 2.8.1 (11-07) | 2 | 38.2 | 562.6 | 557.0 |  |  | 5.9 | 82 | 9.2 | 186 | 0 |
| Resilio 2.8.1 (11-08) | 2 | 63.2 | 563.2 | 557.5 |  | 556.8 | 7.2 | 89 | 7.5 | 143 | 0 |

**dup, initial**

| Tool, day | Runs | Time s | Wire MB | With peers MB | Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Varsto 46adda3 (11-07) | 2 | 24.2 | 836.1 | 819.6 |  |  | 4.2 | 242 | 7.6 | 445 | 0 |
| Varsto c50f260 (11-08) | 2 | 13.2 | 421.0 | 410.0 | 407.9 | 409.5 | 2.9 | 201 | 4.7 | 360 | 0 |
| Resilio 2.8.1 (11-07) | 2 | 75.3 | 856.9 | 848.3 |  |  | 10.1 | 130 | 11.6 | 225 | 0 |
| Resilio 2.8.1 (11-08) | 2 | 78.0 | 856.5 | 847.9 |  | 846.3 | 11.4 | 136 | 9.9 | 201 | 0 |

**two-readers, initial, reader ams**

| Tool, day | Runs | Time s | Wire MB | With peers MB | Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Varsto 46adda3 (11-07) | 2 | 56.9 | 2208.4 | 2170.6 |  |  | 14.1 | 563 | 28.0 | 629 | 0 |
| Varsto c50f260 (11-08) | 2 | 72.3 | 2212.4 | 2183.7 | 0.0 | 4107.3 | 15.2 | 558 | 24.9 | 516 | 0 |
| Resilio 2.8.1 (11-07) | 2 | 55.3 | 2576.1 | 2560.2 |  |  | 20.6 | 676 | 31.4 | 388 | 0 |
| Resilio 2.8.1 (11-08) | 2 | 101.6 | 2924.5 | 2894.9 |  | 3419.1 | 29.3 | 661 | 35.8 | 254 | 0 |

**two-readers, initial, reader waw**

| Tool, day | Runs | Time s | Wire MB | With peers MB | Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Varsto 46adda3 (11-07) | 2 | 94.8 | 2200.3 | 2172.3 |  |  | 14.2 | 542 | 28.0 | 629 | 0 |
| Varsto c50f260 (11-08) | 2 | 98.4 | 2196.4 | 2172.7 | 0.0 | 4107.3 | 13.6 | 567 | 24.9 | 516 | 0 |
| Resilio 2.8.1 (11-07) | 2 | 110.1 | 2255.0 | 2232.2 |  |  | 22.3 | 586 | 31.4 | 388 | 0 |
| Resilio 2.8.1 (11-08) | 2 | 98.8 | 2620.6 | 2593.9 |  | 3419.1 | 25.7 | 620 | 35.8 | 254 | 0 |

**change+rename, initial**

| Tool, day | Runs | Time s | Wire MB | With peers MB | Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Varsto 46adda3 (11-07) | 2 | 36.7 | 1149.5 | 1124.5 |  |  | 6.9 | 585 | 11.9 | 541 | 0 |
| Varsto c50f260 (11-08) | 2 | 34.0 | 1144.2 | 1124.3 | 0.0 | 1195.5 | 7.1 | 579 | 9.4 | 436 | 0 |
| Resilio 2.8.1 (11-07) | 2 | 53.1 | 1270.3 | 1257.6 |  |  | 11.2 | 575 | 14.3 | 194 | 0 |
| Resilio 2.8.1 (11-08) | 2 | 69.4 | 1271.1 | 1258.4 |  | 1256.9 | 12.8 | 574 | 12.9 | 177 | 0 |

**change+rename, change**

| Tool, day | Runs | Time s | Wire MB | With peers MB | Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Varsto 46adda3 (11-07) | 2 | 56.5 | 1147.9 | 1126.8 |  |  | 7.3 | 585 | 6.4 | 541 | 0 |
| Varsto c50f260 (11-08) | 2 | 61.4 | 37.8 | 21.9 | 1189.7 | 21.8 | 2.7 | 140 | 3.4 | 436 | 0 |
| Resilio 2.8.1 (11-07) | 2 | 11.9 | 12.2 | 12.0 |  |  | 3.0 | 575 | 2.2 | 263 | 0 |
| Resilio 2.8.1 (11-08) | 2 | 14.7 | 12.2 | 12.0 |  | 12.0 | 3.2 | 574 | 2.2 | 230 | 0 |

**change+rename, rename**

| Tool, day | Runs | Time s | Wire MB | With peers MB | Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Varsto 46adda3 (11-07) | 2 | 49.7 | 1146.3 | 1126.2 |  |  | 7.1 | 585 | 6.4 | 541 | 0 |
| Varsto c50f260 (11-08) | 2 | 38.2 | 16.6 | 0.1 | 1223.7 | 0.1 | 2.3 | 140 | 4.5 | 436 | 0 |
| Resilio 2.8.1 (11-07) | 2 | 59.1 | 1282.4 | 1268.6 |  |  | 11.3 | 584 | 13.9 | 263 | 0 |
| Resilio 2.8.1 (11-08) | 2 | 66.5 | 1281.9 | 1269.1 |  | 1267.6 | 13.0 | 579 | 12.5 | 230 | 0 |

**netem, initial**

| Tool, day | Runs | Time s | Wire MB | With peers MB | Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Varsto 46adda3 (11-07) | 2 | 363.9 | 355.1 | 311.9 |  |  | 18.3 | 494 | 12.6 | 768 | 0 |
| Varsto c50f260 (11-08) | 2 | 335.3 | 332.0 | 294.6 | 16.3 | 288.1 | 20.3 | 278 | 9.2 | 767 | 0 |
| Resilio 2.8.1 (11-07) | 2 | 607.3 | 321.5 | 314.0 |  |  | 28.7 | 71 | 21.6 | 76 | 0 |
| Resilio 2.8.1 (11-08) | 2 | 599.0 | 321.4 | 314.0 |  | 310.6 | 31.8 | 69 | 19.2 | 73 | 0 |

| Tool, day | Runs | Time s | Wire MB | With peers MB | Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Varsto 46adda3 (11-07) | 1 | 75.5 | 322.8 | 308.6 |  |  | 12.7 | 328 | 9.5 | 918 | 0 |

| Tool, day | Runs | Time s | Wire MB | With peers MB | Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Varsto c50f260 (11-08) | 1 | 61.1 | 319.0 | 285.1 | 16.3 | 280.5 | 12.4 | 300 | 10.7 | 845 | 0 |

| Tool, day | Runs | Time s | Wire MB | With peers MB | Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Varsto 46adda3 (11-07) | 1 | 41.4 | 313.8 | 301.8 |  |  | 10.7 | 384 | 5.4 | 1006 | 0 |

### What the scenarios show

1. **Many small files.** Unchanged for Varsto (44-45 s both days, 10 000
   files from the peer; the new build fetched 9 474 distinct blocks and
   reused the 526 duplicate ones locally, 16 MB less on the wire). Resilio
   Sync is faster when it does not stall (25-30 s), but on both days one of
   its two runs took over five minutes: a single small file stayed in its
   download state with no traffic (f002953 on 11-07, f003617 on 11-08, both
   about 27 KB) until Resilio Sync retried it some four and a half minutes
   later. Two stalls in four runs is not an accident; it is how 2.8.1
   behaves with this folder.
2. **Two large files.** Varsto 43-47 s against Resilio Sync's 109-110 s,
   both days alike. Nothing to reuse, so the new build is the same.
3. **Compressible text.** Varsto 17-21 s and 170-175 MB on the wire for
   537 MB of files, against 38-63 s and 563 MB: Varsto compresses every
   block with zstd before encrypting it and serves the same compressed,
   encrypted objects to peers; Resilio Sync sends the files as they are.
4. **Duplicate content.** The clearest gain of the new build: 408 MB of the
   816 MB were taken from blocks already on the reader's disk, 420 MB
   crossed the wire instead of 836 MB, and the pull took 12-14 s instead of
   20-29 s. Resilio Sync sends every copy (857 MB, 78 s).
5. **Two readers at once.** In the new build the readers can serve each
   other while they pull, and in one of the two runs they did: Warsaw got
   0.67 GB of its 2.2 GB from Amsterdam, the writer sent 3.8 GB instead of
   4.3 GB, and Amsterdam, uploading while it downloaded, took 90 s instead
   of 57 s. In the other run nothing went between the readers (the writer
   sent 4.4 GB, Amsterdam took 54 s). Warsaw finished in 95-101 s either
   way. Resilio Sync's readers exchanged 0.2-0.8 GB in each run, its writer
   sent 3.4 GB, and both readers took 96-108 s. On time the two are about
   even here; on the writer's upload Resilio Sync spreads the load more
   reliably.
6. **A small change after the sync (1 MiB rewritten in a 1 GiB file, 10 MiB
   appended to a 128 MiB log).** This is what the new build set out to fix,
   and on bytes it did: the reader fetched 4 blocks (21-22 MB with peers,
   38 MB on the interface with the bucket's metadata) and reused 1.19 GB of
   its own blocks, where the old build fetched the two files whole (1148
   MB). Resilio Sync sends 12 MB. On time Varsto is still behind: 47 and
   76 s against Resilio Sync's 11-13 s. Both halves cost: the writer's
   part (27-30 s from the change to the end of the push) is mostly its own
   watcher's sync of all five folders, which started two seconds after the
   change and took 25 s (the `mut` push itself took 3.5 s and uploaded 20
   MB); the reader's part (15-46 s) is the service start plus a pull that
   reads and hashes the 1.1 GiB it already has to find the blocks to reuse
   (about 11 s of pull in the first run; the second run's pull took 46 s,
   not explained).
7. **Directory with 1.13 GiB renamed.** The new build moves the files
   without a byte of data: 0.1 MB with peers, 16-17 MB on the interface
   (metadata from the bucket), 1.22 GB reused, in 33-43 s (writer 17-28 s,
   again mostly the all-folders sync; reader 15-16 s). The old build
   fetched everything again (1146 MB, 50 s), and so does Resilio Sync
   (1282 MB, 59-67 s). The reader no longer leaves the old, empty directory
   behind.
8. **Constrained link (40 ms added delay, 1 % loss, 100 Mbit/s on the
   reader's incoming traffic), the 10 000 small files.** Varsto 324-347 s
   both days against Resilio Sync's 594-609 s, with about the same bytes
   (Varsto 331-355 MB on the interface, 295-312 MB with the peer; Resilio
   Sync 321 MB). Varsto's route log shows TCP; which transport Resilio Sync
   used was not recorded. The new build changed nothing here.

### Bug status after c50f260

1. **Pull stops part-way with STUN off: gone.** The same configuration
   (`p2p enable --no-stun --public <ip:port>` on the reader) that stopped
   twice at 8 846 of 10 000 files on 11-07 completed on 11-08: 10 000
   files, 9 474 blocks from the peer, 526 reused, every SHA-256 right, in
   61 s (slower than the 42-47 s with STUN on; one run, so no more than a
   hint). The diagnostic is `BENCH_VARSTO_NO_STUN=1 ... run --scenario
   files-nostun`.
2. **A sync right after the writer restarted fetched nothing: not seen
   again.** 20 Varsto runs on 11-08 (every scenario, both repetitions, the
   diagnostic), none failed and none reported an unavailable file. The
   driver still restarts the reader's service after the writer's, so this
   is "did not recur", not "cannot recur".
3. **Whole files sent again after a change or rename: fixed** (scenarios 6
   and 7 above). The remaining cost of a change is time, not bytes.
4. **Duplicates fetched twice: fixed** (scenario 4; 526 of the 10 000 small
   files were reused too).
5. **Readers do not help each other: works, but not every time** (scenario
   5: 0.67 GB reader to reader in one run, nothing in the other), at the
   price of a slower first reader when it does.
6. Still open: the writer's peak RSS (0.4-0.8 GiB against Resilio Sync's
   0.07-0.25 GiB); the writer service syncing all five folders every 10-20 s
   for minutes after a change (its log on 11-08 shows `sync start subject=
   "all folders"` back to back, 7-25 s each), which is what made the change
   steps' writer time 17-30 s; the empty-directory leftover of 11-07 is gone.

## Versions

| | |
|---|---|
| Varsto, 11-07 | 0.0.1-alpha.16, the published daily build 20261106-46adda3 (`varsto-daily-linux-x86_64.tar.gz`, SHA-256 `1586764462f9cc7091bb89653767b5fc592f14398ba0a45c3151bf9282a8b475`). The pull-request build asked for first (CI runs 42378887990, 42379173190, 42379813594, 42382193499 of PR #124) had no Linux package when the machines were set up |
| Varsto, 11-08 | 0.0.1-alpha.16, the published daily build 20261108-c50f260 (same file name, SHA-256 `e33757f363108ca964f54d016a08be4ed5adbbdbcaf05a244e32253b159d42c2`, checked against the site's `SHA256SUMS`), built from `main` at c50f260 |
| Resilio Sync | 2.8.1 (1390), Linux x64, from `https://download-cdn.resilio.com/2.8.1.1390/linux/x64/0/resilio-sync_x64.tar.gz` (SHA-256 `5eb7c4d9fac3c4e4b7d8ccceee0a4912c31dd1663e6fb4d2d21fc7f7833b3f2e`), both days. See "Why not Resilio Sync 3.1" |
| Scripts | `scripts/bench/resilio-vs-varsto.py` (driver, uses `p2p-bench.py`), `bench-tools.py`, `bench-node.sh`, `gen-data.py`, at the commit that adds this page (the 11-08 version; the 11-07 run used the previous commit of the branch, whose differences are in "Method") |

## Machines and link

Three Scaleway POP2-2C-8G (2 vCPU AMD EPYC 7543, 8 GB, 40 GB block volume,
Ubuntu 24.04, kernel 6.8) each day, new machines on 11-08 (the same public
addresses were handed out again): the writer in Paris (fr-par-1), readers
in Amsterdam (nl-ams-1) and Warsaw (pl-waw-1). Measured once before the
runs each day (11-07 / 11-08):

| Path | Round trip (ping, mean) | TCP, writer sends (iperf3 -R, 1 stream / 4 streams) |
|---|---|---|
| Paris - Amsterdam | 12.1 / 12.2 ms | 570 / 415 and 571 / 415 Mbit/s |
| Paris - Warsaw | 33.0 / 33.0 ms | 421 / 416 and 401 / 440 Mbit/s |
| Amsterdam - Warsaw | 21.8 / 21.8 ms | |

With four streams iperf3 reached about 415-440 Mbit/s; the fastest pull
here (Varsto, 2 GiB in 43-47 s) averaged 365-400 Mbit/s. One 256 MiB
object from the bucket in one stream: 93-149 MB/s in Paris, 112-152 MB/s
in Amsterdam.

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
- **Second run (2026-11-08), what changed in the procedure.** In build
  c50f260 a paused service stops its peer-to-peer part, so nothing is paused
  any more, and `folder attach` on the running reader service starts the
  pull by itself. Varsto's time is therefore, like Resilio Sync's, from the
  moment the reader is told about the folder (`POST /api/folder/attach`) to
  the first poll (every 0.25 s) that sees every file at its size, confirmed
  by the SHA-256 check; its pull report (blocks from peers, blocks reused
  locally) is read from the service log. For the change and rename steps
  the reader's service is stopped while the writer publishes the change
  (the writer's time runs from the change to the end of its `POST
  /api/sync`, which its own watcher may already have started) and the
  bucket's new blocks are deleted; the reader's time is then from its
  service start to the complete folder. The writer's bytes sent to each
  reader (iptables) are recorded in every step. The reader's service is
  restarted after the writer's in every run (the 11-07 run did this from
  its third `large` run on).
- **Constrained link**: `tc netem delay 40ms loss 1% rate 100mbit` on the
  reader's incoming traffic (through an `ifb` device, so it shapes the
  direction in which the data arrives), removed after the run.
- At least two repetitions per scenario; the tables give medians (with two
  runs, the mean of the two); the single runs are in the raw data.

## Every run

### 2026-11-07, Varsto 46adda3

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
under "Varsto findings" (11-07). Writer-side preparation, not timed in the
runs: Varsto's pushes of all five sets into the bucket took 94 s (`files`
5.9 s, `pair` 48.6 s, `text` 9.0 s storing 160 MB, `dup` 7.0 s storing
408 MB, `mut` 23.7 s); Resilio Sync indexed the five folders in 21 s (the
data was in the page cache after the pushes).

### 2026-11-08, Varsto c50f260

| Scenario | Step | Tool | Rep | Reader | Time s | Wire MB | Reader CPU s | Verified | Note |
|---|---|---|---|---|---|---|---|---|---|
| files | initial | resilio | 1 | ams | 25.46 | 313.4 | 11.13 | identical |  |
| files | initial | varsto | 1 | ams | 41.96 | 293.7 | 11.29 | identical |  |
| files | initial | resilio | 2 | ams | 311.2 | 313.4 | 12.2 | identical |  |
| files | initial | varsto | 2 | ams | 46.63 | 295.3 | 11.55 | identical |  |
| large | initial | varsto | 1 | ams | 42.41 | 2176.6 | 14.99 | identical |  |
| large | initial | resilio | 1 | ams | 117.86 | 2249.7 | 22.01 | identical |  |
| large | initial | resilio | 2 | ams | 99.85 | 2249.3 | 21.87 | identical |  |
| large | initial | varsto | 2 | ams | 43.57 | 2180.9 | 13.48 | identical |  |
| text | initial | varsto | 1 | ams | 19.26 | 170.0 | 2.28 | identical |  |
| text | initial | resilio | 1 | ams | 63.22 | 563.3 | 7.36 | identical |  |
| text | initial | resilio | 2 | ams | 63.22 | 563.1 | 7.08 | identical |  |
| text | initial | varsto | 2 | ams | 15.0 | 170.2 | 2.29 | identical |  |
| dup | initial | varsto | 1 | ams | 11.93 | 419.2 | 2.8 | identical |  |
| dup | initial | resilio | 1 | ams | 77.74 | 856.6 | 11.64 | identical |  |
| dup | initial | resilio | 2 | ams | 78.24 | 856.4 | 11.25 | identical |  |
| dup | initial | varsto | 2 | ams | 14.44 | 422.9 | 2.97 | identical |  |
| two-readers | initial | varsto | 1 | ams | 90.44 | 2234.0 | 15.83 | identical |  |
| two-readers | initial | varsto | 1 | waw | 101.45 | 2197.8 | 15.06 | identical |  |
| two-readers | initial | resilio | 1 | ams | 107.61 | 2741.2 | 28.16 | identical |  |
| two-readers | initial | resilio | 1 | waw | 101.59 | 2826.8 | 27.34 | identical |  |
| two-readers | initial | resilio | 2 | ams | 95.6 | 3107.7 | 30.47 | identical |  |
| two-readers | initial | resilio | 2 | waw | 96.08 | 2414.3 | 24.07 | identical |  |
| two-readers | initial | varsto | 2 | ams | 54.16 | 2190.9 | 14.53 | identical |  |
| two-readers | initial | varsto | 2 | waw | 95.43 | 2195.1 | 12.23 | identical |  |
| change+rename | initial | varsto | 1 | ams | 32.29 | 1141.1 | 7.06 | identical |  |
| change+rename | change | varsto | 1 | ams | 46.63 | 35.8 | 2.64 | identical | push 31.3 s + pull 15.34 s |
| change+rename | rename | varsto | 1 | ams | 42.87 | 16.3 | 2.19 | identical | push 27.78 s + pull 15.08 s |
| change+rename | initial | resilio | 1 | ams | 72.82 | 1265.7 | 12.91 | identical |  |
| change+rename | change | resilio | 1 | ams | 10.15 | 12.1 | 3.14 | identical |  |
| change+rename | rename | resilio | 1 | ams | 72.15 | 1276.6 | 12.91 | identical |  |
| change+rename | initial | resilio | 2 | ams | 66.07 | 1276.5 | 12.74 | identical |  |
| change+rename | change | resilio | 2 | ams | 19.25 | 12.2 | 3.25 | identical |  |
| change+rename | rename | resilio | 2 | ams | 60.92 | 1287.1 | 13.02 | identical |  |
| change+rename | initial | varsto | 2 | ams | 35.71 | 1147.3 | 7.19 | identical |  |
| change+rename | change | varsto | 2 | ams | 76.15 | 39.8 | 2.8 | identical | push 30.27 s + pull 45.88 s |
| change+rename | rename | varsto | 2 | ams | 33.48 | 17.0 | 2.32 | identical | push 17.4 s + pull 16.09 s |
| netem | initial | varsto | 1 | ams | 323.54 | 331.0 | 19.93 | identical |  |
| netem | initial | resilio | 1 | ams | 593.68 | 321.4 | 31.53 | identical |  |
| netem | initial | resilio | 2 | ams | 604.32 | 321.5 | 32.0 | identical |  |
| netem | initial | varsto | 2 | ams | 347.06 | 333.1 | 20.58 | identical |  |
| files-nostun | initial | varsto | 1 | ams | 61.1 | 319.0 | 12.44 | identical |  |

`files-nostun` is the diagnostic run described under "Bug status". Writer-
side preparation on 11-08: Varsto's pushes of the five sets took 96 s in
all; Resilio Sync indexed the five folders in 20 s. The first Varsto
`files` run of the day was repeated because the driver had not captured its
pull report (its time, 39 s, was in line with the two kept).

## Limits of this measurement

- Two repetitions per day, one machine type, two days. Differences of
  less than about a third between the tools should not be read as real:
  Resilio Sync's text pull, for example, took 38 s one day and 63 s the
  next with nothing changed on its side.
- Resilio Sync 2.8.1 is the last 2.x release; the current stable is 3.1.2,
  which could not be run this way (below). 3.x may behave differently.
- Resilio Sync has no tracker or relay here and is given the peers'
  addresses; Varsto finds them through the bucket. Neither reflects the
  setup most users have.
- Varsto's time to propagate a change leaves out its reader's scheduling
  (the reader is started for the pull; on 11-07 also its detection on the
  writer); Resilio Sync's includes both. For changes, compare the bytes
  more than the seconds.
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

## Varsto findings of 2026-11-07 (build 46adda3)

These came up while setting the first run up; their status after c50f260
is under "Bug status" above.

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
