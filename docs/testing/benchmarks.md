# Benchmarks and NAT tests

Measurement tools for speed and peer-to-peer behaviour. They are not part of the pass/fail test levels: they produce numbers. Written from the scripts in `scripts/bench` and `scripts/nat-test`; if they disagree with this page, the scripts are right.

The website page `website/src/pages/benchmarks.html` reports results of these tools. Its data file is `website/src/data/benchmarks-2026-10.json`, which `website/build.py` copies to `data/` on the site as it is (every `website/src/data/*.json` except `daily.json`). The numbers on the page are for the code of those days; they are not re-measured on every build.

## What needs rented machines

`p2p-bench.py` and `home-nat.py` create short-lived machines with the Scaleway command line (`scw`, configured with a project that has this machine's SSH key), tag them `varsto-build` and delete them (and the temporary bucket) with their `down` step. They need `rclone` and `scw` on this machine, and they import `scripts/cloud-build/scw-build.py` for the machine handling (see [BUILDING.md](../../BUILDING.md), "Scaleway fallback"). If a run is interrupted, `scripts/cloud-build/scw-build.py cleanup` deletes leftover machines. They cost money; run `down` when finished. Do not run them in CI.

## `scripts/bench/p2p-bench.py`: peer-to-peer versus object storage

Measures, across countries, how fast a folder is pulled to a fresh device from a bucket (`s3` mode) and from another device (`p2p` mode), and how fast a vault is pushed. One writer in Paris (fr-par-1) and readers in Amsterdam (nl-ams-1) and Warsaw (pl-waw-1) share a vault whose metadata is in a temporary bucket. Every reader run joins as a fresh device and times `POST /api/sync` until the folder is complete; Varsto checks content hashes on the way in and the driver compares sha256 lists afterwards. In `p2p` mode the bucket's blocks are deleted first (`purge-chunks`), and a run whose pull report shows fewer blocks from peers than downloaded fails.

Steps, in order (`python3 scripts/bench/p2p-bench.py <step> [options]`):

| Step | Does |
|---|---|
| `up` | Creates the three machines (`--type`, default `POP2-4C-16G`; `--disk-gb`, default 80) and the bucket |
| `setup` | Packages, the binary (`--binary`, default `target/x86_64-unknown-linux-musl/release/varsto`, a static musl build), the helper `bench-node.sh` |
| `baseline` | `ping`, `iperf3` and plain S3 downloads between the zones |
| `gen` | Generates the data sets on the writer (`--sets small,big,text`; `--files`, `--text-mib`) with `gen-data.py` |
| `writer` | The vault with the bucket as storage, one folder per data set |
| `push-local`, `push-ram`, `push-s3` | Timed pushes to a directory on the writer's disk, into tmpfs (Varsto's CPU work only), and into the bucket |
| `run --mode s3\|p2p --set small\|big\|text --readers ams,waw [--reps 2 --rep-start 1 --variant LABEL]` | Timed pulls |
| `purge-chunks` | Deletes every block object from the bucket (before `p2p` runs) |
| `down` | Deletes machines, volumes, IPs and the bucket |

Work directory: `--work` or `BENCH_WORK`, default `dist/bench` (git-ignored). State is in `state.json`; **results go to `results.jsonl`** there, one JSON line per measurement.

Data sets (`scripts/bench/gen-data.py <small|files|big|large|text> <dir>`): `small` many small files in nested directories (default 50 000, sizes log-normal around 16 KiB, one file in twenty a copy), `files` the same shape with 10 000 files, `big` four 2 GiB and one 4 GiB incompressible files, `large` two 2 GiB files, `text` compressible log-like text (default 512 MiB). The layout comes from a fixed seed; the bytes come from the operating system.

From results to the website page:

```bash
python3 scripts/bench/report.py dist/bench/results.jsonl > website/src/data/benchmarks-<date>.json
python3 scripts/bench/page.py website/src/data/benchmarks-<date>.json website/src/pages/benchmarks.html
python3 website/build.py
```

`report.py` takes several result files and writes medians per configuration (runs with a `--variant` label stand for earlier builds, kept for comparison). `page.py` replaces the text between the `<!-- fragment: name -->` markers of the page source (the tables and the inline-SVG charts) and leaves the prose alone; the prose, the Finnish, Swedish and French pages and the filename of the data file (`benchmarks-2026-10.json` is linked from the pages) are edited by hand.

`bench-node.sh` runs on each machine (`setup`, `svc-start`, `svc-stop`, `wait-sync`, `api`, `timed-sync`, `proc`, `hashes`); the driver calls it. You do not run it yourself.

## `scripts/bench/resilio-vs-varsto.py`: Varsto peer-to-peer against Resilio Sync

The same three machines and bucket as `p2p-bench.py` (it imports it; default work directory `dist/bench-resilio`, machines POP2-2C-8G with 40 GB), with Resilio Sync on them too. Both tools pull the same data sets from the writer in Paris, one tool at a time, relays, trackers and rendezvous off; Varsto in p2p mode (the bucket's blocks deleted). Per run and reader it records the time to a folder whose every SHA-256 matches the writer's list, the bytes on the reader's interface and with the peers (iptables), CPU seconds and peak RSS of both daemons. Steps: `up`, `setup --binary <varsto> --build LABEL`, `baseline`, `gen` (sets `files`, `pair`, `text`, `dup`, `mut` of `gen-data.py`), `writer`, `rsl-writer`, then `plan` (every scenario, both tools, two repetitions; `--only`, `--stop-after-min`) or single `run --tool varsto|resilio --scenario NAME --set SET [--readers ams,waw] [--netem "..."]`, `report [--detail]` (Markdown medians), and `down` (or `p2p-bench.py down` with the same `--work`). `bench-tools.py` is its helper on the machines (manifests, the completion poll, the changes, counters); `bench-node.sh` has `netem-on`/`netem-off` (netem on the incoming traffic through `ifb0`), `acct`, `dropcaches` and `rsl-install` for it. Resilio Sync is the last 2.x release: 3.1 does not sync from a configuration file (see the report). Results and the method in detail: [resilio-vs-varsto-2026-11.md](resilio-vs-varsto-2026-11.md).

## `scripts/bench/netem-local.sh`: one machine, an emulated long link

Peer to peer against an S3 bucket on one machine, over an emulated link: a network namespace of its own (`unshare -Urn`, no root needed) whose loopback gets `tc netem` delay and rate, `rclone serve s3` inside it, a writer and a reader. The reader downloads a folder through its background service, timed, in modes `s3` (peer-to-peer off), `p2p` (the bucket's packs moved away) and `both`.

```bash
scripts/bench/netem-local.sh <varsto binary> <data dir> <work dir> [modes] [delay ms each way] [rate]
# defaults: modes "s3 p2p both", 16 ms each way (32 ms round trip), 800mbit
```

Needs `rclone`, `tc`, `python3`, `bc`. Prints one JSON line per run on standard output (`kind`, `mode`, `seconds`, `mb_s`, `chunks`, `from_peers`, bytes, and whether the files were identical). Nothing is written to the repository. The website page quotes its results in the text.

## `scripts/bench/ui-latency.py`: how fast the interface answers

Times the requests the interface makes (`GET /api/...`) against the local service, idle and while a sync and a verification hold the engine, on a synthetic vault with many files; optionally drives the page in Chromium (Playwright) and counts long tasks, requests and the JS heap.

```bash
python3 scripts/bench/ui-latency.py <varsto binary> <work dir> [--files 50000] [--rounds 5] [--busy-seconds 40] [--browser 60] [--browser-only] [--json out.json]
```

Everything lives under `<work dir>` (a throw-away `--home`, folders and a local storage); keep a few GB free there. Re-running with the same directory reuses the vault; the first run's initial sync of 50 000 files takes a few minutes. Results are printed, and written to `--json` if given. It does not feed the website page.

## `scripts/nat-test/home-nat.py`: peer-to-peer through real NATs

Measures transfers between this machine (behind a home router, with the installed `varsto` and its background service, used for real) and cloud machines: "ams" (public address, the relay) and "waw-cone" and "waw-sym" (network namespaces on the Warsaw machine behind iptables NAT: MASQUERADE, and MASQUERADE `--random-fully` for a symmetric mapping, set up by `nat-node.sh`). The bucket holds the ledger and rendezvous records only; before every pull its blocks are deleted, so a transfer counts only when the file arrives with the right SHA-256 and the pull reports every block from peers.

Steps (`python3 scripts/nat-test/home-nat.py <cmd> [options]`):

| Step | Does |
|---|---|
| `up [--type DEV1-M]` | Bucket in fr-par and machines in nl-ams-1 and pl-waw-1 |
| `setup --package <linux tar.gz>` | The binary and the NAT namespaces on the machines |
| `vault` | The vault on Amsterdam; the Warsaw devices and this machine join it |
| `baseline` | Round trips, single-stream TCP both ways, a bucket download |
| `run [--mb 64] [--only src:dst,...]` | Transfers in every direction, from peers only |
| `shots --out <dir> [--delay 3.0]` | Screenshots of this machine's Peers page during a transfer (default `dist/nat-test/shots`) |
| `restart` | Restarts the services (with automatic verification off, so it does not read blocks from the bucket whose blocks the test deletes) |
| `s3` | The same kind of download from the bucket, to compare |
| `down` | Deletes the machines and the bucket |
| `local-reset` | Stops this machine's service and moves its vault aside (do this before `vault` if it holds another vault) |

Work directory: `--work` or `NAT_WORK`, default `dist/nat-test`; **results go to `results.jsonl`** there. The `--home-folder` option (default `~/Varsto NAT test`) is the folder on this machine. The home-NAT section of the website page comes from these runs and is written by hand (it is in the text only, not in the JSON).

For NAT behaviour inside a closed environment without rented machines, use the VM lab ([lab.md](lab.md)): its two routers are a cone and a symmetric NAT, and `crates/varsto-core/tests/nat.rs` tests QUIC transfer, certificate pinning and relayed fetch on localhost (no real NAT; the traversal logic is covered by unit tests).

## When to run these

Not before every release. Run the benchmarks after a change to the transfer path (block size, peer-to-peer, compression, pull order) and when the website page needs fresh numbers; say in the page what build was measured.
