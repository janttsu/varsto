# The VM lab: runbook

The lab is a small internet made of virtual machines on one Linux host. It plays the multi-device scenarios that need real networks: pairing, peer-to-peer through NAT, storage outages, clock skew, scale and more. This page tells how to bring it up, run every scenario, read the results and tear it down, from nothing. It is written from `scripts/test/lab/lab.py` and `scripts/test/lab/scenarios.py`; if the two disagree with this page, the scripts are right and this page needs a fix.

For the other test levels see [TESTING.md](../../TESTING.md). For building binaries see [BUILDING.md](../../BUILDING.md).

**A release needs every scenario.** Run the whole list (`scenarios.py` with no `--only`) against the exact binary that is to be released, not only the scenarios of the areas that changed. A change in one area breaks others in ways nobody predicts. [HANDOVER.md](../../HANDOVER.md) says when the last full run was done.

## What the lab is

All libvirt networks are isolated: nothing reaches the real LAN or the internet.

| Network | Range | Role |
|---|---|---|
| `vl-wan` | `198.51.100.0/24` (documentation range, "the internet") | The host is `.1` (S3 on port 9900, STUN on UDP 3478, the rendezvous service on TCP 8790 and UDP 3334). `vl-pub` is `.20`. The outside addresses of the two routers are `.11` and `.12`. |
| `vl-home` | `10.78.1.0/24` | A home LAN behind `vl-rhome` (`.254`, a cone NAT: nftables masquerade). |
| `vl-office` | `10.78.2.0/24` | An office LAN behind `vl-roffice` (`.254`, a symmetric NAT: masquerade with `fully-random`). |

| VM | Memory | Network | Role |
|---|---|---|---|
| `vl-rhome` | 512 MiB | home + wan | cone NAT router |
| `vl-roffice` | 512 MiB | office + wan | symmetric NAT router |
| `vl-pub` | 1536 MiB | wan | a device with a public address; also a second STUN server (`.20`) |
| `vl-laptop` | 1536 MiB | home (`.10`) | device |
| `vl-desktop` | 1536 MiB | home (`.11`) | device |
| `vl-work` | 1536 MiB | office (`.10`) | device |
| `vl-build` | 8192 MiB, 8 vCPUs, 40 GB disk | libvirt `default` NAT network | build machine, not part of the test network; created by `lab.py build` |

Every other VM has 2 vCPUs and a 12 GB thin disk. The six lab VMs need about 7 GiB of RAM together, the build VM 8 GiB more. The devices' default route is their router; the host also holds `.1` on the home and office bridges, for SSH only.

Every name starts with `vl-` (VMs, networks, the pool `vl-pool`). `lab.py down` touches nothing else.

## Host prerequisites

- Linux with libvirt and QEMU/KVM: `virsh`, `qemu-img`, `/dev/kvm`, and UEFI firmware for libvirt (the VMs boot with `firmware='efi'`).
- Your user can use `qemu:///system` without root (member of the `libvirt` group). Set `VARSTO_LIBVIRT_URI` to use another URI.
- The libvirt network `default` exists and is active. The routers get a temporary NIC on it to install nftables, and the build VM lives on it.
- Tools: `ssh`, `scp`, `ssh-keygen`, `rsync`, `curl`, `sha512sum`, `xorriso` (for the cloud-init seed), `python3`, and `rclone` (a current one: the host runs `rclone serve s3`).
- Free ports on the host's `198.51.100.1` address once the network exists: TCP 9900, UDP 3478, TCP 8790, UDP 3334.
- Disk: the lab directory (default `/mnt/ssd/varsto-lab`, set `VARSTO_LAB_DIR`) holds the base image, the VM disks, the S3 bucket data and built binaries. The scripts do not state how much space they need. The scale scenarios write 20 000 files and 1 GiB, so keep tens of GB free (an estimate, not a measurement). The build VM's cargo target directory lives inside the VM disk.
- Internet access on the host the first time (Debian cloud image) and for the build VM (Rust, crates, packages). The device VMs have no internet.
- A host build of the rendezvous service, copied to `<lab dir>/bin/varsto-rendezvous` (or elsewhere, with `VARSTO_LAB_RENDEZVOUS_BIN`). Without it `lab.py services` still starts, but the rendezvous scenarios fail:

  ```bash
  cargo build --release -p varsto-rendezvous
  mkdir -p /mnt/ssd/varsto-lab/bin
  cp target/release/varsto-rendezvous /mnt/ssd/varsto-lab/bin/
  ```

- Optional: for the `restic` scenario a static restic binary on the host (`VARSTO_LAB_RESTIC`, default `/usr/bin/restic`) is copied to the VM when the VM cannot install one.
- Optional: the `upgrade-from-alpha-15` scenario downloads the released alpha.15 Linux package from GitHub on the host (checked against that release's `SHA256SUMS`). It needs internet on the host.

## Where things live

All under the lab directory `DIR` (`VARSTO_LAB_DIR`, default `/mnt/ssd/varsto-lab`):

| Path | What |
|---|---|
| `debian-13-genericcloud-amd64.qcow2` | Base image (Debian 13, from `cloud.debian.org`, SHA-512 checked). A copy in `~/.cache/varsto-test/images/` is used instead of downloading. |
| `pool/` | The libvirt directory pool `vl-pool`: base volume, per-VM qcow2 disks and seed ISOs. |
| `vms/<vm>/` | cloud-init files and the generated `domain.xml`. |
| `id_ed25519` (+ `.pub`) | The lab's SSH key, made on first use. The VMs accept only this key. |
| `s3/<bucket>/` | The data of the lab S3 server. Scenarios use the bucket `vault1`. |
| `run/` | `pids.json`, `s3.log`, `stun.log`, `rendezvous.log` of the host services. |
| `varsto-musl` | The last binary built by `lab.py build`. |
| `bin/varsto-rendezvous` | The rendezvous service binary (you put it there). |
| `release/<version>/` | Output of `lab.py release`. |
| `scenarios.lock` | Lock file: only one `scenarios.py` run at a time. |

In the repository (git-ignored): `test-results/lab/results.json` and `test-results/lab/logs/<scenario>/<vm>/`.

Inside the device VMs: user `varsto` (passwordless sudo), the binary in `/opt/varsto/varsto` linked as `/usr/local/bin/varsto`, test data in `~/data`, the vault in `~/.local/share/varsto`.

Constants in `lab.py`: S3 endpoint `http://198.51.100.1:9900` with the fixed lab credentials (`vlab-access` / `vlab-secret-key-123`, valid only on the isolated lab network), STUN `198.51.100.1:3478` and `198.51.100.20:3478`, rendezvous `http://198.51.100.1:8790` (plain HTTP; the devices say `VARSTO_RENDEZVOUS_PLAIN_HTTP=1`).

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `VARSTO_LIBVIRT_URI` | lab.py | libvirt URI, default `qemu:///system` |
| `VARSTO_LAB_DIR` | lab.py | lab directory, default `/mnt/ssd/varsto-lab` |
| `VARSTO_LAB_RENDEZVOUS_BIN` | lab.py | path of the rendezvous binary, default `<dir>/bin/varsto-rendezvous` |
| `VARSTO_LOG` | scenarios.py | log level for every `varsto` run on the VMs, default `debug` (for example `trace`) |
| `VARSTO_LAB_RESTIC` | scenarios.py | static restic binary for the `restic` scenario, default `/usr/bin/restic` |

Scenarios give each `varsto` run on the VMs `VARSTO_PASSPHRASE`, `VARSTO_NO_INSTALL=1`, `VARSTO_LOG` and `VARSTO_S3_SECRET`, and `VARSTO_RENDEZVOUS=off` except in the rendezvous scenarios. Secrets travel in the environment, never on a command line. The lab passphrase and S3 credentials are fixed test values.

## `lab.py` subcommands

Run from the repository root: `python3 scripts/test/lab/lab.py <command>`.

| Command | What it does |
|---|---|
| `up` | Creates the pool, downloads the base image, makes the SSH key, defines and starts the three libvirt networks and the six VMs, waits for SSH (300 s each), sets up the nftables rules on the routers (then removes their temporary uplink) and the helpers on the devices, starts the second STUN server on `vl-pub`, prints `status`. Idempotent: run it again to start VMs that stopped. |
| `services` | Stops any host services of an earlier call, then starts in the background on the host: `rclone serve s3` on `198.51.100.1:9900` (data in `<dir>/s3`, directory cache 5 s), the STUN server on UDP 3478, and the rendezvous service if its binary exists. Prints the pids; they are saved in `run/pids.json`. |
| `services-stop` | Stops those processes. Run it when you are done. |
| `stun-serve [--addr A]` | A minimal STUN server in the foreground. Used by `services` and on `vl-pub`; you do not run it by hand. |
| `build [repo]` | Creates the build VM on first use, installs Rust and musl tools there once, copies the repository (without `target`, `.git`, `website/public`) with rsync, builds `cargo build --release --locked -p varsto-cli --features software-key --target x86_64-unknown-linux-musl`, and copies the binary to `<dir>/varsto-musl`. `repo` defaults to the checkout the script is in. The feature `software-key` is needed by the `strongroom-software-key` scenario; a binary built another way must have it. |
| `install-bin [binary]` | Copies a binary (default `<dir>/varsto-musl`) to `/opt/varsto/varsto` on the four device VMs (`vl-pub`, `vl-laptop`, `vl-desktop`, `vl-work`) and prints each `varsto --version`. |
| `install <package.tar.gz>` | The same from a release package (`varsto-<version>-x86_64-unknown-linux-musl.tar.gz`). |
| `release [--repo R]` | Runs `build`, installs mingw-w64, zip and a JDK and the Android SDK 35 / NDK 27 in the build VM once, runs `website/build-release.sh` for Linux musl and Windows (the cross-compiled programs) and `apps/android/build.sh` (a debug APK, since no signing secrets exist there), and copies the results to `<dir>/release/<version>/`. This is a way to get packages without GitHub Actions; the packages are not signed and the Windows installer is not built (Inno Setup needs Windows). See [BUILDING.md](../../BUILDING.md). |
| `ssh <vm> [cmd...]` | A shell, or one command, on a VM (`lab.py ssh vl-laptop varsto --version`). |
| `status` | One line per lab VM: state, address, role. |
| `down [--all]` | Stops the host services, destroys and undefines the six VMs and deletes their disks, removes the three networks. `--all` also removes the build VM. Kept: base image, SSH key, S3 directory, built binaries. |

## `scenarios.py` options

`python3 scripts/test/lab/scenarios.py [options]`

| Option | Meaning |
|---|---|
| (none) | Run all scenarios in order. |
| `--only A,B` | Run only the named scenarios (comma separated). They still run in list order, not in the order you typed. An unknown name stops the run. |
| `--binary PATH` | Install that binary on all device VMs first (like `lab.py install-bin`), after the lock is taken. |
| `--list` | Print the scenario names in run order and exit. No VM needed. |
| `--check` | Self-check: every scenario registered once, the first is `reset`, the ones that need a docstring have one, the helpers work on a fake bucket. Prints `N scenarios, M problems`. Exit code 1 on a problem. No VM needed. |

Exit code of a real run: the number of scenarios that did not pass (0 means all passed). Each scenario prints `PASS`, `FAIL` (an assertion) or `ERROR` (a helper gave up or an exception), its seconds and the reason. A second run at the same time is refused ("another scenarios.py run is using the lab").

The scenario list is `scenarios.py --list`. The first, `reset`, deletes the vaults and test data on every device, empties the S3 directory, fixes the VMs' clocks and restarts the host services (`services-stop`, then `services`). Later scenarios build on the vault and state the earlier ones made (the same Python process keeps notes between them), so the early ones (`reset`, `init-and-s3-through-nat`, `pair-over-lan`, `sync-to-second-device`) are a prerequisite of many. The code does not list prerequisites per scenario.

## Full run, from nothing

```bash
# 1. Binaries: the lab binary and the rendezvous service
python3 scripts/test/lab/lab.py up
python3 scripts/test/lab/lab.py build            # in the build VM, installs Rust the first time
cargo build --release -p varsto-rendezvous       # on the host
mkdir -p /mnt/ssd/varsto-lab/bin && cp target/release/varsto-rendezvous /mnt/ssd/varsto-lab/bin/

# 2. Services and binary on the devices
python3 scripts/test/lab/lab.py services
python3 scripts/test/lab/lab.py install-bin

# 3. Self-check, then the whole run (stop at the first sign of a broken lab)
python3 scripts/test/lab/scenarios.py --check
python3 scripts/test/lab/scenarios.py 2>&1 | tee lab-run.txt

# 4. Clean up
python3 scripts/test/lab/lab.py services-stop
python3 scripts/test/lab/lab.py down --all        # or leave the VMs for the next run
```

If the host's `cargo` target directory is on a small disk, follow the layout advice in [BUILDING.md](../../BUILDING.md) before the host build of the rendezvous service.

Notes:

- `lab.py up` takes a while the first time (image download, six boots, nftables install). `lab.py build` takes a while the first time (Rust install, a full release build of the workspace in the VM). The scripts print no expected durations and the repository has no measured run times for the whole lab, so a full run's length is not stated here; record it in the report.
- To test the binary CI built instead of one from the build VM, download the Linux package from the run (artifact `packages-linux-windows`, see BUILDING.md) and use `lab.py install <package>` instead of `build` and `install-bin`. Use the lab's own build for the strongroom scenario, or build with `--features software-key`.
- `scenarios.py --binary PATH` combines the install and the run.
- Write the result into a report: [report-template.md](report-template.md).

## Running one scenario or a subset

```bash
python3 scripts/test/lab/scenarios.py --only reset,init-and-s3-through-nat,pair-over-lan,sync-to-second-device,policy
```

Start with `reset` so the run starts clean, and include the scenarios that make the vault the one you want. If a scenario fails at once with a missing vault, folder or key, a scenario before it in `--list` makes that state; add it. Some scenarios (for example `upgrade-from-alpha-15`) build their own vaults and need less, but the code does not say which; try them alone and add predecessors on failure. A passing subset does not replace the full run before a release.

## Results and logs

- `test-results/lab/results.json`: `results` (a list of `scenario`, `status`, `seconds`, `detail`, `logs`) and `context` (measurements and facts the scenarios noted, secrets left out). Written at the end of the run; an interrupted run leaves no file.
- `test-results/lab/logs/<scenario>/<vm>/`: after each scenario, passed or not, the logs of every device VM (Varsto `logs/`, `service.log`, the `~/*.log` outputs of background commands), paths relative to the home of user `varsto`. A failed scenario prints the path. Running a scenario again replaces its directory. The logs hold generated file and folder names and endpoints but never keys, passphrases or recovery words. See also TESTING.md, "Lab logs".
- Host service logs: `<dir>/run/s3.log`, `stun.log`, `rendezvous.log`.
- `test-results/` is git-ignored and CI does not upload lab logs.

## Troubleshooting

- `command failed ... virsh`: you cannot use `qemu:///system`; check the `libvirt` group or `VARSTO_LIBVIRT_URI`.
- `<vm> did not accept SSH within 300 s`: the VM did not boot (UEFI firmware missing, no KVM) or its network is down. `lab.py status`, then `virsh -c qemu:///system console <vm>`.
- The nftables install on a router fails: the `default` libvirt network is not active (`virsh net-start default`).
- Port in use when `services` starts: an old S3 or rendezvous process from another run; `lab.py services-stop`, check `ss -lntup`.
- `no <dir>/bin/varsto-rendezvous: the rendezvous scenarios will fail`: build and copy the rendezvous service (see above).
- `another scenarios.py run is using the lab`: wait, or find the other process. Two runs against the same VMs and bucket ruin both.
- Listings of the S3 bucket lag by up to 5 s (`rclone serve s3` directory cache); scenarios wait for it. A new scenario that deletes bucket objects must wait or poll before asserting.
- The `transmission` torrent scenario needs the build VM: the device VMs have no internet, so the build VM downloads the Debian packages and copies them over. Run `lab.py build` at least once.
- A scenario fails but the cause is unclear: read its logs directory, then re-run it alone with `VARSTO_LOG=trace`.
- Start over: `lab.py down` then `lab.py up`. A leftover state from a crashed run is also cleared by the first scenario, `reset`.

## Other tools that need a lab-like setup

- `scripts/test/provision-vm.sh` and friends: the single-VM `smoke` suite, see TESTING.md.
- `scripts/bench` and `scripts/nat-test`: cross-country measurements on rented machines, see [benchmarks.md](benchmarks.md).
- `scripts/cloud-build`: builds and tests on throw-away Scaleway machines, see [BUILDING.md](../../BUILDING.md).
