#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Cross-country benchmark: peer-to-peer versus object storage.

One writer in Paris (fr-par-1) and two readers, Amsterdam (nl-ams-1) and
Warsaw (pl-waw-1), share a vault whose metadata lives in a temporary
Scaleway bucket in fr-par. Every reader run joins as a fresh device, attaches
an empty folder and times `POST /api/sync` on its background service until
the folder is complete; Varsto checks every chunk's content hash on the way
in and the driver compares sha256 lists afterwards.

    p2p-bench.py up           create the three machines and the bucket
    p2p-bench.py setup        packages, binary, helper scripts
    p2p-bench.py baseline     ping, iperf3 and plain S3 downloads between the zones
    p2p-bench.py gen          generate the data sets on the writer
    p2p-bench.py writer       vault with the bucket as its storage, one folder per data set
    p2p-bench.py push-local   timed pushes into a directory on the writer's disk
    p2p-bench.py push-ram --sets small,text   the same into tmpfs (Varsto's CPU work only)
    p2p-bench.py push-s3      timed pushes into the bucket; starts the writer's service
    p2p-bench.py run --mode s3|p2p --set small|big|text --readers ams,waw [--reps 2]
    p2p-bench.py purge-chunks delete every chunk object from the bucket
    p2p-bench.py down         delete the machines (with volumes and IPs) and the bucket

Modes: `s3` readers have peer-to-peer off, so every block comes from the
bucket. `p2p` runs only after `purge-chunks`: the bucket keeps the ledger,
manifests and device records, the blocks exist on the writer alone, and a
pull report with `chunks_from_peers` below `chunks_downloaded` fails the run.

Needs the `scw` command line configured, rclone, and this machine's SSH key
in the Scaleway project. The Linux binary comes from --binary (a static musl
build). Machines are tagged `varsto-build`, so `scw-build.py cleanup` finds
them too. Results go to <work>/results.jsonl.
"""
import argparse
import concurrent.futures as cf
import importlib.util
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
_spec = importlib.util.spec_from_file_location("scw_build", ROOT / "scripts/cloud-build/scw-build.py")
sb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sb)

TAG = sb.TAG
ZONES = {"par": "fr-par-1", "ams": "nl-ams-1", "waw": "pl-waw-1"}
PORT = 17893
FOLDERS = {"small": "small", "files": "files", "big": "big", "large": "large", "text": "text"}
log = sb.log


class Bench:
    def __init__(self, args):
        self.args = args
        self.work = pathlib.Path(args.work).resolve()
        self.work.mkdir(parents=True, exist_ok=True)
        self.state_file = self.work / "state.json"
        self.state = json.loads(self.state_file.read_text()) if self.state_file.exists() else {}

    def save(self):
        self.state_file.write_text(json.dumps(self.state, indent=2))

    def ip(self, node):
        return self.state["nodes"][node]["ip"]

    def ssh(self, node, cmd, check=True, capture=True):
        p = subprocess.run(sb.ssh_base("root", self.ip(node)) + [cmd], capture_output=capture, text=True)
        if check and p.returncode != 0:
            what = "(command with credentials)" if "VARSTO_S3_SECRET" in cmd or "RCLONE_" in cmd else cmd
            raise SystemExit(f"{node}: remote command failed ({p.returncode}): {what[:60]}\n{(p.stderr or '')[-2000:]}")
        return p.stdout if capture else ""

    def node_sh(self, node, *args, check=True, env=""):
        return self.ssh(node, f"{env} bash /bench/bench-node.sh " + " ".join(shlex.quote(a) for a in args), check=check)

    def record(self, entry):
        entry["utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(self.work / "results.jsonl", "a") as f:
            f.write(json.dumps(entry) + "\n")
        log(f"recorded {entry.get('kind')}: " + json.dumps({k: v for k, v in entry.items() if k in ('mode', 'set', 'readers', 'rep', 'summary')})[:600])

    def s3_env(self):
        env, access, secret = sb.scw_s3_env()
        return env, access, secret

    def s3_flags(self):
        _, access, _ = self.s3_env()
        b = self.state["bucket"]
        return f"--storage-name cloud --s3-endpoint https://s3.fr-par.scw.cloud --s3-region fr-par --s3-bucket {b} --s3-access-key-id {access}"

    def secret_env(self):
        _, _, secret = self.s3_env()
        return f"VARSTO_S3_SECRET={shlex.quote(secret)}"

    # ----- machines -------------------------------------------------------------

    def up(self):
        stamp = int(time.time())
        env, _, _ = self.s3_env()
        if "bucket" not in self.state:
            bucket = f"varsto-bench-{stamp}"
            subprocess.run(["rclone", "mkdir", f"scw:{bucket}"], env=env, check=True)
            self.state["bucket"] = bucket
            self.save()
            log(f"bucket {bucket} created")
        nodes = self.state.setdefault("nodes", {})
        for node, zone in ZONES.items():
            if node in nodes:
                continue
            srv = sb.scw("instance", "server", "create", f"zone={zone}", f"name={TAG}-bench-{node}-{stamp}",
                         f"type={self.args.type}", "image=ubuntu_noble", "ip=new", f"tags.0={TAG}",
                         f"root-volume=sbs:{self.args.disk_gb}GB")
            nodes[node] = {"id": srv["id"], "zone": zone}
            self.save()
            log(f"{node}: created {srv['id']} in {zone}")
        for node, n in nodes.items():
            deadline = time.time() + 900
            while time.time() < deadline:
                s = sb.scw("instance", "server", "get", n["id"], f"zone={n['zone']}")
                ips = [i.get("address") for i in (s.get("public_ips") or []) if i.get("address") and ":" not in i["address"]]
                ip = (s.get("public_ip") or {}).get("address") or (ips[0] if ips else None)
                if s.get("state") == "running" and ip:
                    n["ip"] = ip
                    n["private_ip"] = s.get("private_ip")
                    break
                time.sleep(10)
            else:
                raise SystemExit(f"{node} did not start")
            self.save()
            log(f"{node}: running at {n['ip']}")
        for node in nodes:
            sb.wait_ssh("root", self.ip(node))
        log("all machines answer SSH")

    def down(self):
        env, _, _ = self.s3_env()
        for node, n in self.state.get("nodes", {}).items():
            log(f"{node}: terminating {n['id']} with its volumes and IP")
            subprocess.run(["scw", "instance", "server", "terminate", n["id"], f"zone={n['zone']}", "with-ip=true", "with-block=true"],
                           capture_output=True)
        if self.state.get("bucket"):
            subprocess.run(["rclone", "purge", f"scw:{self.state['bucket']}"], env=env, check=False)
            log(f"bucket {self.state['bucket']} removed")
        time.sleep(20)
        left = {}
        for zone in ZONES.values():
            left[zone] = [s["name"] for s in sb.scw("instance", "server", "list", f"zone={zone}")
                          if (s.get("name") or "").startswith(f"{TAG}-bench-")]
        ips = {zone: [i["address"] for i in sb.scw("instance", "ip", "list", f"zone={zone}") if not i.get("server")]
               for zone in ZONES.values()}
        log(f"bench machines left: {left}; unattached IPs: {ips}")
        buckets = subprocess.run(["rclone", "lsd", "scw:"], env=env, capture_output=True, text=True).stdout
        log("bench buckets left: " + str([l.split()[-1] for l in buckets.splitlines() if "varsto-bench-" in l]))

    def setup(self):
        binary = pathlib.Path(self.args.binary)
        version = subprocess.run([str(binary), "--version"], capture_output=True, text=True).stdout.strip()
        self.state["version"] = version
        self.state["commit"] = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        self.save()

        def one(node):
            ip = self.ip(node)
            self.ssh(node, "mkdir -p /bench")
            sb.scp(str(binary), f"root@{ip}:/bench/varsto")
            sb.scp(str(HERE / "bench-node.sh"), f"root@{ip}:/bench/bench-node.sh")
            sb.scp(str(HERE / "gen-data.py"), f"root@{ip}:/bench/gen-data.py")
            self.node_sh(node, "setup")
            return node, self.ssh(node, "nproc; free -g | sed -n 2p; lscpu | grep 'Model name'; uname -r; "
                                        "dd if=/dev/zero of=/bench/dd.tmp bs=1M count=2048 oflag=direct 2>&1 | tail -1; rm -f /bench/dd.tmp")
        with cf.ThreadPoolExecutor(3) as ex:
            info = dict(ex.map(one, self.state["nodes"]))
        self.record({"kind": "machines", "version": version, "commit": self.state["commit"], "type": self.args.type,
                     "info": info, "zones": ZONES})

    # ----- baselines ------------------------------------------------------------

    def baseline(self):
        out = {"kind": "baseline", "ping": {}, "iperf3": {}, "s3": {}}
        nodes = list(ZONES)
        for a in nodes:
            for b in nodes:
                if a < b:
                    r = self.ssh(a, f"ping -c 30 -i 0.2 -q {self.ip(b)} | tail -1")
                    out["ping"][f"{a}-{b}"] = r.strip()
        self.ssh("par", "pkill -x iperf3 || true; iperf3 -s -D")
        time.sleep(1)
        for r in ("ams", "waw"):
            # -R: the writer sends, the reader receives, as in a pull.
            j = json.loads(self.ssh(r, f"iperf3 -c {self.ip('par')} -t 15 -R -J"))
            out["iperf3"][f"par->{r}"] = {"mbit_s": j["end"]["sum_received"]["bits_per_second"] / 1e6,
                                         "retransmits": j["end"].get("sum_sent", {}).get("retransmits")}
            j = json.loads(self.ssh(r, f"iperf3 -c {self.ip('par')} -t 15 -R -P 4 -J"))
            out["iperf3"][f"par->{r} 4 streams"] = {"mbit_s": j["end"]["sum_received"]["bits_per_second"] / 1e6}
        self.ssh("par", "pkill -x iperf3 || true")
        # Plain S3 from each machine: one 256 MiB object in one stream, and
        # 200 objects of 4 KiB one after another (per-request latency).
        _, access, secret = self.s3_env()
        rc = (f"RCLONE_CONFIG_S_TYPE=s3 RCLONE_CONFIG_S_PROVIDER=Scaleway RCLONE_CONFIG_S_REGION=fr-par "
              f"RCLONE_CONFIG_S_ENDPOINT=s3.fr-par.scw.cloud RCLONE_CONFIG_S_ACCESS_KEY_ID={access} "
              f"RCLONE_CONFIG_S_SECRET_ACCESS_KEY={shlex.quote(secret)}")
        b = self.state["bucket"]
        self.ssh("par", f"mkdir -p /bench/s3base/small && head -c 268435456 /dev/urandom > /bench/s3base/blob && "
                        f"for i in $(seq 1 200); do head -c 4096 /dev/urandom > /bench/s3base/small/o$i; done && "
                        f"{rc} rclone copy /bench/s3base s:{b}/baseline --transfers 16 && rm -rf /bench/s3base")
        for r in nodes:
            t = self.ssh(r, f"rm -rf /bench/s3dl; s=$(date +%s.%N); {rc} rclone copyto s:{b}/baseline/blob /bench/s3dl/blob "
                            f"--multi-thread-streams 0; e=$(date +%s.%N); echo \"$s $e\"")
            s, e = map(float, t.split())
            t2 = self.ssh(r, f"s=$(date +%s.%N); {rc} rclone copy s:{b}/baseline/small /bench/s3dl/small --transfers 1 --checkers 1 "
                             f"--s3-no-head-object; e=$(date +%s.%N); echo \"$s $e\"; ls /bench/s3dl/small | wc -l; rm -rf /bench/s3dl")
            s2, e2, n = t2.split()
            out["s3"][r] = {"one_stream_256mib_mb_s": 256 * 1.048576 / (e - s), "small_4kib_objects": int(n),
                            "small_ms_per_object": (float(e2) - float(s2)) * 1000 / max(1, int(n))}
        env, _, _ = self.s3_env()
        subprocess.run(["rclone", "purge", f"scw:{b}/baseline"], env=env, check=False)
        self.record(out)

    # ----- data and writer --------------------------------------------------------

    def gen(self):
        sets = self.args.sets.split(",")
        for s in sets:
            extra = f" --files {self.args.files}" if s == "small" and self.args.files else (f" --mib {self.args.text_mib}" if s == "text" else "")
            t = time.time()
            log(self.ssh("par", f"rm -rf /bench/data/{s} && python3 /bench/gen-data.py {s} /bench/data/{s}{extra}").strip())
            log(f"{s} generated in {time.time() - t:.0f} s")
            n = self.node_sh("par", "hashes", f"/bench/data/{s}", f"/bench/{s}.sha").strip()
            for r in ("ams", "waw"):
                subprocess.run(sb.ssh_base("root", self.ip("par")) + [f"cat /bench/{s}.sha"], stdout=open(self.work / f"{s}.sha", "w"), check=True)
                sb.scp(str(self.work / f"{s}.sha"), f"root@{self.ip(r)}:/bench/{s}.sha")
            du = self.ssh("par", f"du -sb /bench/data/{s} | cut -f1").strip()
            self.record({"kind": "dataset", "set": s, "files": int(n), "bytes": int(du)})

    def timed(self, node, cmd, env=""):
        """Run a varsto command under /usr/bin/time -v; returns wall, CPU and peak memory."""
        t = time.time()
        out = self.ssh(node, f"{env} VARSTO_PASSPHRASE=bench-passphrase /usr/bin/time -v -o /bench/last.time {cmd}")
        wall = time.time() - t
        tv = self.ssh(node, "cat /bench/last.time")
        return wall, out, parse_time_v(tv)

    def warm(self, s):
        """Read the data set once so the timed push measures Varsto, not the
        cold random reads of network block storage (about 200 small files/s)."""
        self.ssh("par", f"tar cf - -C /bench/data {s} | cat > /dev/null")

    def writer(self):
        v = "/bench/varsto --home /bench/w"
        # A new vault every time: empty the bucket of any earlier attempt.
        env, _, _ = self.s3_env()
        subprocess.run(["rclone", "delete", f"scw:{self.state['bucket']}"], env=env, check=False)
        self.node_sh("par", "svc-stop", "/bench/w", check=False)
        key_cmd = f"{v} init --name writer-paris --json"
        self.ssh("par", f"rm -rf /bench/w /bench/w.*; VARSTO_PASSPHRASE=bench-passphrase {key_cmd} > /bench/init.json")
        self.state["vault_key"] = json.loads(self.ssh("par", "cat /bench/init.json"))["vault_key"]
        self.save()
        _, access, _ = self.s3_env()
        self.ssh("par", f"{self.secret_env()} VARSTO_PASSPHRASE=bench-passphrase {v} storage add-s3 cloud --endpoint https://s3.fr-par.scw.cloud "
                        f"--region fr-par --bucket {self.state['bucket']} --access-key-id {access}")
        for s in self.args.sets.split(","):
            self.ssh("par", f"VARSTO_PASSPHRASE=bench-passphrase {v} folder add {s} /bench/data/{s}")

    def push_local(self):
        """The same push into a directory on the writer's own disk (network
        block storage here: every object is written with fsync)."""
        lv = "/bench/varsto --home /bench/wl"
        for rep in range(self.args.rep_start, self.args.rep_start + self.args.reps):
            for s in self.args.sets.split(","):
                self.ssh("par", f"rm -rf /bench/wl /bench/localstore && export VARSTO_PASSPHRASE=bench-passphrase && "
                                f"{lv} init --name local-only >/dev/null && {lv} storage add-local disk /bench/localstore && "
                                f"{lv} folder add {s} /bench/data/{s}")
                self.warm(s)
                wall, out, tv = self.timed("par", f"{lv} --json push {s}")
                self.record({"kind": "push", "target": "local-disk", "set": s, "rep": rep, "wall": wall, "time": tv, "report": json.loads(out)})
                self.ssh("par", "rm -rf /bench/wl /bench/localstore")

    def push_s3(self):
        """The writer's real push into the bucket, then its service with peer-to-peer on."""
        v = "/bench/varsto --home /bench/w"
        for s in self.args.sets.split(","):
            self.warm(s)
            wall, out, tv = self.timed("par", f"{v} --json push {s}", env=self.secret_env())
            self.record({"kind": "push", "target": "s3-fr-par", "set": s, "rep": 1, "wall": wall, "time": tv, "report": json.loads(out)})
        self.ssh("par", f"VARSTO_PASSPHRASE=bench-passphrase {v} p2p enable --port {PORT}")
        self.writer_service(restart=True)

    def push_ram(self):
        """The push into a directory in RAM (tmpfs): what is left is Varsto's
        own work (chunking, hashing, zstd, encryption), no disk latency."""
        lv = "/bench/varsto --home /bench/wl"
        for rep in range(self.args.rep_start, self.args.rep_start + self.args.reps):
            for s in self.args.sets.split(","):
                self.ssh("par", f"rm -rf /bench/wl /dev/shm/store && export VARSTO_PASSPHRASE=bench-passphrase && "
                                f"{lv} init --name ram-only >/dev/null && {lv} storage add-local ram /dev/shm/store && "
                                f"{lv} folder add {s} /bench/data/{s}")
                self.warm(s)
                wall, out, tv = self.timed("par", f"{lv} --json push {s}")
                self.record({"kind": "push", "target": "tmpfs", "set": s, "rep": rep, "wall": wall, "time": tv, "report": json.loads(out)})
                self.ssh("par", "rm -rf /bench/wl /dev/shm/store")

    def writer_service(self, restart=False):
        if restart:
            self.node_sh("par", "svc-stop", "/bench/w", check=False)
        self.node_sh("par", "svc-start", "/bench/w", env=self.secret_env())
        self.node_sh("par", "wait-sync", "/bench/w", "1")
        time.sleep(3)  # the snapshot of what we serve follows the first sync

    def purge_chunks(self):
        env, _, _ = self.s3_env()
        b = self.state["bucket"]
        subprocess.run(["rclone", "purge", f"scw:{b}/chunks"], env=env, check=False)
        left = subprocess.run(["rclone", "lsf", "-R", f"scw:{b}/chunks"], env=env, capture_output=True, text=True).stdout.split()
        top = subprocess.run(["rclone", "lsf", f"scw:{b}"], env=env, capture_output=True, text=True).stdout.split()
        self.record({"kind": "purge-chunks", "chunks_left": len(left), "bucket_top": top})

    # ----- reader runs ------------------------------------------------------------

    def run(self):
        mode, s = self.args.mode, self.args.set
        readers = self.args.readers.split(",")
        for rep in range(self.args.rep_start, self.args.rep_start + self.args.reps):
            self.one_run(mode, s, readers, rep)

    def writer_proc(self):
        """CPU and memory of the writer's service, when it runs (it serves the p2p runs)."""
        out = self.node_sh("par", "proc", "/bench/w", check=False).strip()
        try:
            return json.loads(out)
        except ValueError:
            return None

    def one_run(self, mode, s, readers, rep):
        tag = f"{mode}-{s}-{'+'.join(readers)}-{rep}{'-' + self.args.variant if self.args.variant else ''}"
        log(f"run {tag}")
        homes = {r: f"/bench/h-{tag}" for r in readers}
        datas = {r: f"/bench/r-{tag}" for r in readers}

        def prepare(r):
            h = homes[r]
            # Leftovers of an aborted run: stop its service first.
            self.ssh(r, "for h in /bench/h-*; do [ -f $h/service.json ] && bash /bench/bench-node.sh svc-stop $h >/dev/null; done; true")
            self.ssh(r, f"rm -rf /bench/h-* /bench/r-*; {self.secret_env()} VARSTO_PASSPHRASE=bench-passphrase /bench/varsto --home {h} join "
                        f"--name {r}-{tag} --vault-key {self.state['vault_key']} {self.s3_flags()} > /dev/null")
            if mode == "p2p":
                self.ssh(r, f"VARSTO_PASSPHRASE=bench-passphrase /bench/varsto --home {h} p2p enable --port {PORT} >/dev/null")
            self.node_sh(r, "svc-start", h, env=self.secret_env())
            self.node_sh(r, "wait-sync", h, "1")  # publishes its peer record when p2p is on
            self.node_sh(r, "api", h, "POST", "/api/service/pause", '{"paused":true}')
        with cf.ThreadPoolExecutor(len(readers)) as ex:
            list(ex.map(prepare, readers))
        if mode == "p2p":
            # The writer reads the new devices' records (and so accepts their
            # QUIC certificates) when its service starts; it also zeroes its counters.
            self.writer_service(restart=True)
        for r in readers:
            self.node_sh(r, "api", homes[r], "POST", "/api/folder/attach",
                         json.dumps({"name_or_id": FOLDERS[s], "path": datas[r], "plain": True}))
        before = {"par": self.writer_proc()}
        for r in readers:
            before[r] = json.loads(self.node_sh(r, "proc", homes[r]))
        sampler = subprocess.Popen(sb.ssh_base("root", self.ip("par")) + ["vmstat -n 5"], stdout=subprocess.PIPE, text=True)

        def go(r):
            return r, json.loads(self.node_sh(r, "timed-sync", homes[r], FOLDERS[s]))
        with cf.ThreadPoolExecutor(len(readers)) as ex:
            synced = dict(ex.map(go, readers))
        sampler.terminate()
        vmstat = sampler.stdout.read() if sampler.stdout else ""
        after = {"par": self.writer_proc()}
        traffic, p2p = {}, {}
        for r in readers:
            after[r] = json.loads(self.node_sh(r, "proc", homes[r]))
        if mode == "p2p":
            traffic["par"] = json.loads(self.node_sh("par", "api", "/bench/w", "GET", "/api/p2p/traffic"))
            for r in readers:
                traffic[r] = json.loads(self.node_sh(r, "api", homes[r], "GET", "/api/p2p/traffic"))
                p2p[r] = json.loads(self.node_sh(r, "api", homes[r], "GET", "/api/p2p"))
        verify, stop = {}, {}
        for r in readers:
            self.node_sh(r, "hashes", datas[r], f"/bench/{tag}.sha")
            verify[r] = self.ssh(r, f"cmp -s /bench/{s}.sha /bench/{tag}.sha && echo identical || echo DIFFERENT").strip()
            stop[r] = parse_time_v(self.node_sh(r, "svc-stop", homes[r], check=False))
            # This device is gone after the run: drop its rendezvous record, or
            # every later reader would first spend punch timeouts on a dead peer.
            dev = json.loads(self.ssh(r, f"cat {homes[r]}/vault.json"))["device_id"]
            env, _, _ = self.s3_env()
            subprocess.run(["rclone", "deletefile", f"scw:{self.state['bucket']}/vault/peers/{dev}.enc"], env=env,
                           capture_output=True)
            self.ssh(r, f"cp {homes[r]}.log /bench/log-{tag}-{r}.txt; rm -rf {homes[r]} {datas[r]}")
        summary = {}
        for r in readers:
            rep_ = synced[r]["report"]
            pull = rep_[0]["pull"] if isinstance(rep_, list) and rep_ else {}
            wall = synced[r]["wall"]
            summary[r] = {
                "wall_s": round(wall, 2),
                "files": pull.get("files_updated"),
                "chunks": pull.get("chunks_downloaded"),
                "chunks_from_peers": pull.get("chunks_from_peers"),
                "bytes": pull.get("bytes_downloaded"),
                "mb_s": round((pull.get("bytes_downloaded") or 0) / 1e6 / wall, 2),
                "files_s": round((pull.get("files_updated") or 0) / wall, 1),
                "unavailable": len(pull.get("files_unavailable") or []),
                "cpu_s": round(after[r]["user_s"] + after[r]["sys_s"] - before[r]["user_s"] - before[r]["sys_s"], 1),
                "peak_rss_mib": round(after[r]["hwm_kib"] / 1024, 1),
                "verified": verify[r],
            }
            if mode == "p2p":
                t = traffic[r]
                summary[r]["p2p_in_bytes"] = sum(p.get("rx_total", 0) for p in t.get("peers", []))
                # Which transport carried the requests: the service logs every route it settles on.
                summary[r]["routes"] = self.ssh(r, f"grep -oE ': (tcp|quic|relay) [^ ]+ answered' /bench/log-{tag}-{r}.txt | sort | uniq -c", check=False).strip()
                summary[r]["paths"] = [(p.get("name"), p.get("path"), str(p.get("addr"))) for p in t.get("peers", [])]
        summary["writer_cpu_s"] = (round(after["par"]["user_s"] + after["par"]["sys_s"] - before["par"]["user_s"] - before["par"]["sys_s"], 1)
                                   if before["par"] and after["par"] else None)
        if mode == "p2p":
            summary["writer_out_bytes"] = traffic["par"].get("totals")
        self.record({"kind": "run", "mode": mode, "set": s, "readers": readers, "rep": rep, "variant": self.args.variant, "summary": summary,
                     "sync": synced, "traffic": traffic, "p2p": p2p, "proc_before": before, "proc_after": after,
                     "service_time_v": stop, "writer_vmstat": vmstat})
        if mode == "p2p":
            for r in readers:
                if summary[r]["chunks_from_peers"] != summary[r]["chunks"]:
                    raise SystemExit(f"{r}: not every chunk came from a peer: {summary[r]}")
        for r in readers:
            if summary[r]["verified"] != "identical" or summary[r]["unavailable"]:
                raise SystemExit(f"{r}: folder incomplete or different: {summary[r]}")


def parse_time_v(text):
    out = {}
    for line in text.splitlines():
        line = line.strip()
        for key, name in (("User time (seconds)", "user_s"), ("System time (seconds)", "sys_s"),
                          ("Maximum resident set size (kbytes)", "max_rss_kib"), ("Percent of CPU this job got", "cpu_pct"),
                          ("Elapsed (wall clock) time", "elapsed")):
            if line.startswith(key):
                v = line.split(": ", 1)[1].strip() if ": " in line else line.rsplit(":", 1)[1].strip()
                out[name] = v.rstrip("%")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=["up", "setup", "baseline", "gen", "writer", "push-local", "push-ram", "push-s3", "run", "purge-chunks", "down"])
    ap.add_argument("--work", default=os.environ.get("BENCH_WORK", "dist/bench"))
    ap.add_argument("--binary", default=str(ROOT / "target/x86_64-unknown-linux-musl/release/varsto"))
    ap.add_argument("--type", default="POP2-4C-16G")
    ap.add_argument("--disk-gb", type=int, default=80)
    ap.add_argument("--sets", default="small,big,text")
    ap.add_argument("--files", type=int, help="small: number of files (default 50000)")
    ap.add_argument("--text-mib", type=int, default=512)
    ap.add_argument("--mode", choices=["s3", "p2p"])
    ap.add_argument("--set", choices=list(FOLDERS))
    ap.add_argument("--readers", default="ams")
    ap.add_argument("--reps", type=int, default=2)
    ap.add_argument("--rep-start", type=int, default=1)
    ap.add_argument("--variant", default="", help="run: label for a build other than the published one")
    args = ap.parse_args()
    b = Bench(args)
    step = args.step.replace("-", "_")
    getattr(b, step)()


if __name__ == "__main__":
    main()
