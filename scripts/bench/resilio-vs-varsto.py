#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Varsto peer-to-peer against Resilio Sync on the same machines.

Uses the machines, bucket and Varsto vault of p2p-bench.py (writer in
Paris, readers in Amsterdam and Warsaw; same --work directory), and adds
Resilio Sync. Both tools pull the same data from the same writer, one tool
at a time, with relays, trackers and LAN discovery off, the page cache
dropped and the reader's folder empty before every initial sync. Varsto
runs in p2p mode: the bucket keeps only the metadata (ledger, manifests,
device records), `purge-chunks` deletes every block, and a run fails unless
every block came from a peer.

    resilio-vs-varsto.py up         three machines and the bucket (POP2-2C-8G, 40 GB)
    resilio-vs-varsto.py setup --binary <varsto> --build LABEL
                                    p2p-bench setup, plus Resilio Sync, bench-tools.py,
                                    traffic accounting (iptables) and a netem check
    resilio-vs-varsto.py baseline   ping, iperf3, plain S3 (p2p-bench's)
    resilio-vs-varsto.py gen        data sets on the writer, manifests on every machine,
                                    Resilio's copy of the writer's folders
    resilio-vs-varsto.py writer     Varsto vault, timed pushes into the bucket, service, purge-chunks
    resilio-vs-varsto.py rsl-writer Resilio Sync on the writer with one folder per data set; times its indexing
    resilio-vs-varsto.py run --tool varsto|resilio --scenario NAME --set SET [--readers ams,waw]
                                    [--reps 2 --rep-start 1] [--netem "delay 40ms loss 1% rate 100mbit"]
    resilio-vs-varsto.py plan [--only a,b] [--reps 2] [--stop-after-min 200]
                                    every scenario in priority order, both tools, alternating
                                    V R / R V; starts no run after --stop-after-min from `up`
    resilio-vs-varsto.py report [--detail]  medians per scenario, tool and step as Markdown
                                    (--detail: every run too)
    resilio-vs-varsto.py down       p2p-bench down (machines, volumes, IPs, bucket)

Per run and reader the record (kind "rvv" in <work>/results.jsonl) has the
wall seconds to a verified folder (every sha256 equal to the writer's
manifest), the bytes on the reader's public interface (/proc/net/dev) and,
from an iptables chain, the bytes exchanged with the writer and the other
reader; CPU seconds and peak RSS of the daemon on the reader and the writer.

Timing, both tools alike: from the moment the reader is told about the
folder (Varsto: `POST /api/folder/attach` on its running service, which
starts the pull; Resilio Sync: starting `rslsync`) to the first poll
(every 0.25 s) that sees every file at its size with no temporary file,
confirmed by the sha256 check after it. Varsto's pull report (blocks from
peers, reused local blocks) is read from its service log. Changes after
the initial sync (set `mut`), both tools: from the change on the writer
to the reader's verified folder. Varsto's reader stays up. It is held
(`POST /api/service/hold`) so it does not pull while the writer publishes
and the bucket's new blocks are deleted; peer-to-peer is not stopped (a
pause would stop it). The reader's `POST /api/sync` of that folder runs
while the hold is set (it does not go through the loop) and is inside
the same clock. The hold is cleared after the folder matches.
"""
import argparse
import concurrent.futures as cf
import importlib.util
import json
import os
import pathlib
import shlex
import statistics
import subprocess
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("p2p_bench", HERE / "p2p-bench.py")
pb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pb)
sb = pb.sb
log = pb.log

VPORT = pb.PORT
RPORT = 17894
# The last 2.x release. The current stable (3.1.2 (1076), stable/linux/x64/0/...) did not
# sync a folder from a configuration file at all in 2026-11 (it logs "Stop
# synchronization" and never dials the folder's known hosts, with or without
# tracker and relay), so a run needs the web interface there; 2.8.1 runs from the file.
RSL_URL = "https://download-cdn.resilio.com/2.8.1.1390/linux/x64/0/resilio-sync_x64.tar.gz"
SETS = ["files", "pair", "text", "dup", "mut"]
GEN_ARGS = {"files": "", "pair": "", "text": " --mib 512", "dup": " --mib 768", "mut": ""}
MUTABLE = {"mut"}
PP = "VARSTO_PASSPHRASE=bench-passphrase"
VW = "/bench/varsto --home /bench/w"

# Priority order of the brief; `plan` drops from the bottom when time runs short.
PLAN = [
    ("files", "files", ["ams"], None),
    ("large", "pair", ["ams"], None),
    ("text", "text", ["ams"], None),
    ("dup", "dup", ["ams"], None),
    ("two-readers", "pair", ["ams", "waw"], None),
    ("change+rename", "mut", ["ams"], None),
    ("netem", "files", ["ams"], "delay 40ms loss 1% rate 100mbit"),
]


class RvV(pb.Bench):
    # ----- helpers --------------------------------------------------------------

    def tools(self, node, *args, check=True):
        return self.ssh(node, "python3 /bench/bench-tools.py " + " ".join(shlex.quote(a) for a in args), check=check)

    def jtools(self, node, *args):
        return json.loads(self.tools(node, *args))

    def iface(self, node):
        return self.state["iface"][node]

    def others(self, node):
        return [self.ip(n) for n in pb.ZONES if n != node]

    def net(self, node):
        return self.jtools(node, "net", self.iface(node), *self.others(node))

    def dropcaches(self):
        with cf.ThreadPoolExecutor(3) as ex:
            list(ex.map(lambda n: self.node_sh(n, "dropcaches"), pb.ZONES))

    def man(self, tool, s):
        """The manifest of the writer's folder of this tool (they differ only for the changed set)."""
        return f"/bench/{'r' if tool == 'resilio' and s in MUTABLE else ''}{s}.man"

    def spread(self, path):
        """Copy a file of the writer to the readers (through this machine)."""
        local = self.work / pathlib.Path(path).name
        with open(local, "w") as f:
            subprocess.run(sb.ssh_base("root", self.ip("par")) + [f"cat {path}"], stdout=f, check=True)
        for r in ("ams", "waw"):
            sb.scp(str(local), f"root@{self.ip(r)}:{path}")

    def stop_resilio(self):
        for n in pb.ZONES:
            self.ssh(n, "pkill -x rslsync; for i in $(seq 1 40); do pgrep -x rslsync >/dev/null || exit 0; sleep 0.25; done; pkill -9 -x rslsync; true", check=False)

    def stop_varsto(self):
        self.node_sh("par", "svc-stop", "/bench/w", check=False)
        for r in ("ams", "waw"):
            self.ssh(r, "for h in /bench/h-*; do [ -f $h/service.json ] && bash /bench/bench-node.sh svc-stop $h >/dev/null; done; true", check=False)

    def clocks(self):
        """Clock offset of every machine against this one (midpoint of an SSH round trip)."""
        out = {}
        for n in pb.ZONES:
            a = time.time()
            t = float(self.ssh(n, "date +%s.%N"))
            b = time.time()
            out[n] = round(t - (a + b) / 2, 3)
        return out

    def versions(self):
        return {"varsto": self.state.get("version"), "varsto_build": self.state.get("build"),
                "resilio": self.state.get("rsl_version")}

    def record_rvv(self, entry):
        entry.update({"kind": "rvv", "versions": self.versions()})
        self.record(entry)

    # ----- machines and setup ----------------------------------------------------

    def up(self):
        self.state.setdefault("t_up", time.time())
        self.save()
        super().up()

    def setup(self):
        super().setup()
        self.state["build"] = self.args.build
        self.state["iface"] = {}
        for n in pb.ZONES:
            ip = self.ip(n)
            sb.scp(str(HERE / "bench-tools.py"), f"root@{ip}:/bench/bench-tools.py")
            self.state["iface"][n] = self.node_sh(n, "iface").strip()
            self.node_sh(n, "acct", *self.others(n))
            out = self.node_sh(n, "rsl-install", RSL_URL).strip().splitlines()
            self.state["rsl_sha256"] = out[0]
            self.state["rsl_version"] = " ".join(out[1:]).strip()[:200]
        # netem and ifb are kernel modules: load them once here, so a missing one shows now.
        nm = {}
        for r in ("ams", "waw"):
            nm[r] = self.ssh(r, "modprobe sch_netem && modprobe ifb && modprobe act_mirred && modprobe cls_u32 && echo ok "
                                "|| (apt-get install -y -qq linux-modules-extra-$(uname -r) >/dev/null 2>&1; "
                                "modprobe sch_netem && modprobe ifb && modprobe act_mirred && modprobe cls_u32 && echo ok-extra)", check=False).strip()
        self.save()
        self.record({"kind": "tools", "versions": self.versions(), "resilio_tarball_sha256": self.state["rsl_sha256"],
                     "resilio_url": RSL_URL, "iface": self.state["iface"], "netem": nm})
        log(f"versions {self.versions()}; netem {nm}")

    # ----- data -------------------------------------------------------------------

    def gen(self):
        for s in self.args.sets.split(","):
            t = time.time()
            log(self.ssh("par", f"rm -rf /bench/data/{s} /bench/rdata/{s} && mkdir -p /bench/rdata && "
                                f"python3 /bench/gen-data.py {s} /bench/data/{s}{GEN_ARGS[s]}").strip())
            info = self.jtools("par", "manifest", f"/bench/data/{s}", f"/bench/{s}.man")
            log(f"{s}: {info} in {time.time() - t:.0f} s")
            # Resilio Sync keeps .sync/ in the folder and Varsto .varsto-folder:
            # each tool gets its own tree. Hard links for the sets that never
            # change (no extra space), a real copy for the one that does.
            if s in MUTABLE:
                self.ssh("par", f"cp -a /bench/data/{s} /bench/rdata/{s} && cp /bench/{s}.man /bench/r{s}.man")
                self.spread(f"/bench/r{s}.man")
            else:
                self.ssh("par", f"cp -al /bench/data/{s} /bench/rdata/{s}")
            self.spread(f"/bench/{s}.man")
            self.record({"kind": "dataset", "set": s, **info})
        log(self.ssh("par", "df -h /bench | tail -1; du -sh /bench/data").strip())

    # ----- Varsto writer --------------------------------------------------------------

    def varsto_fair(self, node, home):
        """As close to Resilio Sync's conditions as this build allows: no
        rendezvous service (so no relay through it), no router port mapping,
        no update check; background jobs that would read or upload blocks
        off. STUN stays on: with `--no-stun --public <ip:port>` instead
        (BENCH_VARSTO_NO_STUN=1) a 10 000-file pull from the peer stopped
        after about 65 s with some 1 150 files "not available on any
        readable storage", twice (see docs/testing/resilio-vs-varsto-2026-11.md)."""
        ip = self.ip(node)
        if os.environ.get("BENCH_VARSTO_DEFAULTS"):  # p2p-bench.py's settings, to compare
            for c in (f"p2p enable --port {VPORT}", "verify set --off"):
                self.ssh(node, f"{PP} /bench/varsto --home {home} {c} >/dev/null")
            return
        for c in ("config auto-update off", "scrub set --off", "forward set --off", "mailbox set --off",
                  (f"p2p enable --port {VPORT} --public {ip}:{VPORT} --no-stun" if os.environ.get("BENCH_VARSTO_NO_STUN") else f"p2p enable --port {VPORT}"),
                  "p2p rendezvous off",
                  "p2p port-mapping off", "verify set --off"):
            self.ssh(node, f"{PP} /bench/varsto --home {home} {c} >/dev/null")

    def writer(self):
        self.stop_resilio()
        super().writer()
        self.varsto_fair("par", "/bench/w")
        for s in self.args.sets.split(","):
            self.warm(s)
            wall, out, tv = self.timed("par", f"{VW} --json push {s}", env=self.secret_env())
            self.record({"kind": "push", "tool": "varsto", "target": "s3-fr-par", "set": s, "wall": wall, "time": tv,
                         "report": json.loads(out), "versions": self.versions()})
        self.writer_service(restart=True)
        self.purge_chunks()

    # ----- Resilio writer ---------------------------------------------------------------

    def rsl_config(self, name, storage, folders, port=RPORT):
        return {"device_name": name, "listening_port": port, "storage_path": storage, "pid_file": f"{storage}/rslsync.pid",
                "use_upnp": False, "download_limit": 0, "upload_limit": 0,
                "shared_folders": [dict({"use_relay_server": False, "use_tracker": False, "search_lan": False,
                                         "use_sync_trash": False, "overwrite_changes": False, "selective_sync": False}, **f)
                                   for f in folders]}

    def put_config(self, node, cfg, path):
        """Through a file in the (git-ignored) work directory: the secrets never go on a command line."""
        local = self.work / f"rsl-{node}.json"
        local.write_text(json.dumps(cfg, indent=1))
        os.chmod(local, 0o600)
        sb.scp(str(local), f"root@{self.ip(node)}:{path}")
        local.unlink()

    def rsl_secrets(self):
        sec = self.state.setdefault("rsl", {})
        for s in self.args.sets.split(","):
            if s in sec:
                continue
            rw = self.ssh("par", "/bench/rslsync --generate-secret").strip()
            ro = self.ssh("par", f"/bench/rslsync --get-ro-secret {rw}").strip()
            assert rw and ro and rw != ro and " " not in rw + ro, "rslsync did not print secrets"
            sec[s] = {"rw": rw, "ro": ro}
        self.save()
        return sec

    def rsl_writer_start(self):
        """Start Resilio Sync on the writer with every data set's folder; returns its pid once idle."""
        sec = self.rsl_secrets()
        sets = [s for s in self.args.sets.split(",") if s]
        folders = [{"secret": sec[s]["rw"], "dir": f"/bench/rdata/{s}", "known_hosts": []} for s in sets]
        self.ssh("par", "mkdir -p /bench/rsl-w/storage")
        self.put_config("par", self.rsl_config("writer-paris", "/bench/rsl-w/storage", folders), "/bench/rsl-w/config.json")
        pid = self.ssh("par", "cd /bench/rsl-w && (setsid nohup /bench/rslsync --nodaemon --config /bench/rsl-w/config.json "
                              ">> /bench/rsl-w.log 2>&1 < /dev/null & echo $!)").strip()
        time.sleep(2)
        idle = self.jtools("par", "idle", pid, "--quiet", "5", "--max", "2400")
        return pid, idle

    def rsl_writer(self):
        """First start: Resilio Sync indexes (hashes) every folder, as Varsto's push did."""
        self.stop_varsto()
        self.stop_resilio()
        self.ssh("par", "rm -rf /bench/rsl-w /bench/rdata/*/.sync")
        t = time.time()
        pid, idle = self.rsl_writer_start()
        self.record({"kind": "rsl-index", "tool": "resilio", "sets": SETS, "wall_to_idle_s": round(time.time() - t, 1),
                     "idle": idle, "versions": self.versions(),
                     "log_tail": self.ssh("par", "tail -5 /bench/rsl-w.log", check=False)})
        self.stop_resilio()

    # ----- runs -------------------------------------------------------------------------

    def run(self):
        for rep in range(self.args.rep_start, self.args.rep_start + self.args.reps):
            self.one(self.args.tool, self.args.scenario or self.args.set, self.args.set,
                     self.args.readers.split(","), rep, self.args.netem)

    def one(self, tool, scenario, s, readers, rep, netem=None):
        log(f"=== {tool} {scenario} set={s} readers={readers} rep={rep} netem={netem}")
        try:
            if tool == "varsto":
                self.varsto_one(scenario, s, readers, rep, netem)
            else:
                self.resilio_one(scenario, s, readers, rep, netem)
        finally:
            if netem:
                for r in readers:
                    self.node_sh(r, "netem-off", check=False)

    def netem_on(self, readers, netem):
        if netem:
            for r in readers:
                log(f"{r}: " + self.node_sh(r, "netem-on", *netem.split()).strip())

    def reader_entry(self, wall, n0, n1, cpu, hwm_kib, verified, extra=None):
        peers = {ip: {"rx": n1["peers"][ip]["rx"] - n0["peers"][ip]["rx"], "tx": n1["peers"][ip]["tx"] - n0["peers"][ip]["tx"]}
                 for ip in n0["peers"]}
        e = {"wall_s": None if wall is None else round(wall, 2),
             "iface_rx": n1["iface_rx"] - n0["iface_rx"], "iface_tx": n1["iface_tx"] - n0["iface_tx"],
             "peer_rx": sum(p["rx"] for p in peers.values()), "peer_tx": sum(p["tx"] for p in peers.values()),
             "by_peer": peers, "cpu_s": round(cpu, 2), "peak_rss_mib": round(hwm_kib / 1024, 1), "verified": verified}
        e["wire_bytes"] = e["iface_rx"] + e["iface_tx"]
        e.update(extra or {})
        return e

    # Varsto ----------------------------------------------------------------------------

    def varsto_one(self, scenario, s, readers, rep, netem):
        self.stop_resilio()
        tag = f"v-{scenario.replace('+', '_')}-{'_'.join(readers)}-{rep}"
        homes = {r: f"/bench/h-{tag}" for r in readers}
        datas = {r: f"/bench/r-{tag}" for r in readers}
        env, _, _ = self.s3_env()
        b = self.state["bucket"]
        writer = json.loads(self.ssh("par", "cat /bench/w/vault.json"))["device_id"]
        for name in subprocess.run(["rclone", "lsf", f"scw:{b}/vault/peers"], env=env, capture_output=True, text=True).stdout.split():
            if name != f"{writer}.enc":
                subprocess.run(["rclone", "deletefile", f"scw:{b}/vault/peers/{name}"], env=env, capture_output=True)
        lock = threading.Lock()
        se = self.secret_env()
        stamp = int(time.time())
        names = {r: f"{r}-{tag}-{stamp}" for r in readers}

        def prepare(r):
            h = homes[r]
            self.ssh(r, "for h in /bench/h-*; do [ -f $h/service.json ] && bash /bench/bench-node.sh svc-stop $h >/dev/null; done; true")
            self.ssh(r, f"rm -rf /bench/h-* /bench/r-* /bench/rr-* /bench/rsl-r; {se} {PP} VARSTO_VAULT_KEY={self.state['vault_key']} "
                        f"/bench/varsto --home {h} join --name {names[r]} {self.s3_flags()} > /dev/null")
            self.ssh(r, f"{se} {PP} /bench/varsto --home {h} folder request {s} >/dev/null")
            with lock:
                self.ssh("par", f"{se} {PP} {VW} sync >/dev/null && {se} {PP} {VW} folder approve {s} {names[r]} --yes >/dev/null")
            self.ssh(r, f"{se} {PP} /bench/varsto --home {h} sync >/dev/null")
            self.varsto_fair(r, h)
            self.node_sh(r, "svc-start", h, env=se)
            self.node_sh(r, "wait-sync", h, "1")

        with cf.ThreadPoolExecutor(len(readers)) as ex:
            list(ex.map(prepare, readers))
        # The writer trusts a new device's certificate after two restarts (see p2p-bench.py).
        self.writer_service(restart=True)
        self.writer_service(restart=True)
        # A reader that tried the writer while it restarted may hold it in a
        # back-off: restart the readers too, so every run starts with a
        # reachable writer, as Resilio Sync's does. (The services are never
        # paused: in this build a paused service stops its peer-to-peer part.)
        def restart(r):
            self.node_sh(r, "svc-stop", homes[r], check=False)
            self.node_sh(r, "svc-start", homes[r], env=se)
            self.node_sh(r, "wait-sync", homes[r], "1")
        with cf.ThreadPoolExecutor(len(readers)) as ex:
            list(ex.map(restart, readers))
        self.netem_on(readers, netem)
        try:
            # `folder attach` on the running service starts the pull by itself:
            # the attach is the start of the timed part.
            self.varsto_step("initial", scenario, s, readers, rep, netem, homes, datas, tag, writer_wall=0.0,
                             run={r: f"bash /bench/bench-node.sh api {homes[r]} POST /api/folder/attach "
                                     + shlex.quote(json.dumps({"name_or_id": s, "path": datas[r], "plain": True})) for r in readers})
            if s in MUTABLE:
                for what in ("change", "rename"):
                    self.varsto_mutation(what, scenario, s, readers, rep, netem, homes, datas, tag)
        finally:
            for r in readers:
                self.node_sh(r, "svc-stop", homes[r], check=False)
                dev = json.loads(self.ssh(r, f"cat {homes[r]}/vault.json"))["device_id"]
                subprocess.run(["rclone", "deletefile", f"scw:{b}/vault/peers/{dev}.enc"], env=env, capture_output=True)
                self.ssh(r, f"cp {homes[r]}.log /bench/log-{tag}-{r}.txt; cp {homes[r]}/logs/varsto-service.log /bench/debug-{tag}-{r}.log; "
                            f"rm -rf {homes[r]} {datas[r]}", check=False)

    def pull_report(self, r, home, folder, since):
        """The pull reports of the folder since `since` (epoch) from the
        service's own log (`pull done subject=<id> ... result={json}`, zero
        fields left out), summed: the attach or the service start runs the
        real pull, later syncs of the step are no-ops."""
        lines = self.ssh(r, f"grep 'pull done subject=' {home}/logs/varsto-service.log | grep -F '\"folder\":\"{folder}\"'", check=False)
        total, n = {}, 0
        for line in lines.splitlines():
            try:
                t = time.mktime(time.strptime(line[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
                rep = json.loads(line.split(" result=", 1)[1].strip())
            except (ValueError, IndexError):
                continue
            if t < since - 2:
                continue
            n += 1
            for k, v in rep.items():
                if isinstance(v, (int, float)):
                    total[k] = total.get(k, 0) + v
                elif k == "files_unavailable":
                    total[k] = max(total.get(k, 0), unavailable_count(v))
        total["pulls"] = n
        return total

    def varsto_mutation(self, step, scenario, s, readers, rep, netem, homes, datas, tag):
        """One clock from the change to the verified folder, reader left running.

        The reader is held so it cannot pull the new blocks from the bucket.
        After the writer's push and the purge, it is asked to sync that folder.
        """
        man = self.man("varsto", s)
        old = [json.loads(l)["path"] for l in self.ssh("par", f"cat {man}").splitlines()]
        src = "dir" if any(p.startswith("dir/") for p in old) else "dir-moved"
        hints = ["--changed", f"{src}/big.bin", f"{src}/app.log"] if step == "change" else ["--gone", src]
        tree = f"/bench/data/{s}"
        self.tools("par", "mutate", tree, man, man + ".new", str(rep), step, "--dry")
        self.spread(man + ".new")
        for r in readers:
            self.ssh(r, f"cp {man} {man}.old && mv {man}.new {man}")
            self.node_sh(r, "api", homes[r], "POST", "/api/service/hold", json.dumps({"hold": True}))
        seen = {}
        wb = wn0 = None

        def observe(r):
            args = ["observe", datas[r], man, "--iface", self.iface(r), "--ips", *self.others(r),
                    "--service-json", f"{homes[r]}/service.json", "--timeout", "900", *hints]
            return r, json.loads(self.ssh(r, "python3 /bench/bench-tools.py " + " ".join(shlex.quote(a) for a in args)))

        try:
            with cf.ThreadPoolExecutor(len(readers) + 1) as ex:
                futs = [ex.submit(observe, r) for r in readers]
                time.sleep(3)  # the waiters have recorded the old files
                wb, wn0 = self.writer_proc(), self.net("par")
                out = self.mutate("varsto", s, rep, step)
                t = json.loads(self.node_sh("par", "timed-sync", "/bench/w", s))
                push = t["report"][0].get("push") if isinstance(t["report"], list) and t["report"] else t["report"]
                self.purge_chunks()
                def pull(r):
                    self.node_sh(r, "api", homes[r], "POST", "/api/sync", json.dumps({"folder": s}))
                with cf.ThreadPoolExecutor(len(readers)) as ex2:
                    list(ex2.map(pull, readers))
                for f in futs:
                    r, o = f.result()
                    seen[r] = o
        finally:
            for r in readers:
                self.node_sh(r, "api", homes[r], "POST", "/api/service/hold", json.dumps({"hold": False}), check=False)
        wa, wn1 = self.writer_proc(), self.net("par")
        per = {}
        for r in readers:
            o = seen[r]
            w = o["wait"]
            pull = self.pull_report(r, homes[r], s, out["t0"])
            traffic = json.loads(self.node_sh(r, "api", homes[r], "GET", "/api/p2p/traffic", check=False) or "{}")
            routes = self.ssh(r, f"grep -oE ': (tcp|quic|relay) [^ ]+ answered' {homes[r]}/logs/varsto-service.log | sort | uniq -c", check=False).strip()
            p0, p1 = o["proc_before"], o["proc_after"] or o["proc_before"]
            wall = (w["done"] - out["t0"]) if w.get("done") else None
            per[r] = self.reader_entry(
                wall, o["net_before"], o["net_after"],
                p1["user_s"] + p1["sys_s"] - p0["user_s"] - p0["sys_s"], p1["hwm_kib"], w["verified"],
                {"reader_wall_s": None if wall is None else round(wall, 2),
                 "writer_sync_wall_s": round(t["wall"], 2),
                 "files": pull.get("files_updated", 0), "chunks": pull.get("chunks_downloaded", 0),
                 "chunks_from_peers": pull.get("chunks_from_peers", 0), "bytes_pulled": pull.get("bytes_downloaded", 0),
                 "chunks_reused_local": pull.get("chunks_reused_local", 0), "bytes_reused_local": pull.get("bytes_reused_local", 0),
                 "unavailable": pull.get("files_unavailable", 0),
                 "pull_report": pull, "wait": w,
                 "p2p_in_bytes": sum(p.get("rx_total", 0) for p in traffic.get("peers", [])),
                 "paths": [(p.get("name"), p.get("path"), str(p.get("addr"))) for p in traffic.get("peers", [])],
                 "routes": routes})
        wr = {"cpu_s": round(wa["user_s"] + wa["sys_s"] - wb["user_s"] - wb["sys_s"], 2) if wa and wb else None,
              "peak_rss_mib": round(wa["hwm_kib"] / 1024, 1) if wa else None,
              "sent_to": {ip: wn1["peers"][ip]["tx"] - wn0["peers"][ip]["tx"] for ip in wn0["peers"]},
              "iface_tx": wn1["iface_tx"] - wn0["iface_tx"]}
        self.record_rvv({"tool": "varsto", "scenario": scenario, "set": s, "step": step, "readers": readers, "rep": rep,
                         "netem": netem, "per_reader": per, "writer": wr,
                         "extra": {"writer_push": push, "writer_sync_wall_s": round(t["wall"], 2), "mutation": out}})
        for r in readers:
            e = per[r]
            no_report = not e["pull_report"].get("pulls")
            if e["chunks_from_peers"] != e["chunks"] or e["verified"] != "identical" or e["unavailable"] or e["wall_s"] is None or no_report:
                raise SystemExit(f"varsto {r} {step}: not every block from a peer, folder different, or no pull report: "
                                 + json.dumps({k: e.get(k) for k in ('chunks', 'chunks_from_peers', 'verified', 'unavailable', 'wall_s', 'pull_report')}))

    def varsto_step(self, step, scenario, s, readers, rep, netem, homes, datas, tag, writer_wall, run, env="", hints=(), extra=None):
        if step == "initial":
            self.dropcaches()
        wb, wn0 = self.writer_proc(), self.net("par")

        def go(r):
            args = ["observe", datas[r], self.man("varsto", s), "--iface", self.iface(r), "--ips", *self.others(r),
                    "--service-json", f"{homes[r]}/service.json", "--run", run[r], "--log", f"/bench/observe-{tag}-{r}.log",
                    "--timeout", "1500" if step == "initial" else "900", *hints]
            return r, json.loads(self.ssh(r, f"{env} python3 /bench/bench-tools.py " + " ".join(shlex.quote(a) for a in args)))
        with cf.ThreadPoolExecutor(len(readers)) as ex:
            seen = dict(ex.map(go, readers))
        wa, wn1 = self.writer_proc(), self.net("par")
        per = {}
        for r in readers:
            o = seen[r]
            w = o["wait"]
            pull = self.pull_report(r, homes[r], s, o["t0"])
            traffic = json.loads(self.node_sh(r, "api", homes[r], "GET", "/api/p2p/traffic", check=False) or "{}")
            routes = self.ssh(r, f"grep -oE ': (tcp|quic|relay) [^ ]+ answered' {homes[r]}/logs/varsto-service.log | sort | uniq -c", check=False).strip()
            p0, p1 = o["proc_before"], o["proc_after"] or o["proc_before"]
            reader_wall = (w["done"] - o["t0"]) if w.get("done") else None
            per[r] = self.reader_entry(
                None if reader_wall is None else reader_wall + writer_wall, o["net_before"], o["net_after"],
                p1["user_s"] + p1["sys_s"] - p0["user_s"] - p0["sys_s"], p1["hwm_kib"], w["verified"],
                {"reader_wall_s": None if reader_wall is None else round(reader_wall, 2), "writer_wall_s": round(writer_wall, 2),
                 "files": pull.get("files_updated", 0), "chunks": pull.get("chunks_downloaded", 0),
                 "chunks_from_peers": pull.get("chunks_from_peers", 0), "bytes_pulled": pull.get("bytes_downloaded", 0),
                 "chunks_reused_local": pull.get("chunks_reused_local", 0), "bytes_reused_local": pull.get("bytes_reused_local", 0),
                 "unavailable": pull.get("files_unavailable", 0),
                 "pull_report": pull, "wait": w,
                 "p2p_in_bytes": sum(p.get("rx_total", 0) for p in traffic.get("peers", [])),
                 "paths": [(p.get("name"), p.get("path"), str(p.get("addr"))) for p in traffic.get("peers", [])],
                 "routes": routes})
        w = {"cpu_s": round(wa["user_s"] + wa["sys_s"] - wb["user_s"] - wb["sys_s"], 2) if wa and wb else None,
             "peak_rss_mib": round(wa["hwm_kib"] / 1024, 1) if wa else None,
             "sent_to": {ip: wn1["peers"][ip]["tx"] - wn0["peers"][ip]["tx"] for ip in wn0["peers"]},
             "iface_tx": wn1["iface_tx"] - wn0["iface_tx"]}
        self.record_rvv({"tool": "varsto", "scenario": scenario, "set": s, "step": step, "readers": readers, "rep": rep,
                         "netem": netem, "per_reader": per, "writer": w, "extra": extra or {}})
        for r in readers:
            e = per[r]
            no_report = not e["pull_report"].get("pulls") or (step == "initial" and e["chunks"] == 0)
            if e["chunks_from_peers"] != e["chunks"] or e["verified"] != "identical" or e["unavailable"] or e["wall_s"] is None or no_report:
                raise SystemExit(f"varsto {r} {step}: not every block from a peer, folder different, or no pull report: "
                                 + json.dumps({k: e.get(k) for k in ('chunks', 'chunks_from_peers', 'verified', 'unavailable', 'wall_s', 'pull_report')}))

    def mutate(self, tool, s, rep, what):
        """The same change to this tool's tree on the writer; the new manifest replaces the old everywhere."""
        tree = f"/bench/{'rdata' if tool == 'resilio' else 'data'}/{s}"
        man = self.man(tool, s)
        out = self.jtools("par", "mutate", tree, man, man + ".new", str(rep), what)
        self.ssh("par", f"mv {man}.new {man}")
        self.spread(man)
        return out

    # Resilio Sync -----------------------------------------------------------------------

    def resilio_one(self, scenario, s, readers, rep, netem):
        self.stop_varsto()
        self.stop_resilio()
        sec = self.rsl_secrets()
        tag = f"rr-{scenario.replace('+', '_')}-{'_'.join(readers)}-{rep}"
        datas = {r: f"/bench/{tag}" for r in readers}
        for r in readers:
            self.ssh(r, f"rm -rf /bench/r-* /bench/rr-* /bench/rsl-r && mkdir -p /bench/rsl-r/storage {datas[r]}")
            hosts = [f"{self.ip('par')}:{RPORT}"] + [f"{self.ip(o)}:{RPORT}" for o in readers if o != r]
            self.put_config(r, self.rsl_config(f"{r}-{tag}", "/bench/rsl-r/storage",
                                               [{"secret": sec[s]["ro"], "dir": datas[r], "known_hosts": hosts}]),
                            "/bench/rsl-r/config.json")
        wpid, idle = self.rsl_writer_start()
        log(f"resilio writer idle: {idle.get('idle_after_s')} s")
        self.netem_on(readers, netem)
        try:
            start = "exec /bench/rslsync --nodaemon --config /bench/rsl-r/config.json"
            self.resilio_step("initial", scenario, s, readers, rep, netem, datas, wpid, start=start, extra={"writer_idle": idle})
            if s in MUTABLE:
                for what in ("change", "rename"):
                    # Let the reader settle (it may still be finishing its own bookkeeping).
                    time.sleep(5)
                    self.resilio_step(what, scenario, s, readers, rep, netem, datas, wpid, start=None)
        finally:
            for r in readers:
                self.ssh(r, f"cp /bench/rsl-r.log /bench/log-{tag}-{r}.txt 2>/dev/null; pkill -x rslsync; sleep 1; "
                            f"rm -rf {datas[r]} /bench/rsl-r", check=False)
            self.stop_resilio()

    def resilio_step(self, step, scenario, s, readers, rep, netem, datas, wpid, start, extra=None):
        man = self.man("resilio", s)
        if step == "initial":
            self.dropcaches()
            wait_args = []
        else:
            # The waiters must see the old files before the change.
            old = [json.loads(l)["path"] for l in self.ssh("par", f"cat {man}").splitlines()]
            src = "dir" if any(p.startswith("dir/") for p in old) else "dir-moved"
            if step == "change":
                wait_args = ["--changed", f"{src}/big.bin", f"{src}/app.log"]
            else:
                wait_args = ["--gone", src]
        wb, wn0 = self.jtools("par", "proc", wpid), self.net("par")
        result = {}
        mut_out = {}

        def observe(r):
            args = ["observe", datas[r], man, "--iface", self.iface(r), "--ips", *self.others(r),
                    "--pidfile", "/bench/rsl-r.pid", "--timeout", "1500" if step == "initial" else "600", *wait_args]
            if start:
                args += ["--start", start, "--log", "/bench/rsl-r.log"]
            return r, self.jtools(r, *args)

        if step == "initial":
            with cf.ThreadPoolExecutor(len(readers)) as ex:
                result = dict(ex.map(observe, readers))
        else:
            # The expected manifest has to be on the readers before their waiters
            # start, and the waiters have to start before the change: write it
            # first (mutate computes it before changing anything), then start them.
            mut_out = self.mutate_resilio_then_wait(s, rep, step, readers, observe, result)
        wa, wn1 = self.jtools("par", "proc", wpid), self.net("par")
        per = {}
        for r in readers:
            o = result[r]
            w = o["wait"]
            t0 = o["t0"] if step == "initial" else mut_out["t0"]
            wall = (w["done"] - t0) if w.get("done") else None
            p0 = o["proc_before"] if step != "initial" else {"user_s": 0, "sys_s": 0}
            p1 = o["proc_after"] or o["proc_before"]
            per[r] = self.reader_entry(wall, o["net_before"], o["net_after"], p1["user_s"] + p1["sys_s"] - p0["user_s"] - p0["sys_s"],
                                       p1["hwm_kib"], w["verified"], {"wait": w})
        wr = {"cpu_s": round(wa["user_s"] + wa["sys_s"] - wb["user_s"] - wb["sys_s"], 2), "peak_rss_mib": round(wa["hwm_kib"] / 1024, 1),
              "sent_to": {ip: wn1["peers"][ip]["tx"] - wn0["peers"][ip]["tx"] for ip in wn0["peers"]},
              "iface_tx": wn1["iface_tx"] - wn0["iface_tx"]}
        self.record_rvv({"tool": "resilio", "scenario": scenario, "set": s, "step": step, "readers": readers, "rep": rep,
                         "netem": netem, "per_reader": per, "writer": wr, "extra": dict(extra or {}, mutation=mut_out, clocks=self.clocks())})
        for r in readers:
            if per[r]["verified"] != "identical" or per[r]["wall_s"] is None:
                raise SystemExit(f"resilio {r} {step}: folder incomplete or different: {per[r]['wait']}")

    def mutate_resilio_then_wait(self, s, rep, step, readers, observe, result):
        """Expected manifest first (written as .new, nothing changed yet), spread
        to the readers, waiters started, then the change itself."""
        man = self.man("resilio", s)
        tree = f"/bench/rdata/{s}"
        self.tools("par", "mutate", tree, man, man + ".new", str(rep), step, "--dry")
        self.spread(man + ".new")
        for r in ("ams", "waw"):
            self.ssh(r, f"cp {man} {man}.old && mv {man}.new {man}")
        with cf.ThreadPoolExecutor(len(readers) + 1) as ex:
            futs = [ex.submit(observe, r) for r in readers]
            time.sleep(3)  # the waiters have read the old state
            out = self.jtools("par", "mutate", tree, man, man + ".new", str(rep), step)
            for f in futs:
                r, o = f.result()
                result[r] = o
        self.ssh("par", f"mv {man}.new {man}")
        return out

    # ----- plan and report -------------------------------------------------------------------

    def plan(self):
        only = set(self.args.only.split(",")) if self.args.only else None
        t_up = self.state.get("t_up", time.time())
        failures = []
        for scenario, s, readers, netem in PLAN:
            if only and scenario not in only:
                continue
            for rep in range(self.args.rep_start, self.args.rep_start + self.args.reps):
                order = ("varsto", "resilio") if rep % 2 else ("resilio", "varsto")
                for tool in order:
                    used = (time.time() - t_up) / 60
                    if used > self.args.stop_after_min:
                        log(f"time budget: {used:.0f} min since up, skipping {tool} {scenario} rep {rep}")
                        self.record({"kind": "skipped", "tool": tool, "scenario": scenario, "rep": rep, "minutes_used": round(used)})
                        continue
                    try:
                        self.one(tool, scenario, s, readers, rep, netem)
                    except (SystemExit, Exception) as e:  # one failed run does not stop the plan
                        log(f"FAILED {tool} {scenario} rep {rep}: {str(e)[:500]}")
                        failures.append((tool, scenario, rep, str(e)[:300]))
                        self.record({"kind": "failed", "tool": tool, "scenario": scenario, "rep": rep, "error": str(e)[:2000]})
        log(f"plan done; failures: {failures}")

    def report(self):
        if self.args.before:
            print(report_compare(pathlib.Path(self.args.before), self.work / "results.jsonl"))
            return
        print(report_markdown(self.work / "results.jsonl"))
        if self.args.detail:
            print()
            print(report_runs(self.work / "results.jsonl"))


def unavailable_count(v):
    """`files_unavailable` of a pull report: a list, or in the service log a
    summary `{"len": n, "first": [...]}` when the list is long."""
    if isinstance(v, dict):
        return int(v.get("len", len(v.get("first") or [])))
    return len(v or [])


def report_markdown(path):
    """Medians per scenario, step, reader and tool of the verified runs (runs
    whose folder differed are counted in the last column, not in the medians)."""
    rows, bad = {}, {}
    order = [p[0] for p in PLAN]
    for line in open(path):
        e = json.loads(line)
        if e.get("kind") != "rvv":
            continue
        t0_mut = (e.get("extra") or {}).get("mutation", {}).get("t0") if e["tool"] == "resilio" else None
        for r, pr in e["per_reader"].items():
            key = (e["scenario"], e["step"], r if len(e["readers"]) > 1 else "", e["tool"])
            if pr.get("verified") != "identical" or pr.get("wall_s") is None:
                bad[key] = bad.get(key, 0) + 1
                continue
            w = pr.get("wait") or {}
            b99 = None
            if w.get("bytes99"):
                b99 = w["bytes99"] - (t0_mut or w["started"])
            rows.setdefault(key, []).append((pr, e["writer"], b99))
    med = lambda xs: statistics.median(xs) if xs else None

    def f(xs, d=1):
        m = med([x for x in xs if x is not None])
        return "" if m is None else f"{m:.{d}f}"
    out = ["| Scenario | Step | Reader | Tool | Runs | Time s | Resilio: 99 % of bytes s | Wire MB (reader) | With peers MB | "
           "Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed runs |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    keys = sorted(set(rows) | set(bad), key=lambda k: (order.index(k[0]) if k[0] in order else 99, k[0],
                                                        ["initial", "change", "rename"].index(k[1]), k[2], k[3]))
    for key in keys:
        v = rows.get(key, [])
        out.append("| " + " | ".join([key[0], key[1], key[2], key[3], str(len(v)),
                                       f([x[0]["wall_s"] for x in v]),
                                       f([x[2] for x in v]),
                                       f([x[0]["wire_bytes"] / 1e6 for x in v]),
                                       f([(x[0]["peer_rx"] + x[0]["peer_tx"]) / 1e6 for x in v]),
                                       f([x[0].get("bytes_reused_local", 0) / 1e6 for x in v]) if key[3] == "varsto" else "",
                                       f([sum(x[1]["sent_to"].values()) / 1e6 for x in v if x[1].get("sent_to")]),
                                       f([x[0]["cpu_s"] for x in v]),
                                       f([x[0]["peak_rss_mib"] for x in v], 0),
                                       f([x[1].get("cpu_s") for x in v]),
                                       f([x[1].get("peak_rss_mib") for x in v], 0),
                                       str(bad.get(key, 0))]) + " |")
    return "\n".join(out)


def collect(path):
    """(scenario, step, reader, tool) -> list of (per_reader entry, writer entry) of verified runs, and failures."""
    rows, bad = {}, {}
    for line in open(path):
        e = json.loads(line)
        if e.get("kind") != "rvv":
            continue
        for r, pr in e["per_reader"].items():
            key = (e["scenario"], e["step"], r if len(e["readers"]) > 1 else "", e["tool"])
            if pr.get("verified") != "identical" or pr.get("wall_s") is None:
                bad[key] = bad.get(key, 0) + 1
            else:
                rows.setdefault(key, []).append((pr, e["writer"]))
    return rows, bad


def report_compare(before, after):
    """One table per scenario and step: both builds of Varsto and both days of
    Resilio Sync side by side (medians; with two runs, the mean)."""
    runs = {"before": collect(before), "after": collect(after)}
    med = lambda xs: statistics.median(xs) if xs else None

    def f(xs, d=1):
        m = med([x for x in xs if x is not None])
        return "" if m is None else f"{m:.{d}f}"
    out = []
    order = [p[0] for p in PLAN]
    keys = sorted({k[:3] for day in runs.values() for k in list(day[0]) + list(day[1])},
                  key=lambda k: (order.index(k[0]) if k[0] in order else 99, k[0], ["initial", "change", "rename"].index(k[1]), k[2]))
    for sc, step, reader in keys:
        title = f"{sc}, {step}" + (f", reader {reader}" if reader else "")
        out.append(f"**{title}**\n")
        out.append("| Tool, day | Runs | Time s | Wire MB | With peers MB | Reused local MB | Writer sent MB | Reader CPU s | Reader RSS MiB | Writer CPU s | Writer RSS MiB | Failed |")
        out.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
        for tool in ("varsto", "resilio"):
            for day, label in (("before", "11-07"), ("after", "11-08")):
                rows, bad = runs[day]
                v = rows.get((sc, step, reader, tool), [])
                if not v and not bad.get((sc, step, reader, tool)):
                    continue
                name = {"varsto": {"before": "Varsto 46adda3 (11-07)", "after": "Varsto c50f260 (11-08)"},
                        "resilio": {"before": "Resilio 2.8.1 (11-07)", "after": "Resilio 2.8.1 (11-08)"}}[tool][day]
                out.append("| " + " | ".join([
                    name, str(len(v)), f([x[0]["wall_s"] for x in v]), f([x[0]["wire_bytes"] / 1e6 for x in v]),
                    f([(x[0]["peer_rx"] + x[0]["peer_tx"]) / 1e6 for x in v]),
                    f([x[0].get("bytes_reused_local", 0) / 1e6 for x in v]) if tool == "varsto" and day == "after" else "",
                    f([sum(x[1]["sent_to"].values()) / 1e6 for x in v if x[1].get("sent_to")]),
                    f([x[0]["cpu_s"] for x in v]), f([x[0]["peak_rss_mib"] for x in v], 0),
                    f([x[1].get("cpu_s") for x in v]), f([x[1].get("peak_rss_mib") for x in v], 0),
                    str(bad.get((sc, step, reader, tool), 0))]) + " |")
        out.append("")
    return "\n".join(out)


def report_runs(path):
    """Every run, one line per reader: what the medians are made of."""
    out = ["| Scenario | Step | Tool | Rep | Reader | Time s | Wire MB | Reader CPU s | Verified | Note |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for line in open(path):
        e = json.loads(line)
        if e.get("kind") != "rvv":
            continue
        for r, pr in e["per_reader"].items():
            note = ""
            if pr.get("unavailable"):
                note = f"{pr['unavailable']} files unavailable"
            if e["tool"] == "varsto" and e["step"] != "initial":
                note = f"push {pr.get('writer_wall_s')} s + pull {pr.get('reader_wall_s')} s"
            out.append(f"| {e['scenario']} | {e['step']} | {e['tool']} | {e['rep']} | {r} | {pr.get('wall_s')} | "
                       f"{pr['wire_bytes'] / 1e6:.1f} | {pr['cpu_s']} | {pr['verified']} | {note} |")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("step", choices=["up", "setup", "baseline", "gen", "writer", "rsl-writer", "run", "plan", "report", "purge-chunks", "down"])
    ap.add_argument("--work", default=os.environ.get("BENCH_WORK", "dist/bench-resilio"))
    ap.add_argument("--binary", default=str(pb.ROOT / "target/x86_64-unknown-linux-musl/release/varsto"))
    ap.add_argument("--build", default="", help="setup: which build the binary is (recorded with every result)")
    ap.add_argument("--type", default="POP2-2C-8G")
    ap.add_argument("--disk-gb", type=int, default=40)
    ap.add_argument("--sets", default=",".join(SETS))
    ap.add_argument("--tool", choices=["varsto", "resilio"])
    ap.add_argument("--scenario")
    ap.add_argument("--set", choices=SETS)
    ap.add_argument("--readers", default="ams")
    ap.add_argument("--reps", type=int, default=2)
    ap.add_argument("--rep-start", type=int, default=1)
    ap.add_argument("--netem", default=None)
    ap.add_argument("--only", default="")
    ap.add_argument("--stop-after-min", type=float, default=200)
    ap.add_argument("--variant", default="")
    ap.add_argument("--detail", action="store_true", help="report: also every run")
    ap.add_argument("--before", default="", help="report: an earlier results.jsonl to put side by side, per scenario")
    args = ap.parse_args()
    b = RvV(args)
    getattr(b, args.step.replace("-", "_"))()


if __name__ == "__main__":
    main()
