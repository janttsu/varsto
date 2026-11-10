#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Helper that runs on the benchmark machines for resilio-vs-varsto.py
(standard library only). Every file list skips what the tools keep in the
synced directory for themselves: `.sync/` and `*.!sync` (Resilio Sync),
`.varsto*` (Varsto).

    bench-tools.py manifest <dir> <out>          path, size, sha256 of every file (JSON lines)
    bench-tools.py verify <dir> <manifest>       "identical" or what differs
    bench-tools.py wait <dir> <manifest> [--timeout s] [--changed path ...] [--gone path ...]
        poll until the directory looks complete (sizes; for --changed paths a
        new inode or mtime; --gone paths absent), then check every sha256;
        prints {"done": epoch, ...}. The time is that of the poll that saw it
        complete, not of the hash check after it.
    bench-tools.py mutate <dir> <manifest> <out-manifest> <rep> (change|rename) [--dry]
        change: 1 MiB of new random bytes in the middle of dir/big.bin and
        10 MiB of log lines appended to dir/app.log; rename: dir <-> dir-moved.
        The expected manifest is written first (from the old one, without
        hashing the changed files twice), then the change is made; prints
        {"t0": epoch of the change}.
    bench-tools.py net <iface> <ip> ...          bytes of the interface and, per address, of
                                                 the iptables accounting chain BENCHACCT
    bench-tools.py proc <pid>                    CPU seconds, peak and current RSS
    bench-tools.py idle <pid> [--quiet 5] [--max 1800]
        wait until the process used no CPU and read no disk for --quiet seconds
    bench-tools.py observe <dir> <manifest> --iface IF --ips IP ... (--pidfile F | --pid N | --service-json J)
                   [--start CMD | --run CMD] [wait options]
        counters, then the daemon started in the background (--start, its
        pid written to F) or a command run to completion (--run: Varsto's
        folder attach or service start), then `wait`, then the counters
        again: one JSON object with t0 (just before the start or run), the
        wait result, CPU/RSS of the pid before and after (--service-json:
        the pid in Varsto's service.json, read after --run), and the bytes
"""
import argparse
import hashlib
import json
import os
import pathlib
import random
import subprocess
import time

SKIP_DIRS = {".sync"}


def skipped(name: str) -> bool:
    return name.startswith(".varsto") or name.endswith(".!sync")


def walk(root: pathlib.Path):
    """(relative path, stat) of every regular file."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath == str(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for f in filenames:
            p = os.path.join(dirpath, f)
            if skipped(f):
                continue
            try:
                st = os.lstat(p)
            except FileNotFoundError:
                continue
            out.append((os.path.relpath(p, root), st))
    return sorted(out)


def temp_files(root: pathlib.Path) -> int:
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath == str(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        n += sum(1 for f in filenames if f.endswith(".!sync"))
    return n


def sha256(path, extra_tail: bytes = b"", patch=None) -> str:
    h = hashlib.sha256()
    off = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b:
                break
            if patch:
                po, pb = patch
                lo, hi = max(off, po), min(off + len(b), po + len(pb))
                if lo < hi:
                    b = b[:lo - off] + pb[lo - po:hi - po] + b[hi - off:]
            h.update(b)
            off += len(b)
    h.update(extra_tail)
    return h.hexdigest()


def load(manifest):
    return {e["path"]: e for e in map(json.loads, open(manifest))}


def write(entries, out):
    with open(out, "w") as f:
        for p in sorted(entries):
            f.write(json.dumps(entries[p]) + "\n")


def manifest(a):
    root = pathlib.Path(a.dir)
    entries = {p: {"path": p, "size": st.st_size, "sha256": sha256(root / p)} for p, st in walk(root)}
    write(entries, a.out)
    print(json.dumps({"files": len(entries), "bytes": sum(e["size"] for e in entries.values())}))


def compare(root: pathlib.Path, want: dict):
    have = dict(walk(root))
    missing = [p for p in want if p not in have]
    extra = [p for p in have if p not in want]
    bad = [p for p in want if p in have and (have[p].st_size != want[p]["size"] or sha256(root / p) != want[p]["sha256"])]
    if not (missing or extra or bad):
        return "identical", {}
    return "DIFFERENT", {"missing": len(missing), "extra": len(extra), "bad": len(bad),
                         "examples": (missing + extra + bad)[:5]}


def verify(a):
    v, detail = compare(pathlib.Path(a.dir), load(a.manifest))
    print(json.dumps({"verified": v, **detail}))


def wait(a):
    root = pathlib.Path(a.dir)
    want = load(a.manifest)
    t_start = time.time()
    base = {}
    for p in a.changed or []:
        try:
            st = os.stat(root / p)
            base[p] = (st.st_ino, st.st_mtime_ns)
        except FileNotFoundError:
            base[p] = None
    polls = checks = 0
    total = sum(e["size"] for e in want.values()) or 1
    t99 = None  # first poll with 99 % of the bytes in files of the right size
    while time.time() - t_start < a.timeout:
        polls += 1
        now = time.time()
        if root.is_dir():
            have = dict(walk(root))
            if t99 is None and sum(want[p]["size"] for p in want if p in have and have[p].st_size == want[p]["size"]) >= 0.99 * total:
                t99 = now
            ok = (len(have) == len(want) and all(p in have and have[p].st_size == want[p]["size"] for p in want)
                  and not any((root / g).exists() for g in a.gone or []))
            if ok and base:
                for p, b in base.items():
                    st = have[p]
                    if b and (st.st_ino, st.st_mtime_ns) == b:
                        ok = False
                        break
            # The writer may already have finished, so the new bytes can be
            # in place before this loop's first look. A matching hash counts.
            if not ok and base and polls % 4 == 1 and temp_files(root) == 0:
                checks += 1
                v, detail = compare(root, want)
                if v == "identical":
                    print(json.dumps({"done": now, "started": t_start, "bytes99": t99, "polls": polls, "hash_checks": checks,
                                      "verified": v, "checked_at": time.time()}))
                    return
            if ok and temp_files(root) == 0:
                checks += 1
                v, detail = compare(root, want)
                if v == "identical":
                    print(json.dumps({"done": now, "started": t_start, "bytes99": t99, "polls": polls, "hash_checks": checks,
                                      "verified": v, "checked_at": time.time()}))
                    return
                base = {}  # content differs: from now on only the hashes decide
                time.sleep(2)
        time.sleep(a.interval)
    v, detail = compare(root, want) if root.is_dir() else ("DIFFERENT", {"missing": len(want)})
    print(json.dumps({"done": None, "started": t_start, "bytes99": t99, "polls": polls, "hash_checks": checks, "verified": v, **detail}))


def mutate(a):
    root = pathlib.Path(a.dir)
    want = load(a.manifest)
    if a.what == "change":
        big = "dir/big.bin" if (root / "dir").exists() else "dir-moved/big.bin"
        log = big.replace("big.bin", "app.log")
        size = want[big]["size"]
        rng = random.Random(1000 + a.rep)
        patch = rng.randbytes(1 << 20)
        off = (size // 2) & ~4095
        import importlib.util
        spec = importlib.util.spec_from_file_location("gen_data", pathlib.Path(__file__).resolve().parent / "gen-data.py")
        gd = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gd)
        tail = gd.log_lines(random.Random(2000 + a.rep), 10 * 1024 * 1024, 30 + a.rep).encode()
        want[big] = {"path": big, "size": size, "sha256": sha256(root / big, patch=(off, patch))}
        want[log] = {"path": log, "size": want[log]["size"] + len(tail), "sha256": sha256(root / log, extra_tail=tail)}
        write(want, a.out)
        if a.dry:
            return
        t0 = time.time()
        with open(root / big, "r+b") as f:
            f.seek(off)
            f.write(patch)
        with open(root / log, "ab") as f:
            f.write(tail)
        print(json.dumps({"t0": t0, "changed": [big, log], "bytes_changed": len(patch) + len(tail)}))
    else:
        src, dst = ("dir", "dir-moved") if (root / "dir").exists() else ("dir-moved", "dir")
        moved = {}
        for p, e in want.items():
            q = dst + p[len(src):] if p.startswith(src + "/") else p
            moved[q] = dict(e, path=q)
        write(moved, a.out)
        if a.dry:
            return
        t0 = time.time()
        os.rename(root / src, root / dst)
        print(json.dumps({"t0": t0, "from": src, "to": dst,
                          "bytes_moved": sum(e["size"] for p, e in want.items() if p.startswith(src + "/"))}))


def net(a):
    print(json.dumps(net_counters(a.iface, a.ips)))


def net_counters(iface, ips):
    out = {}
    for line in open("/proc/net/dev"):
        if ":" in line:
            name, rest = line.split(":", 1)
            if name.strip() == iface:
                f = rest.split()
                out["iface_rx"], out["iface_tx"] = int(f[0]), int(f[8])
    rules = subprocess.run(["iptables", "-L", "BENCHACCT", "-vnx"], capture_output=True, text=True).stdout
    per = {ip: {"rx": 0, "tx": 0} for ip in ips}
    for line in rules.splitlines():
        f = line.split()
        if len(f) >= 8 and f[0].isdigit():
            src, dst = f[6], f[7]
            if src in per:
                per[src]["rx"] += int(f[1])
            if dst in per:
                per[dst]["tx"] += int(f[1])
    out["peers"] = per
    out["t"] = time.time()
    return out


def observe(a):
    import contextlib
    import io
    n0 = net_counters(a.iface, a.ips)
    pid = a.pid or (open(a.pidfile).read().strip() if a.pidfile and not a.start else None)
    if a.service_json and os.path.exists(a.service_json) and not a.run:
        pid = str(json.load(open(a.service_json))["pid"])
    p_before = proc_stats(pid) if pid else None
    t0 = time.time()
    if a.start:
        p = subprocess.Popen(a.start, shell=True, stdin=subprocess.DEVNULL, stdout=open(a.log, "ab"),
                             stderr=subprocess.STDOUT, start_new_session=True)
        open(a.pidfile, "w").write(str(p.pid))
        pid = str(p.pid)
    if a.run:
        subprocess.run(a.run, shell=True, check=True, stdout=open(a.log, "ab"), stderr=subprocess.STDOUT)
        if a.service_json:
            pid = str(json.load(open(a.service_json))["pid"])
    p0 = p_before or proc_stats(pid)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        wait(a)
    w = json.loads(buf.getvalue())
    try:
        p1 = proc_stats(pid)
    except (FileNotFoundError, ProcessLookupError):
        p1 = None
    n1 = net_counters(a.iface, a.ips)
    print(json.dumps({"t0": t0, "wait": w, "proc_before": p0, "proc_after": p1, "net_before": n0, "net_after": n1}))


def proc_stats(pid):
    st = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    hz = os.sysconf("SC_CLK_TCK")
    status = dict(l.split(":", 1) for l in open(f"/proc/{pid}/status") if ":" in l)
    io = dict(l.split(":", 1) for l in open(f"/proc/{pid}/io") if ":" in l)
    return {"user_s": int(st[11]) / hz, "sys_s": int(st[12]) / hz,
            "hwm_kib": int(status["VmHWM"].split()[0]), "rss_kib": int(status["VmRSS"].split()[0]),
            "read_bytes": int(io["read_bytes"]), "write_bytes": int(io["write_bytes"])}


def proc(a):
    print(json.dumps(proc_stats(a.pid)))


def idle(a):
    t0 = time.time()
    last = proc_stats(a.pid)
    quiet_since = time.time()
    while time.time() - t0 < a.max:
        time.sleep(1)
        cur = proc_stats(a.pid)
        busy = (cur["user_s"] + cur["sys_s"] - last["user_s"] - last["sys_s"] > 0.03
                or cur["read_bytes"] - last["read_bytes"] > 256 * 1024)
        last = cur
        if busy:
            quiet_since = time.time()
        elif time.time() - quiet_since >= a.quiet:
            print(json.dumps({"idle_after_s": round(quiet_since - t0, 1), **cur}))
            return
    print(json.dumps({"idle_after_s": None, **last}))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("manifest"); p.add_argument("dir"); p.add_argument("out"); p.set_defaults(fn=manifest)
    p = sub.add_parser("verify"); p.add_argument("dir"); p.add_argument("manifest"); p.set_defaults(fn=verify)
    p = sub.add_parser("wait"); p.add_argument("dir"); p.add_argument("manifest")
    p.add_argument("--timeout", type=float, default=1800); p.add_argument("--interval", type=float, default=0.25)
    p.add_argument("--changed", nargs="*"); p.add_argument("--gone", nargs="*"); p.set_defaults(fn=wait)
    p = sub.add_parser("mutate"); p.add_argument("dir"); p.add_argument("manifest"); p.add_argument("out")
    p.add_argument("rep", type=int); p.add_argument("what", choices=["change", "rename"])
    p.add_argument("--dry", action="store_true", help="only write the expected manifest"); p.set_defaults(fn=mutate)
    p = sub.add_parser("net"); p.add_argument("iface"); p.add_argument("ips", nargs="*"); p.set_defaults(fn=net)
    p = sub.add_parser("observe"); p.add_argument("dir"); p.add_argument("manifest")
    p.add_argument("--timeout", type=float, default=1800); p.add_argument("--interval", type=float, default=0.25)
    p.add_argument("--changed", nargs="*"); p.add_argument("--gone", nargs="*")
    p.add_argument("--iface", required=True); p.add_argument("--ips", nargs="*", default=[])
    p.add_argument("--pidfile"); p.add_argument("--pid"); p.add_argument("--service-json")
    p.add_argument("--start"); p.add_argument("--run"); p.add_argument("--log", default="/dev/null")
    p.set_defaults(fn=observe)
    p = sub.add_parser("proc"); p.add_argument("pid"); p.set_defaults(fn=proc)
    p = sub.add_parser("idle"); p.add_argument("pid"); p.add_argument("--quiet", type=float, default=5)
    p.add_argument("--max", type=float, default=1800); p.set_defaults(fn=idle)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
