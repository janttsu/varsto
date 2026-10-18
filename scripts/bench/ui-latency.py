#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""How quickly the local service answers the requests the interface makes,
idle and while a sync and a verification hold the engine, on a synthetic
vault with many files. Optionally drives the page in Chromium and counts
long tasks, requests and the JS heap.

    ui-latency.py <varsto binary> <work dir> [--files 50000] [--browser 60]
                  [--busy-seconds 40] [--json out.json]

Everything lives under <work dir> (a throw-away --home, the folders and a
local storage); nothing outside it is touched. Run it on a disk with a few
GB free. Re-running with the same work dir reuses the vault (the first run
creates it; the initial sync of 50 000 files takes a few minutes).

The browser part needs `pip install playwright` and `playwright install
chromium` (CHROMIUM=/path/to/chromium uses another build).
"""
import argparse
import http.client
import json
import os
import pathlib
import random
import statistics
import subprocess
import sys
import threading
import time

# What the interface asks for (app.js, folders.js, viz.js), GET only.
ENDPOINTS = [
    "/api/service", "/api/status", "/api/folders", "/api/devices", "/api/p2p",
    "/api/policy", "/api/advice?idle_days=90", "/api/verify", "/api/scrub",
    "/api/repair", "/api/ledger", "/api/trash", "/api/history", "/api/storage/known",
    "/api/storage/costs", "/api/data/locations", "/api/activity", "/api/activity?mine=1",
    "/api/progress", "/api/viz", "/api/files?folder=Big",
]
PASS = "bench-passphrase-123"


def run(bin_, home, *args, check=True):
    env = dict(os.environ, VARSTO_PASSPHRASE=PASS)
    return subprocess.run([bin_, "--home", str(home), *args], env=env, check=check,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def make_files(root: pathlib.Path, n: int, seed: int):
    rng = random.Random(seed)
    for i in range(n):
        d = root / f"d{i % 40:02d}" / f"e{(i // 40) % 25:02d}"
        if i < 1000:
            d.mkdir(parents=True, exist_ok=True)
        (d / f"f{i:06d}.txt").write_bytes(os.urandom(rng.randint(200, 3000)))


def setup(bin_, work: pathlib.Path, files: int):
    home = work / "home"
    if (home / "service.ready").exists():
        return home
    for p in ("home", "Big", "Docs", "Photos", "Notes", "box"):
        (work / p).mkdir(parents=True, exist_ok=True)
    print(f"making {files} files ...", flush=True)
    make_files(work / "Big", files, 1)
    for name, n in (("Docs", 300), ("Photos", 200), ("Notes", 100)):
        make_files(work / name, n, hash(name) & 0xffff)
    run(bin_, home, "init", "--name", "bench")
    run(bin_, home, "storage", "add-local", "box", str(work / "box"))
    for name in ("Big", "Docs", "Photos", "Notes"):
        run(bin_, home, "folder", "add", name, str(work / name))
    t = time.time()
    print("initial sync ...", flush=True)
    run(bin_, home, "sync")
    print(f"initial sync took {time.time() - t:.0f} s", flush=True)
    (home / "service.ready").write_text("1")
    return home


class Service:
    def __init__(self, bin_, home):
        env = dict(os.environ, VARSTO_PASSPHRASE=PASS)
        try:
            (home / "service.json").unlink()
        except FileNotFoundError:
            pass
        self.log = open(home.parent / "service.log", "a")
        self.p = subprocess.Popen([bin_, "--home", str(home), "service", "run", "--port", "0",
                                   "--interval", "3600"], env=env, stdout=self.log, stderr=self.log)
        for _ in range(600):
            if (home / "service.json").exists():
                try:
                    j = json.loads((home / "service.json").read_text())
                    self.port, self.token = j["port"], j["token"]
                    break
                except (ValueError, KeyError):
                    pass
            time.sleep(0.1)
        else:
            raise SystemExit("the service did not start")
        # Unlocked by the passphrase in the environment; wait until it answers.
        for _ in range(300):
            try:
                if self.get("/api/status", timeout=30)[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(0.2)

    def request(self, method, path, body=None, timeout=120):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)
        h = {"X-Varsto-Token": self.token, "Host": f"127.0.0.1:{self.port}",
             "Content-Type": "application/json"}
        t = time.perf_counter()
        c.request(method, path, body=json.dumps(body or {}) if method == "POST" else None, headers=h)
        r = c.getresponse()
        data = r.read()
        ms = (time.perf_counter() - t) * 1000
        stale = r.getheader("X-Varsto-Stale")
        c.close()
        return r.status, ms, len(data), stale

    def get(self, path, timeout=120):
        return self.request("GET", path, timeout=timeout)

    def stop(self):
        self.p.terminate()
        try:
            self.p.wait(20)
        except subprocess.TimeoutExpired:
            self.p.kill()


def summary(samples):
    ms = sorted(s for s in samples)
    if not ms:
        return {}
    return {"n": len(ms), "median_ms": round(statistics.median(ms), 1),
            "p95_ms": round(ms[min(len(ms) - 1, int(len(ms) * 0.95))], 1),
            "max_ms": round(ms[-1], 1)}


def measure(svc, rounds, label):
    out = {}
    for ep in ENDPOINTS:
        times, sizes, stale = [], [], 0
        for _ in range(rounds):
            try:
                st, ms, size, s = svc.get(ep, timeout=300)
            except OSError:
                st, ms, size, s = 0, 300000, 0, None
            times.append(ms)
            sizes.append(size)
            stale += 1 if s else 0
        out[ep] = dict(summary(times), bytes=max(sizes), stale=stale)
        print(f"  {label:6} {ep:28} median {out[ep]['median_ms']:8.1f} ms  max {out[ep]['max_ms']:8.1f} ms"
              f"  {max(sizes):>9} B  stale {stale}", flush=True)
    return out


def busy_load(svc, work: pathlib.Path, stop: threading.Event):
    """Keep the engine busy: change files, sync, verify, until stopped."""
    big = work / "Big"
    files = sorted(big.rglob("*.txt"))
    k = 0
    while not stop.is_set():
        for p in files[k:k + 3000]:
            p.write_bytes(os.urandom(random.randint(200, 3000)))
        k = (k + 3000) % max(1, len(files))
        try:
            svc.request("POST", "/api/sync", timeout=900)
            if stop.is_set():
                break
            svc.request("POST", "/api/verify/run", timeout=900)
        except OSError:
            pass


def measure_busy(svc, work, seconds):
    stop = threading.Event()
    t = threading.Thread(target=busy_load, args=(svc, work, stop), daemon=True)
    t.start()
    time.sleep(2)  # the first sync holds the engine now
    out = {ep: [] for ep in ENDPOINTS}
    stale = {ep: 0 for ep in ENDPOINTS}
    end = time.time() + seconds
    lock = threading.Lock()

    def poller(ep):
        while time.time() < end:
            try:
                _, ms, _, s = svc.get(ep, timeout=300)
            except OSError:
                ms, s = 300000, None
            with lock:
                out[ep].append(ms)
                stale[ep] += 1 if s else 0
            time.sleep(0.5)
    # One client per endpoint, as the page's polls are independent.
    ths = [threading.Thread(target=poller, args=(ep,), daemon=True) for ep in ENDPOINTS]
    for th in ths:
        th.start()
    for th in ths:
        th.join()
    stop.set()
    res = {}
    for ep in ENDPOINTS:
        res[ep] = dict(summary(out[ep]), stale=stale[ep])
        r = res[ep]
        print(f"  busy   {ep:28} median {r.get('median_ms', 0):8.1f} ms  max {r.get('max_ms', 0):8.1f} ms"
              f"  n {r.get('n', 0):3}  stale {r['stale']}", flush=True)
    t.join(timeout=900)
    return res


BROWSER_PROBE = """
window.__lt = [];
try { new PerformanceObserver(function (l) { l.getEntries().forEach(function (e) { window.__lt.push(e.duration); }); }).observe({ type: "longtask", buffered: true }); } catch (e) {}
"""


def browser(svc, work, seconds):
    """The page in Chromium: open it, open the big folder's file list, then
    leave it open on that list while the engine is kept busy. Long tasks
    (over 50 ms on the page's thread) are counted per phase."""
    from playwright.sync_api import sync_playwright
    req = urllib_boot(svc)
    res = {}
    with sync_playwright() as p:
        exe = os.environ.get("CHROMIUM")
        b = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()
        c = b.new_context(viewport={"width": 1280, "height": 860})
        pg = c.new_page()
        reqs = []
        loads = []
        pg.on("request", lambda r: reqs.append((time.time(), r.url)))
        pg.on("load", lambda: loads.append(time.time()))
        pg.add_init_script(BROWSER_PROBE)

        def phase(name):
            lt = pg.evaluate("() => { var l = window.__lt; window.__lt = []; return l; }")
            res[name] = {"long_tasks": len(lt), "long_task_max_ms": round(max(lt), 1) if lt else 0,
                         "long_task_total_ms": round(sum(lt), 1)}

        t = time.time()
        pg.goto(req)
        pg.wait_for_function("() => (document.getElementById('foldertree') || {}).textContent && document.getElementById('foldertree').textContent.includes('Big')", timeout=300000)
        res["open_s"] = round(time.time() - t, 1)
        pg.wait_for_timeout(2000)
        phase("open")
        pg.evaluate("() => { document.querySelector('[data-nav=\"files\"]').click(); }")
        t = time.time()
        pg.evaluate("() => { var s = document.getElementById('filesfolder'); s.value = 'Big'; s.dispatchEvent(new Event('change')); }")
        pg.wait_for_function("() => document.querySelectorAll('#files tbody tr[data-path]').length > 0", timeout=300000)
        res["files_s"] = round(time.time() - t, 1)
        pg.wait_for_timeout(2000)
        res["file_rows_drawn"] = pg.evaluate("() => document.querySelectorAll('#files tbody tr[data-path]').length")
        phase("files")
        heap0 = pg.evaluate("() => performance.memory ? performance.memory.usedJSHeapSize : 0")
        n0, t0 = len(reqs), time.time()
        stop = threading.Event()
        load = threading.Thread(target=busy_load, args=(svc, work, stop), daemon=True)
        load.start()
        # The page's thread answers while the service is busy: how late a
        # timer fires shows how blocked it is.
        lag = pg.evaluate("""ms => new Promise(function (done) {
            var worst = 0, end = Date.now() + ms;
            (function tick(prev) { setTimeout(function () { var now = performance.now(); worst = Math.max(worst, now - prev - 100);
              if (Date.now() < end) { tick(now); } else { done(worst); } }, 100); })(performance.now());
        })""", seconds * 1000)
        stop.set()
        phase("busy")
        heap1 = pg.evaluate("() => performance.memory ? performance.memory.usedJSHeapSize : 0")
        res.update({
            "busy_seconds": seconds,
            "busy_requests_per_min": round((len(reqs) - n0) * 60 / (time.time() - t0), 1),
            "busy_worst_timer_lag_ms": round(lag, 1),
            "heap_files_mb": round(heap0 / 1e6, 1),
            "heap_end_mb": round(heap1 / 1e6, 1),
            "page_loads": len(loads),
            "file_rows_after_busy": pg.evaluate("() => document.querySelectorAll('#files tbody tr[data-path]').length"),
        })
        b.close()
        load.join(timeout=900)
    print("  browser", json.dumps(res), flush=True)
    return res


def urllib_boot(svc):
    c = http.client.HTTPConnection("127.0.0.1", svc.port, timeout=30)
    c.request("POST", "/api/session/boot", body="{}", headers={"X-Varsto-Token": svc.token,
              "Host": f"127.0.0.1:{svc.port}", "Content-Type": "application/json"})
    code = json.loads(c.getresponse().read())["boot"]
    return f"http://127.0.0.1:{svc.port}/?boot={code}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("work")
    ap.add_argument("--files", type=int, default=50000)
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--busy-seconds", type=int, default=40)
    ap.add_argument("--browser", type=int, default=0, help="seconds in Chromium (0: skip)")
    ap.add_argument("--browser-only", action="store_true", help="skip the request timings")
    ap.add_argument("--json")
    a = ap.parse_args()
    work = pathlib.Path(a.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    home = setup(os.path.abspath(a.binary), work, a.files)
    svc = Service(os.path.abspath(a.binary), home)
    result = {"files": a.files}
    try:
        if not a.browser_only:
            print("idle:", flush=True)
            result["idle"] = measure(svc, a.rounds, "idle")
            print(f"busy ({a.busy_seconds} s of sync and verify):", flush=True)
            result["busy"] = measure_busy(svc, work, a.busy_seconds)
        if a.browser:
            print(f"browser ({a.browser} s, busy):", flush=True)
            result["browser"] = browser(svc, work, a.browser)
    finally:
        svc.stop()
    if a.json:
        pathlib.Path(a.json).write_text(json.dumps(result, indent=1))


if __name__ == "__main__":
    sys.exit(main())
