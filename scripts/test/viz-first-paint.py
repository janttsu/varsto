#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""The Visualization page never draws invented content (spec section 64): on a
phone viewport, while the first /api/viz answer is delayed, it shows only a
loading note (no board, no chips, no scene hook); the real answer then
replaces it; a failing first answer shows an error with a retry.

    python3 scripts/test/viz-first-paint.py <varsto binary> <work dir>

Makes a small vault under <work dir> (a throw-away --home), starts the
service and opens the page in Chromium at 390x844. Needs `pip install
playwright` and `playwright install chromium` (CHROMIUM=/path/to/chromium uses
another build). Exits non-zero on failure.
"""
import http.client
import json
import os
import pathlib
import subprocess
import sys
import time

from playwright.sync_api import sync_playwright

PASS = "viz-first-paint-passphrase"
# Names of the page's built-in example scene; none may appear before real data.
SCENE_NAMES = ["Home NAS", "S3 bucket", "Archive", "Laptop", "Phone", "Desktop"]
BLANK = """() => { var c = document.querySelector('.viz canvas'); var x = c.getContext('2d');
  var d = x.getImageData(0, 0, c.width, c.height).data; for (var i = 3; i < d.length; i += 4) { if (d[i]) { return false; } } return true; }"""


def main():
    binary, work = os.path.abspath(sys.argv[1]), pathlib.Path(sys.argv[2]).resolve()
    home = work / "home"
    work.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, VARSTO_PASSPHRASE=PASS)

    def v(*a):
        subprocess.run([binary, "--home", str(home), *a], env=env, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not (home / "vault.json").exists():
        v("init", "--name", "testbox")
        (work / "box").mkdir(exist_ok=True)
        v("storage", "add-local", "boxstore", str(work / "box"))
    try:
        (home / "service.json").unlink()
    except FileNotFoundError:
        pass
    svc = subprocess.Popen([binary, "--home", str(home), "service", "run", "--port", "0", "--interval", "3600"],
                           env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    f = None
    for _ in range(300):
        try:
            f = json.loads((home / "service.json").read_text())
            break
        except (FileNotFoundError, ValueError):
            time.sleep(0.1)
    if not f:
        svc.terminate()
        raise SystemExit("the service did not start")
    failures = []
    try:
        base = f"http://127.0.0.1:{f['port']}"
        c = http.client.HTTPConnection("127.0.0.1", f["port"], timeout=30)
        c.request("POST", "/api/session/boot", body="{}", headers={
            "X-Varsto-Token": f["token"], "Host": f"127.0.0.1:{f['port']}", "Content-Type": "application/json"})
        boot = json.loads(c.getresponse().read())["boot"]
        with sync_playwright() as pw:
            exe = os.environ.get("CHROMIUM")
            b = pw.chromium.launch(executable_path=exe) if exe else pw.chromium.launch()
            ctx = b.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2)
            pg = ctx.new_page()
            # A scene flag in the URL, in storage or on window must do nothing.
            pg.goto(f"{base}/?boot={boot}&scene=demo&demo=1&__vizScene=1")
            pg.wait_for_selector("body[data-view='app']", timeout=30000)
            pg.evaluate("() => { localStorage.setItem('varsto-viz-scene', 'demo'); sessionStorage.setItem('varsto-page', 'viz'); window.__vizScene = {}; }")

            mode = {"m": "delay"}

            def handler(route, _req=None):
                if mode["m"] == "fail":
                    route.fulfill(status=500, body="{}")
                    return
                if mode["m"] == "delay" and not mode.get("held"):
                    mode["held"] = route  # the first answer is slow: held until the checks of the first paint are done
                    return
                route.continue_()
            pg.route("**/api/viz", handler)
            pg.reload()
            pg.wait_for_selector(".viz canvas", timeout=30000)
            pg.wait_for_timeout(1200)
            # First paint, answer still pending.
            note = pg.evaluate("() => { var n = document.querySelector('.viz-note'); return n && !n.classList.contains('hidden') ? n.textContent : null; }")
            if not note or "Loading" not in note:
                failures.append(f"no loading note before the first answer: {note!r}")
            text = pg.evaluate("() => document.querySelector('.viz').innerText")
            for n in SCENE_NAMES:
                if n in text:
                    failures.append(f"scene name {n!r} visible before real data")
            if pg.evaluate("() => document.querySelector('.viz-chips').offsetParent !== null"):
                failures.append("chips visible before real data")
            if not pg.evaluate(BLANK):
                failures.append("the board canvas is not blank before real data")
            if pg.evaluate("() => typeof window.varstoViz.demo !== 'undefined' || typeof window.varstoViz.feed !== 'undefined'"):
                failures.append("the scene hook is reachable without the harness flag")
            if pg.evaluate("() => window.varstoViz.state().phase") != "loading":
                failures.append("phase is not loading")
            # The real answer replaces the note.
            mode["held"].continue_()
            pg.wait_for_function("() => window.varstoViz.state().phase === 'live'", timeout=30000)
            pg.wait_for_timeout(500)
            if pg.evaluate("() => { var n = document.querySelector('.viz-note'); return !n.classList.contains('hidden') && n.dataset.k !== 'empty'; }"):
                failures.append("the loading note stayed after the answer")
            text = pg.evaluate("() => document.querySelector('.viz').innerText")
            for n in ["Home NAS", "S3 bucket", "Archive", "Phone", "Desktop"]:
                if n in text:
                    failures.append(f"scene name {n!r} shown with real data")
            # A failing first answer: error with retry.
            mode["m"] = "fail"
            pg.evaluate("() => sessionStorage.setItem('varsto-page', 'viz')")
            pg.reload()
            pg.wait_for_selector(".viz canvas", timeout=30000)
            pg.wait_for_function("() => window.varstoViz.state().phase === 'error'", timeout=30000)
            if not pg.evaluate("() => !!document.querySelector('.viz-note button')"):
                failures.append("no retry button after a failed first answer")
            if not pg.evaluate(BLANK):
                failures.append("the board is not blank after a failed first answer")
            pg.unroute("**/api/viz")
            pg.click(".viz-note button")
            pg.wait_for_function("() => window.varstoViz.state().phase === 'live'", timeout=30000)
            b.close()
    finally:
        svc.terminate()
        svc.wait(20)
    if failures:
        print("FAIL: " + "; ".join(failures))
        return 1
    print("ok: loading note, blank board, no scene hook, error with retry")
    return 0


if __name__ == "__main__":
    sys.exit(main())
