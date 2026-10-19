#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""The page is never reloaded when the service goes away: it says that it
reconnects and keeps what it shows (spec section 71).

    python3 scripts/test/ui-no-reload.py <varsto binary> <work dir>

Makes a small vault under <work dir> (a throw-away --home), starts the
service, opens the page in Chromium, stops the service and starts it again,
and checks that the page was not navigated or reloaded, that it showed the
reconnecting line meanwhile, and that the folder list it had stayed.
Needs `pip install playwright` and `playwright install chromium`
(CHROMIUM=/path/to/chromium uses another build). Exits non-zero on failure.
"""
import http.client
import json
import os
import pathlib
import re
import subprocess
import sys
import time

from playwright.sync_api import sync_playwright

PASS = "reload-test-passphrase"


def main():
    binary, work = os.path.abspath(sys.argv[1]), pathlib.Path(sys.argv[2]).resolve()
    home, docs = work / "home", work / "Docs"
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "a.txt").write_text("a\n")
    env = dict(os.environ, VARSTO_PASSPHRASE=PASS)

    def v(*a):
        subprocess.run([binary, "--home", str(home), *a], env=env, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not (home / "vault.json").exists():
        out = subprocess.run([binary, "--home", str(home), "--json", "init", "--name", "laptop"],
                             env=env, check=True, capture_output=True, text=True).stdout
        # The recovery words of the kit make the folder's recovery copy.
        kit = json.loads(out)["kit"].split("RECOVERY WORDS")[1]
        words = " ".join(re.findall(r"\d+\.\s+([a-z]+)", kit))
        (work / "box").mkdir(exist_ok=True)
        v("storage", "add-local", "box", str(work / "box"))
        subprocess.run([binary, "--home", str(home), "folder", "add", "Docs", str(docs)],
                       env=dict(env, VARSTO_RECOVERY_WORDS=words), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        v("sync")

    def start():
        try:
            (home / "service.json").unlink()
        except FileNotFoundError:
            pass
        p = subprocess.Popen([binary, "--home", str(home), "service", "run", "--port", "0",
                              "--interval", "3600"], env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(300):
            try:
                return p, json.loads((home / "service.json").read_text())
            except (FileNotFoundError, ValueError):
                time.sleep(0.1)
        raise SystemExit("the service did not start")

    svc, f = start()
    c = http.client.HTTPConnection("127.0.0.1", f["port"], timeout=30)
    c.request("POST", "/api/session/boot", body="{}", headers={
        "X-Varsto-Token": f["token"], "Host": f"127.0.0.1:{f['port']}",
        "Content-Type": "application/json"})
    url = f"http://127.0.0.1:{f['port']}/?boot={json.loads(c.getresponse().read())['boot']}"
    failures = []
    with sync_playwright() as pw:
        exe = os.environ.get("CHROMIUM")
        b = pw.chromium.launch(executable_path=exe) if exe else pw.chromium.launch()
        pg = b.new_page()
        navs = []
        pg.on("framenavigated", lambda fr: navs.append(fr.url) if fr == pg.main_frame else None)
        pg.goto(url)
        pg.wait_for_function("() => document.querySelector('#foldertree') && document.querySelector('#foldertree').textContent.includes('Docs')", timeout=30000)
        pg.evaluate("() => { window.__kept = 1; }")
        first = len(navs)
        svc.terminate()
        svc.wait(20)
        # The page notices on its next request (the service poll; focus asks too).
        pg.evaluate("() => window.dispatchEvent(new Event('focus'))")
        try:
            pg.wait_for_function("() => { var n = document.getElementById('connnote'); return n && !n.classList.contains('hidden'); }", timeout=20000)
        except Exception:
            failures.append("no reconnecting line while the service was down")
        svc, f = start()
        pg.wait_for_timeout(8000)
        if pg.evaluate("() => window.__kept") != 1:
            failures.append("the page was reloaded")
        if len(navs) != first:
            failures.append(f"the page navigated: {navs[first:]}")
        if "Docs" not in pg.evaluate("() => document.querySelector('#foldertree').textContent"):
            failures.append("the folder list was cleared")
        b.close()
    svc.terminate()
    svc.wait(20)
    if failures:
        print("FAIL: " + "; ".join(failures))
        return 1
    print("ok: no reload, reconnecting line shown, page kept")
    return 0


if __name__ == "__main__":
    sys.exit(main())
