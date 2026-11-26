#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""A busy service is not shown as a failure.

    python3 scripts/test/ui-busy.py <varsto binary> <work dir>

Makes a small vault under <work dir> (a throw-away --home), starts the
service and opens the page in Chromium with some answers replaced by the
"busy" answer of the service (503 with `busy`), and checks that:

* a background read that is told to ask again (Retry-After) is asked again
  by the page itself, the line under the title says the service is busy
  meanwhile, nothing red appears in the activity list, and the page fills
  once the service answers;
* an action that finds the service busy gets one calm line (not a failure),
  is not sent again, and never shows the address of another request;
* the calm line is translated (Finnish);
* a real failure is still shown as one.

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
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright

PASS = "busy-test-passphrase"


def busy(why, again):
    """The service's own busy answer; `again`: with Retry-After."""
    headers = {"Content-Type": "application/json"}
    if again:
        headers["Retry-After"] = "1"
    body = json.dumps({"error": f"Varsto is busy ({why}); try again in a moment", "busy": why})
    return {"status": 503, "headers": headers, "body": body}


def at(path):
    return lambda url: urlparse(url).path == path


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
        kit = json.loads(out)["kit"].split("RECOVERY WORDS")[1]
        words = " ".join(re.findall(r"\d+\.\s+([a-z]+)", kit))
        (work / "box").mkdir(exist_ok=True)
        v("storage", "add-local", "box", str(work / "box"))
        subprocess.run([binary, "--home", str(home), "folder", "add", "Docs", str(docs)],
                       env=dict(env, VARSTO_RECOVERY_WORDS=words), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        v("sync")
    try:
        (home / "service.json").unlink()
    except FileNotFoundError:
        pass
    svc = subprocess.Popen([binary, "--home", str(home), "service", "run", "--port", "0",
                            "--interval", "3600"], env=env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    f = None
    for _ in range(300):
        try:
            f = json.loads((home / "service.json").read_text())
            break
        except (FileNotFoundError, ValueError):
            time.sleep(0.1)
    if f is None:
        svc.terminate()
        raise SystemExit("the service did not start")

    def page_url():
        """A fresh address: the boot code opens the interface once."""
        c = http.client.HTTPConnection("127.0.0.1", f["port"], timeout=30)
        c.request("POST", "/api/session/boot", body="{}", headers={
            "X-Varsto-Token": f["token"], "Host": f"127.0.0.1:{f['port']}",
            "Content-Type": "application/json"})
        return f"http://127.0.0.1:{f['port']}/?boot={json.loads(c.getresponse().read())['boot']}"

    failures = []
    RED = "() => Array.from(document.querySelectorAll('#log .activity-item.bad')).map(e => e.textContent)"
    LINES = "() => Array.from(document.querySelectorAll('#log .activity-item')).map(e => [e.className, e.textContent])"
    TREE = "() => { var t = document.querySelector('#foldertree'); return !!t && t.textContent.includes('Docs'); }"
    NOTE = "() => { var n = document.getElementById('connnote'); return !!n && !n.classList.contains('hidden') && n.dataset.kind === 'busy'; }"
    try:
        with sync_playwright() as pw:
            exe = os.environ.get("CHROMIUM")
            b = pw.chromium.launch(executable_path=exe) if exe else pw.chromium.launch()

            # 1. A background read: busy three times (ask again), then the real answer.
            pg = b.new_page()
            asked = {"status": 0, "verify": 0}

            def status(route):
                asked["status"] += 1
                if asked["status"] <= 3:
                    route.fulfill(**busy("sync", True))
                else:
                    route.continue_()
            pg.route(at("/api/status"), status)
            pg.goto(page_url())
            try:
                pg.wait_for_function(NOTE, timeout=10000)
            except Exception:
                failures.append("no busy line under the title while the status read was busy")
            try:
                pg.wait_for_function(TREE, timeout=30000)
            except Exception:
                failures.append("the folder list did not fill after the busy answers")
            if asked["status"] < 4:
                failures.append(f"the busy read was not asked again ({asked['status']} requests)")
            red = pg.evaluate(RED)
            if red:
                failures.append(f"a busy background read was shown as a failure: {red}")
            try:
                pg.wait_for_function("() => document.getElementById('connnote').classList.contains('hidden')", timeout=15000)
            except Exception:
                failures.append("the busy line stayed after the service answered")
            pg.unroute(at("/api/status"))

            # 2. An action: busy after the service waited itself (no Retry-After).
            def verify(route):
                asked["verify"] += 1
                route.fulfill(**busy("sync", False))
            pg.route(at("/api/verify/run"), verify)
            pg.evaluate("() => document.getElementById('av-run').click()")
            calm = "Varsto is busy (sync); try again in a moment"
            try:
                pg.wait_for_function(f"() => Array.from(document.querySelectorAll('#log .activity-item')).some(e => e.textContent.includes({json.dumps(calm)}))", timeout=10000)
            except Exception:
                failures.append(f"no calm line for a busy action: {pg.evaluate(LINES)}")
            pg.wait_for_timeout(3000)
            if asked["verify"] != 1:
                failures.append(f"a busy action was sent {asked['verify']} times")
            red = pg.evaluate(RED)
            if red:
                failures.append(f"a busy action was shown as a failure: {red}")
            pg.unroute(at("/api/verify/run"))

            # 3. Busy with another request: its address is not shown.
            pg.route(at("/api/verify/run"), lambda route: route.fulfill(**busy("/api/storage/known", False)))
            pg.evaluate("() => document.getElementById('av-run').click()")
            other = "Varsto is busy with another request; try again in a moment"
            try:
                pg.wait_for_function(f"() => Array.from(document.querySelectorAll('#log .activity-item')).some(e => e.textContent.includes({json.dumps(other)}))", timeout=10000)
            except Exception:
                failures.append(f"no calm line when another request has the engine: {pg.evaluate(LINES)}")
            if "/api/" in pg.evaluate("() => document.getElementById('log').textContent"):
                failures.append("the activity list shows a request address")
            if pg.evaluate(RED):
                failures.append(f"busy with another request was shown as a failure: {pg.evaluate(RED)}")
            pg.unroute(at("/api/verify/run"))

            # 4. A real failure is still one.
            pg.route(at("/api/verify/run"), lambda route: route.fulfill(
                status=400, headers={"Content-Type": "application/json"}, body=json.dumps({"error": "boom"})))
            pg.evaluate("() => document.getElementById('av-run').click()")
            try:
                pg.wait_for_function("() => Array.from(document.querySelectorAll('#log .activity-item.bad')).some(e => e.textContent.includes('verification failed') && e.textContent.includes('boom'))", timeout=10000)
            except Exception:
                failures.append(f"a real failure was not shown as one: {pg.evaluate(LINES)}")
            pg.close()

            # 5. The calm line in Finnish.
            ctx = b.new_context(locale="fi-FI")
            ctx.add_init_script("try { localStorage.setItem('varsto-lang', 'fi'); } catch (e) {}")
            fi = ctx.new_page()
            fi.goto(page_url())
            fi.wait_for_function(TREE, timeout=30000)
            fi.route(at("/api/verify/run"), lambda route: route.fulfill(**busy("sync", False)))
            fi.evaluate("() => document.getElementById('av-run').click()")
            finnish = "Varstolla on muuta työtä kesken (sync); yritä hetken kuluttua uudelleen"
            try:
                fi.wait_for_function(f"() => Array.from(document.querySelectorAll('#log .activity-item')).some(e => e.textContent.includes({json.dumps(finnish)}))", timeout=10000)
            except Exception:
                failures.append(f"the calm line is not translated: {fi.evaluate(LINES)}")
            b.close()
    finally:
        svc.terminate()
        svc.wait(20)
    if failures:
        print("FAIL: " + "; ".join(failures))
        return 1
    print("ok: busy reads asked again and silent, busy actions calm and sent once, failures still red")
    return 0


if __name__ == "__main__":
    sys.exit(main())
