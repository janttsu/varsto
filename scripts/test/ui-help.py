#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Browser test of the Help page, on a throwaway vault in a temporary
directory (never the user's own): with no vault, with a vault but no
storage, and with a storage and a folder, in English and in Finnish. It
checks the first step, that the step's button leads to the right place, and
that the "?" in the page header opens the page's guide, and saves
screenshots.

    python3 scripts/test/ui-help.py <varsto binary> <screenshot dir>

Needs `pip install playwright`; CHROMIUM=/path/to/chromium picks the
browser (default /usr/bin/chromium when it exists).
"""
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request

from playwright.sync_api import sync_playwright

BIN = os.path.abspath(sys.argv[1])
OUT = os.path.abspath(sys.argv[2])
os.makedirs(OUT, exist_ok=True)
PASS = "help-ui-test-passphrase"
work = tempfile.mkdtemp(prefix="varsto-help-ui-")
home = os.path.join(work, "home")
# The service and the command line see only the temporary directory.
ENV = dict(os.environ, HOME=work, VARSTO_NO_INSTALL="1", VARSTO_PASSPHRASE=PASS,
           VARSTO_FOLDER_ROOT=os.path.join(work, "Varsto"))
ENV.pop("VARSTO_HOME", None)
service = None
failures = []


def cli(*args):
    subprocess.run([BIN, "--home", home, *args], env=ENV, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def start():
    global service
    try:
        os.remove(os.path.join(home, "service.json"))
    except FileNotFoundError:
        pass
    log = open(os.path.join(work, "service.log"), "a")
    service = subprocess.Popen([BIN, "--home", home, "service", "run", "--port", "0", "--interval", "3600"],
                               env=ENV, stdout=log, stderr=log)
    for _ in range(60):
        if os.path.exists(os.path.join(home, "service.json")):
            time.sleep(0.5)
            return
        time.sleep(0.5)
    raise SystemExit("the service did not start")


def stop():
    global service
    if service:
        service.send_signal(signal.SIGTERM)
        try:
            service.wait(15)
        except subprocess.TimeoutExpired:
            service.kill()
        service = None


def boot_url(port, token):
    """The address that opens the interface: a one-time code, not the token."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/session/boot", data=b"{}", method="POST",
        headers={"X-Varsto-Token": token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return f"http://127.0.0.1:{port}/?boot={json.load(r)['boot']}"


def url():
    j = json.load(open(os.path.join(home, "service.json")))
    return boot_url(j["port"], j["token"])


def check(cond, what):
    print(("ok   " if cond else "FAIL ") + what)
    if not cond:
        failures.append(what)


def page(browser, lang, w=1280, h=900):
    c = browser.new_context(viewport={"width": w, "height": h})
    pg = c.new_page()
    pg.on("pageerror", lambda e: failures.append(f"page error: {e}"))
    pg.add_init_script(f"try {{ localStorage.setItem('varsto-lang', '{lang}'); }} catch (e) {{}}")
    pg.goto(url())
    return c, pg


def first_step(pg, sel):
    pg.wait_for_selector(f"{sel} .help-step", timeout=20000)
    time.sleep(0.5)
    return pg.eval_on_selector(f"{sel} .help-step", "e => [e.dataset.step, e.querySelector('.help-step-title').textContent]")


try:
    with sync_playwright() as p:
        exe = os.environ.get("CHROMIUM") or ("/usr/bin/chromium" if os.path.exists("/usr/bin/chromium") else None)
        b = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()

        # 1. No vault: the setup screen shows the help panel, create first.
        start()
        titles = {}
        for lang in ("en", "fi"):
            c, pg = page(b, lang)
            sid, title = first_step(pg, "#prehelp-next")
            titles[lang] = title
            check(sid == "create_vault", f"[{lang}] no vault: first step is create_vault ({sid}: {title})")
            check(pg.is_visible("#prehelp") and pg.is_visible("#setup"), f"[{lang}] no vault: help panel above the setup screen")
            pg.screenshot(path=f"{OUT}/help-novault-{lang}.png", full_page=True)
            pg.click("#prehelp-next .help-step >> nth=0 >> .help-actions button >> nth=0")
            time.sleep(1)
            focused = pg.evaluate("document.activeElement && document.activeElement.closest('form') ? document.activeElement.closest('form').id : ''")
            check(focused == "init", f"[{lang}] no vault: the button leads to the Create vault form ({focused})")
            c.close()
        check(titles["fi"] != titles["en"] and "holvi" in titles["fi"].lower(), f"no vault: the step is in Finnish ({titles['fi']})")
        stop()

        # 2. A vault without a storage: Help opens by itself, add a storage first.
        init = subprocess.run([BIN, "--home", home, "--json", "init", "--name", "laptop"], env=ENV,
                              check=True, capture_output=True, text=True).stdout
        kit = json.loads(init)["kit"].split("RECOVERY WORDS")[1]
        RECOVERY_WORDS = " ".join(re.findall(r"\d+\.\s+([a-z]+)", kit))
        start()
        for lang in ("en", "fi"):
            c, pg = page(b, lang)
            pg.wait_for_selector('.page[data-page="help"]:not(.hidden)', timeout=20000)
            check(True, f"[{lang}] no storage: Help opens by itself")
            sid, title = first_step(pg, "#help-next")
            check(sid == "add_storage", f"[{lang}] no storage: first step is add_storage ({title})")
            if lang == "fi":
                check("tallennuspaikka" in title.lower(), f"[fi] no storage: the step is in Finnish ({title})")
            pg.screenshot(path=f"{OUT}/help-nostorage-{lang}.png", full_page=True)
            pg.click("#help-next .help-step >> nth=0 >> .help-actions button >> nth=0")
            time.sleep(1)
            check(pg.is_visible('.page[data-page="storages"]') and pg.is_visible("#addstorage"),
                  f"[{lang}] no storage: the button opens Storages with the Add a storage form")
            focused = pg.evaluate("document.activeElement && document.activeElement.closest('form') ? document.activeElement.closest('form').id : ''")
            check(focused == "addstorage", f"[{lang}] no storage: the form has the focus ({focused})")
            # The "?" on the Storages page opens the storages guide.
            pg.click("#pagehelp")
            pg.wait_for_selector('#help-guides details[data-guide="storages"][open]', timeout=10000)
            check(True, f"[{lang}] the ? button opens the Storages guide")
            c.close()
        stop()

        # 3. A storage and a folder with a file: the default policy wants a
        # copy in the cloud, then the recovery words and other devices.
        os.makedirs(os.path.join(work, "docs"))
        with open(os.path.join(work, "docs", "notes.txt"), "w") as f:
            f.write("hello\n" * 1000)
        cli("storage", "add-local", "box", os.path.join(work, "box"))
        subprocess.run([BIN, "--home", home, "folder", "add", "docs", os.path.join(work, "docs")],
                       env=dict(ENV, VARSTO_RECOVERY_WORDS=RECOVERY_WORDS), check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cli("sync")
        start()
        for lang in ("en", "fi"):
            c, pg = page(b, lang)
            pg.wait_for_selector("#helpnext:not(.hidden)", timeout=20000)
            check(True, f"[{lang}] storage+folder: the overview shows the next step")
            pg.click('.sidebar .nav-item[data-nav="help"]')
            sid, title = first_step(pg, "#help-next")
            check(sid == "policy:docs", f"[{lang}] storage+folder: first step is the cloud copy ({sid}: {title})")
            steps = pg.eval_on_selector_all("#help-next .help-step", "l => l.map(e => e.dataset.step)")
            check("kit" in steps and "add_device" in steps, f"[{lang}] storage+folder: kit and add_device follow ({steps})")
            figs = pg.eval_on_selector_all("#help-now .help-fig-value", "l => l.map(e => e.textContent)")
            check(figs[:3] == ["1", "1", "1"], f"[{lang}] storage+folder: 1 device, 1 storage, 1 folder ({figs})")
            if lang == "fi":
                check("pilvi" in title.lower(), f"[fi] the place is translated ({title})")
            pg.click("#help-next .help-step >> nth=0 >> .help-actions button >> nth=1")
            check(pg.is_visible("#help-next .help-step >> nth=0 >> pre.help-cmd"), f"[{lang}] Show the command reveals it")
            pg.screenshot(path=f"{OUT}/help-folder-{lang}.png", full_page=True)
            # The kit step leads to the Recovery package page and the kit dialog.
            pg.click('#help-next .help-step[data-step="kit"] .help-actions button >> nth=0')
            time.sleep(1)
            check(pg.is_visible('.page[data-page="recovery"]') and pg.is_visible("#modal"),
                  f"[{lang}] the kit step opens the Recovery package page and the kit dialog")
            c.close()
        # The phone layout: Help under More.
        c, pg = page(b, "en", 390, 844)
        pg.click('.tabbar .nav-item[data-nav="more"]')
        pg.click('.more-item[data-nav="help"]')
        first_step(pg, "#help-next")
        pg.screenshot(path=f"{OUT}/help-folder-phone-en.png", full_page=True)
        check(pg.is_visible('.page[data-page="help"]'), "phone: Help is under More")
        c.close()
        stop()

        # 4. Locked: the unlock screen offers Help with the unlock step.
        env = dict(ENV)
        env.pop("VARSTO_PASSPHRASE")
        log = open(os.path.join(work, "service.log"), "a")
        # A service that stops cleanly removes its file itself.
        if os.path.exists(os.path.join(home, "service.json")):
            os.remove(os.path.join(home, "service.json"))
        service = subprocess.Popen([BIN, "--home", home, "service", "run", "--port", "0", "--interval", "3600"],
                                   env=env, stdout=log, stderr=log)
        for _ in range(60):
            if os.path.exists(os.path.join(home, "service.json")):
                break
            time.sleep(0.5)
        time.sleep(0.5)
        c, pg = page(b, "sv")
        pg.wait_for_selector("#unlock:not(.hidden)", timeout=20000)
        pg.click("#prehelp-toggle")
        sid, title = first_step(pg, "#prehelp-next")
        check(sid == "unlock", f"[sv] locked: first step is unlock ({title})")
        pg.screenshot(path=f"{OUT}/help-locked-sv.png", full_page=True)
        c.close()
        stop()
        b.close()
finally:
    stop()
    shutil.rmtree(work, ignore_errors=True)

print()
if failures:
    print(f"{len(failures)} failure(s):")
    for f in failures:
        print("  " + f)
    sys.exit(1)
print("all Help page checks passed; screenshots in " + OUT)
