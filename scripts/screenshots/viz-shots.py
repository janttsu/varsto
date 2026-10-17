#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Screenshots of the Visualization page of the demo vault (demo-vault.sh):
4K at device pixel ratio 1 and 2, a laptop size and a phone, on the theme's
own background and on pure black.

    python3 scripts/screenshots/viz-shots.py <demo work dir> <out dir>

With VIZ_LIVE=1 the page shows the service's own snapshot; by default the
snapshot is the page's demo scene (flows, a docked disk, a move waiting for a
disk), so that every part of the picture is drawn. CHROMIUM=/path/to/chromium
VIZ_SCENE=scene.json serves that snapshot instead of the demo scene, ONLY=name,name
takes only some of the shots, VIZ_IDLE=1 waits until the bar has faded out; CHROMIUM=/path/to/chromium uses another build.
"""
import json
import os
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

work, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
live = os.environ.get("VIZ_LIVE") == "1"


def boot_url():
    j = json.load(open(os.path.join(work, "laptop.json")))
    req = urllib.request.Request(
        f"http://127.0.0.1:{j['port']}/api/session/boot", data=b"{}", method="POST",
        headers={"X-Varsto-Token": j["token"], "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return f"http://127.0.0.1:{j['port']}/?boot={json.load(r)['boot']}"


SHOTS = [
    # name, width, height, device scale factor, colour scheme, background mode, full screen
    ("viz-4k-dpr1-light", 3840, 2160, 1, "light", "auto", True),
    ("viz-tv-4k", 3840, 2160, 1, "dark", "auto", True),
    ("viz-tv-1080", 1920, 1080, 1, "dark", "auto", True),
    ("viz-tv-4k-black", 3840, 2160, 1, "dark", "black", True),
    ("viz-4k-dpr2-black", 1920, 1080, 2, "dark", "black", True),
    ("viz-4k-dpr2-dark", 1920, 1080, 2, "dark", "auto", True),
    ("viz-window-light", 1440, 900, 1, "light", "auto", False),
    ("viz-phone-light", 390, 844, 3, "light", "auto", False),
    ("viz-phone-black", 390, 844, 3, "dark", "black", True),
]

only = [x for x in os.environ.get("ONLY", "").split(",") if x]
scene = json.load(open(os.environ["VIZ_SCENE"])) if os.environ.get("VIZ_SCENE") else None

with sync_playwright() as p:
    exe = os.environ.get("CHROMIUM")
    b = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()
    for name, w, h, dsf, scheme, mode, fullscreen in SHOTS:
        if only and name not in only:
            continue
        c = b.new_context(viewport={"width": w, "height": h}, device_scale_factor=dsf,
                          color_scheme=scheme, bypass_csp=False)
        pg = c.new_page()
        errors = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        if os.environ.get("VIZ_UI"):  # develop the page without rebuilding: serve viz.js and viz.css from this directory
            for f, ct in (("viz.js", "text/javascript"), ("viz.css", "text/css")):
                pg.route("**/" + f, (lambda f, ct: lambda route, _request=None: route.fulfill(status=200, content_type=ct, path=os.path.join(os.environ["VIZ_UI"], f)))(f, ct))
        # The page's scene hook (varstoViz.demo / feed) exists only when this flag is set before the page loads.
        pg.add_init_script("window.__VARSTO_VIZ_TEST = true;")
        pg.goto(boot_url())
        pg.wait_for_selector("body[data-view='app']", timeout=30000)
        pg.evaluate(f"localStorage.setItem('varsto-viz-bg', '{mode}'); sessionStorage.setItem('varsto-page', 'viz');")
        if not live:
            # The page's own demo scene, served as if it were the service's snapshot.
            demo = scene or json.loads(pg.evaluate("JSON.stringify(window.varstoViz.demo())"))
            t0 = time.time()

            def serve(route, _request=None, demo=demo, t0=t0):
                body = dict(demo, utc=demo["utc"] + (time.time() - t0), unlocked=True)
                body.pop("demo", None)
                route.fulfill(status=200, content_type="application/json", body=json.dumps(body))

            pg.route("**/api/viz", serve)
        pg.reload()
        pg.wait_for_selector(".viz canvas", timeout=30000)
        pg.wait_for_timeout(1500)
        if fullscreen:
            pg.keyboard.press("f")
            pg.wait_for_timeout(1500)
        if os.environ.get("VIZ_IDLE"):  # let the bar fade out, as on a TV nobody touches
            pg.wait_for_timeout(5500)
        info = pg.evaluate("(function(){var c=document.querySelector('.viz canvas');return {css:[c.clientWidth,c.clientHeight],scroll:[document.documentElement.scrollWidth>innerWidth,document.documentElement.scrollHeight>innerHeight],px:[c.width,c.height],dpr:window.devicePixelRatio,res:document.querySelector('.viz-bar .viz-status:last-child').textContent}})()")
        print(name, info, "errors:", errors[:3])
        pg.screenshot(path=os.path.join(out, name + ".png"))
        c.close()
    b.close()
