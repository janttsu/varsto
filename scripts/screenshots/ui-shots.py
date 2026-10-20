#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Capture the interface of the demo vault (demo-vault.sh) in Chromium:
desktop overview and files, and the phone layout, each light and dark.

    python3 scripts/screenshots/ui-shots.py <demo work dir> <out dir> [--lang en|fi|sv]

Needs `pip install playwright pillow` and `playwright install chromium`
(CHROMIUM=/path/to/chromium uses another build). --lang renders the whole
interface in Finnish or Swedish (default en): the page keeps its language in
localStorage ("varsto-lang", see crates/varsto-cli/ui/i18n.js), which is set
in every browser context before the page loads, and the browser locale is set
to match. The demo data stays the invented English example. Writes the website names:
desktop-overview-*, desktop-files-*, desktop-organization-*, desktop-import-*, mobile-*,
mobile-import-* (light and dark). The Import page shows imports of every kind in progress
from example_data.import_jobs() (the demo vault imports nothing), with the YouTube source
chosen.
"""
import argparse
import json
import urllib.request
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import example_data  # noqa: E402

from PIL import Image
from playwright.sync_api import sync_playwright

ap = argparse.ArgumentParser()
ap.add_argument("work")
ap.add_argument("out")
ap.add_argument("--lang", choices=("en", "fi", "sv"), default="en")
args = ap.parse_args()
work, out, LANG = args.work, args.out, args.lang
os.makedirs(out, exist_ok=True)
raw = os.path.join(out, "raw")
os.makedirs(raw, exist_ok=True)


def boot_url(port, token):
    """The address that opens the interface: a one-time code, not the token."""
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/session/boot", data=b"{}", method="POST",
        headers={"X-Varsto-Token": token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return f"http://127.0.0.1:{port}/?boot={json.load(r)['boot']}"


def url(dev):
    j = json.load(open(os.path.join(work, f"{dev}.json")))
    return boot_url(j["port"], j["token"])


# Desktop rows use img.thumb; the compact phone list puts them in .mrow-thumb.
_IMGS = "Array.from(document.querySelectorAll('#files img.thumb, #files .mrow-thumb img'))"
THUMBS = (f"{_IMGS}.length >= 3 && {_IMGS}.every(i => i.complete && i.naturalWidth > 0)")

with sync_playwright() as p:
    exe = os.environ.get("CHROMIUM")
    b = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()

    def ctx(scheme, w=1280, h=860, scale=2):
        c = b.new_context(viewport={"width": w, "height": h}, device_scale_factor=scale,
                          color_scheme=scheme, bypass_csp=True, locale=LANG)
        if LANG != "en":  # the interface language the page itself reads
            c.add_init_script(f"try {{ localStorage.setItem('varsto-lang', '{LANG}'); }} catch (e) {{}}")
        return c

    for scheme in ("light", "dark"):
        # Overview on the laptop.
        c = ctx(scheme, scale=1)
        pg = c.new_page()
        pg.goto(url("laptop"))
        pg.wait_for_selector("#folders tbody tr:nth-child(2)", timeout=60000)
        time.sleep(2)
        pg.screenshot(path=f"{out}/desktop-overview-{scheme}.png")
        c.close()
        # Example data (example_data.py) for two views a small demo cannot fill:
        # where the data of a few folders is kept, and traffic between devices.
        c = ctx(scheme, scale=1)
        pg = c.new_page()
        pg.route("**/api/data/locations*", lambda r: r.fulfill(status=200, content_type="application/json",
                                                            body=json.dumps(example_data.locations())))
        pg.route("**/api/p2p/traffic*", lambda r: r.fulfill(status=200, content_type="application/json",
                                                         body=json.dumps(example_data.traffic())))
        # No event stream here: its live traffic events would replace the example.
        pg.route("**/api/events*", lambda r: r.abort())
        pg.goto(url("laptop"))
        pg.wait_for_selector("#folders tbody tr:nth-child(2)", timeout=60000)
        pg.wait_for_selector("#wherecard:not(.hidden)", timeout=60000)
        time.sleep(1.5)
        pg.query_selector("#wherecard").screenshot(path=f"{out}/desktop-where-{scheme}.png")
        pg.click(".sidebar .nav-item[data-nav=peers]")
        pg.wait_for_selector("#tr-table:not(.hidden)", timeout=60000)
        time.sleep(2.5)
        pg.query_selector("#tr-table").evaluate("t => t.closest('.card').scrollIntoView()")
        # The sticky top bar would cover the card's head in an element shot.
        pg.add_style_tag(content=".topbar { position: static !important; }")
        time.sleep(0.3)
        card = pg.query_selector("#tr-table").evaluate_handle("t => t.closest('.card')")
        card.as_element().screenshot(path=f"{out}/desktop-traffic-{scheme}.png")
        c.close()
        c = ctx(scheme, scale=1)
        pg = c.new_page()
        pg.goto(url("laptop"))
        pg.wait_for_selector("#folders tbody tr:nth-child(2)", timeout=60000)
        # The organization page of the same vault (the laptop is its administrator).
        pg.click(".sidebar .nav-item[data-nav=organization]")
        pg.wait_for_selector("#org-users li", timeout=60000)
        time.sleep(1)
        pg.screenshot(path=f"{out}/desktop-organization-{scheme}.png")
        c.close()
        # The Import page: imports of every kind in progress (example data),
        # and the YouTube source chosen with its fields.
        for name, (w, h, dev) in {"desktop-import": (1280, 1500, "laptop"), "mobile-import": (412, 2200, "phone")}.items():
            c = ctx(scheme, w, h, 1 if dev == "laptop" else 2)
            pg = c.new_page()
            pg.route("**/api/import/jobs", lambda r: r.fulfill(status=200, content_type="application/json",
                                                              body=json.dumps(example_data.import_jobs())))
            pg.route("**/api/events*", lambda r: r.abort())
            pg.goto(url(dev))
            pg.wait_for_selector("#folders tbody tr", timeout=60000)
            pg.evaluate("() => { try { sessionStorage.setItem('varsto-import-kind', 'youtube'); } catch (e) {} }")
            if dev == "laptop":
                pg.click(".sidebar .nav-item[data-nav=import]")
            else:
                pg.wait_for_function("document.body.dataset.mobile === '1'")
                pg.click(".tabbar .nav-item[data-nav=more]")
                time.sleep(0.3)
                pg.click(".more-item[data-nav=import]")
            pg.wait_for_selector("#importjobs li.ij-row:nth-child(3)", timeout=60000)
            pg.fill("#import-yt-url", "https://www.youtube.com/@ExampleWorkshop")
            pg.click("details.ij-failed summary")
            time.sleep(1)
            pg.screenshot(path=f"{out}/{name}-{scheme}.png", full_page=True)
            c.close()
        # Files of Photos with a file's details, cropped around the layout.
        c = ctx(scheme)
        pg = c.new_page()
        pg.goto(url("laptop"))
        pg.wait_for_selector("#folders tbody tr:nth-child(2)", timeout=60000)
        pg.click(".tree-item[data-folder=Photos]")
        pg.wait_for_selector("#files tbody tr:nth-child(3)")
        pg.wait_for_function(THUMBS, timeout=60000)
        pg.click("#files tbody tr:nth-child(2)")
        pg.wait_for_selector("#filedetails:not(.hidden)")
        pg.wait_for_function("(function(){var i=document.querySelector('#fd-preview img');"
                             "return i && i.complete && i.naturalWidth>0})()", timeout=60000)
        time.sleep(0.5)
        full_path = f"{raw}/files-full-{scheme}.png"
        pg.screenshot(path=full_path)
        bb = pg.query_selector(".files-layout").bounding_box()
        full = Image.open(full_path)
        x, y, w, h = [v * 2 for v in (bb["x"], bb["y"], bb["width"], bb["height"])]
        m = 48
        crop = full.crop((max(0, x - m), max(0, y - m), min(full.width, x + w + m), min(full.height, y + h + m)))
        crop.resize((crop.width // 2, crop.height // 2), Image.LANCZOS).save(
            f"{out}/desktop-files-{scheme}.png", optimize=True)
        c.close()
        # The phone layout: the selective Photos folder.
        c = ctx(scheme, 412, 915)
        pg = c.new_page()
        pg.goto(url("phone"))
        pg.wait_for_selector("#folders tbody tr", timeout=60000)
        pg.wait_for_function("document.body.dataset.mobile === '1'")
        pg.click(".tabbar .nav-item[data-nav=files]")
        time.sleep(0.4)
        pg.click(".folder-card[data-folder=Photos]")
        pg.wait_for_selector("#files tbody tr:nth-child(3)")
        pg.wait_for_function(THUMBS, timeout=60000)
        time.sleep(0.5)
        pg.screenshot(path=f"{out}/mobile-{scheme}.png")
        c.close()
    b.close()

for n in sorted(os.listdir(out)):
    if n.endswith(".png"):
        print(n, Image.open(os.path.join(out, n)).size)
