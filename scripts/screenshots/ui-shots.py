#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Capture the interface of the demo vault (demo-vault.sh) in Chromium:
desktop overview and files, and the phone layout, each light and dark.

    python3 scripts/screenshots/ui-shots.py <demo work dir> <out dir>

Needs `pip install playwright pillow` and `playwright install chromium`
(CHROMIUM=/path/to/chromium uses another build). Writes the website names:
desktop-overview-*, desktop-files-*, mobile-* (light and dark).
"""
import json
import os
import sys
import time

from PIL import Image
from playwright.sync_api import sync_playwright

work, out = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True)
raw = os.path.join(out, "raw")
os.makedirs(raw, exist_ok=True)


def url(dev):
    j = json.load(open(os.path.join(work, f"{dev}.json")))
    return f"http://127.0.0.1:{j['port']}/?token={j['token']}"


THUMBS = ("Array.from(document.querySelectorAll('img.thumb')).length >= 3 && "
          "Array.from(document.querySelectorAll('img.thumb')).every(i => i.complete && i.naturalWidth > 0)")

with sync_playwright() as p:
    exe = os.environ.get("CHROMIUM")
    b = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()

    def ctx(scheme, w=1280, h=860, scale=2):
        return b.new_context(viewport={"width": w, "height": h}, device_scale_factor=scale,
                             color_scheme=scheme, bypass_csp=True)

    for scheme in ("light", "dark"):
        # Overview on the laptop.
        c = ctx(scheme, scale=1)
        pg = c.new_page()
        pg.goto(url("laptop"))
        pg.wait_for_selector("#folders tbody tr:nth-child(2)", timeout=60000)
        time.sleep(2)
        pg.screenshot(path=f"{out}/desktop-overview-{scheme}.png")
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
