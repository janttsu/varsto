#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Collect screenshots from CI or test runs into the website's names and sizes.

    python3 scripts/screenshots/finalize.py <in dir> <out dir> [--version V --commit C --source TEXT]

Searches <in dir> recursively for the known names (the newest file wins when
a name appears twice), scales each to the width the website shows it at and
writes <out dir>/<name>.png plus shots.json (version, commit, date, source
and the size of every picture). Unknown files are ignored.
"""
import argparse
import datetime
import json
import pathlib

from PIL import Image

# Website name -> display width in pixels (None keeps the capture's size).
WIDTHS = {
    "desktop-overview-light": 1280, "desktop-overview-dark": 1280,
    "desktop-files-light": 1024, "desktop-files-dark": 1024,
    "mobile-light": 824, "mobile-dark": 824,
    "macos-app": 1024,
    "linux-app": 1280, "linux-tray": None,
    "windows-app": 1280, "windows-tray": None,
    "android-light": 540, "android-dark": 540,
    "android-overview-light": 540, "android-overview-dark": 540,
    "android-files-light": 540, "android-files-dark": 540,
    "ios-simulator": 540,
}

ap = argparse.ArgumentParser()
ap.add_argument("src")
ap.add_argument("dst")
ap.add_argument("--version", default="")
ap.add_argument("--commit", default="")
ap.add_argument("--source", default="")
a = ap.parse_args()
src, dst = pathlib.Path(a.src), pathlib.Path(a.dst)
dst.mkdir(parents=True, exist_ok=True)
found = {}
for p in src.rglob("*.png"):
    if "raw" in p.parts:
        continue
    if p.stem in WIDTHS and (p.stem not in found or p.stat().st_mtime > found[p.stem].stat().st_mtime):
        found[p.stem] = p
sizes = {}
for name, p in sorted(found.items()):
    im = Image.open(p)
    im.load()
    if im.mode not in ("RGB", "RGBA"):
        im = im.convert("RGBA")
    w = WIDTHS[name]
    if w and im.width != w:
        im = im.resize((w, round(im.height * w / im.width)), Image.LANCZOS)
    im.save(dst / f"{name}.png", optimize=True)
    sizes[name] = [im.width, im.height]
    print(f"{name}.png {im.width}x{im.height}  <- {p}")
missing = sorted(set(WIDTHS) - set(found))
if missing:
    print("not in this run (kept as they are):", ", ".join(missing))
meta = {
    "version": a.version,
    "commit": a.commit,
    "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
    "source": a.source,
    "sizes": sizes,
}
(dst / "shots.json").write_text(json.dumps(meta, indent=2) + "\n")
