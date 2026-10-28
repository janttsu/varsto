#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Collect screenshots from CI or test runs into the website's names and sizes.

    python3 scripts/screenshots/finalize.py <in dir> <out dir> [--version V --commit C --source TEXT --run N] [--pack]

Searches <in dir> recursively for the known names (the newest file wins when
a name appears twice), scales each to the width the website shows it at and
writes <out dir>/<name>.png plus shots.json (version, commit, date, source
and the size of every picture). Unknown files are ignored.

With --pack the output is what ops/site/screenshots-sync.py takes: en/ (the
shared and English pictures), fi/ and sv/ (the localized interface from
ui-shots.py --lang) and viz/viz-tv.png (the 4K TV scene scaled to 1920 px), and
shots.json holds the sizes per set: {"en": {name: [w, h]}, "fi": ..., "sv": ...,
"viz": ...}.
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
    "desktop-organization-light": 1280, "desktop-organization-dark": 1280,
    "desktop-where-light": None, "desktop-where-dark": None,
    "desktop-traffic-light": None, "desktop-traffic-dark": None,
    "desktop-rendezvous-light": None, "desktop-rendezvous-dark": None,
    "mobile-light": 824, "mobile-dark": 824,
    "macos-app": 1024,
    "linux-app": 1280, "linux-tray": None,
    "windows-app": 1280, "windows-tray": None,
    "android-light": 540, "android-dark": 540,
    "android-overview-light": 540, "android-overview-dark": 540,
    "android-files-light": 540, "android-files-dark": 540,
    "ios-simulator": 540,
}

# Website pictures of the localized interface and of the visualization. In a
# CI download directory each lives in the artifact folder named here.
UI_WIDTHS = {k: v for k, v in WIDTHS.items() if k.startswith(("desktop-", "mobile-"))}
# set -> (artifact folder, {capture name: (website name, display width)})
SETS = {
    "en": (None, {k: (k, v) for k, v in WIDTHS.items()}),
    "fi": ("shots-linux-fi", {k: (k, v) for k, v in UI_WIDTHS.items()}),
    "sv": ("shots-linux-sv", {k: (k, v) for k, v in UI_WIDTHS.items()}),
    # the 4K render of the TV scene (viz-shots.py, viz_tv_scene.py), exported at 1920 px
    "viz": ("shots-linux-viz", {"viz-tv-4k": ("viz-tv", 1920)}),
}

ap = argparse.ArgumentParser()
ap.add_argument("src")
ap.add_argument("dst")
ap.add_argument("--version", default="")
ap.add_argument("--commit", default="")
ap.add_argument("--source", default="")
ap.add_argument("--run", default="")
ap.add_argument("--pack", action="store_true",
                help="write <dst>/en, fi, sv and viz (a CI download directory with the artifact "
                     "folders shots-linux-fi, -sv and -viz) and one shots.json with sizes per set; "
                     "without it everything goes flat into <dst> as before")
a = ap.parse_args()
src, dst = pathlib.Path(a.src), pathlib.Path(a.dst)


def build(name, out):
    """Scale the captures of one set into <out>; returns {website name: [w, h]}."""
    folder, names = SETS[name]
    others = {f for f, _ in SETS.values() if f and f != folder}
    out.mkdir(parents=True, exist_ok=True)
    found = {}
    for p in src.rglob("*.png"):
        if "raw" in p.parts or (folder and folder not in p.parts) or others & set(p.parts):
            continue
        if p.stem in names and (p.stem not in found or p.stat().st_mtime > found[p.stem].stat().st_mtime):
            found[p.stem] = p
    sizes = {}
    for cap, p in sorted(found.items()):
        site_name, w = names[cap]
        im = Image.open(p)
        im.load()
        if im.mode not in ("RGB", "RGBA"):
            im = im.convert("RGBA")
        if w and im.width != w:
            im = im.resize((w, round(im.height * w / im.width)), Image.LANCZOS)
        im.save(out / f"{site_name}.png", optimize=True)
        sizes[site_name] = [im.width, im.height]
        print(f"{name}/{site_name}.png {im.width}x{im.height}  <- {p}")
    missing = sorted(set(names) - set(found))
    if missing:
        print(f"not in this run, set {name} (kept as they are):", ", ".join(missing))
    return sizes


meta = {
    "version": a.version,
    "commit": a.commit,
    "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
    "source": a.source,
    "run": a.run,
}
if a.pack:
    meta["sizes"] = {name: build(name, dst / name) for name in SETS}
else:
    meta["sizes"] = build("en", dst)
(dst / "shots.json").write_text(json.dumps(meta, indent=2) + "\n")
