# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Sprites for the live visualization page (crates/varsto-cli/ui/viz/).

Every object of the website scenes, rendered alone with the studio camera and
light rig of `scene_kit` on a transparent background (a shadow catcher keeps the
soft contact shadow), in the light and the dark palette, then converted to
WebP with alpha at 512 and 1024 px.

    ~/.local/opt/blender/blender -b --python website/tools/render/viz_sprites.py -- [options]

Options (after the "--"):
    --only NAME[,NAME]   render only these sprites
    --samples N          Cycles samples (default 96)
    --device AUTO|OPTIX|CUDA|CPU   AUTO picks the GPU when 2.5 GB of VRAM is free
    --work DIR           scratch directory for the raw PNGs
    --out DIR            output directory (default crates/varsto-cli/ui/viz)
    --theme light|dark|both
    --convert-only       skip rendering, convert the PNGs in --work (plain python3 works too)

Outputs `<name>.webp` / `<name>-dark.webp` at 512 px and `<name>@2x.webp` /
`<name>-dark@2x.webp` at 1024 px, and `manifest.json`: per sprite the anchor
(where the object stands on the floor, as a fraction of the image) and the
width of the image in metres, so the page can draw every object at one scale.
"""
from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
OUT = os.path.join(ROOT, "crates", "varsto-cli", "ui", "viz")
GRID = 256            # grid px = cm; the image spans GRID / zoom cm
AX, AY = 128, 176     # where the object's floor point lands in the grid

try:
    import bpy  # noqa: F401
    sys.path.insert(0, HERE)
    import scene_kit as K
except ImportError:  # converting with plain python3
    K = None


def nas_state(led):
    root = K.empty("nas")
    K.box(0.8, 0.62, 0.52, K.mat("paper"), bevel=0.03, parent=root)
    for z in (0.33, 0.10):
        K.box(0.6, 0.03, 0.13, K.mat("light"), bevel=0.012, at=(0, -0.31, z), parent=root, name="bay")
        K.box(0.2, 0.012, 0.025, K.mat("grey"), bevel=0.006, at=(-0.14, -0.342, z + 0.05), parent=root, name="handle")
        K.cyl(0.025, 0.012, K.mat(led, emission=1.5, rough=0.3), parent=root, at=(0.22, -0.335, z + 0.065), axis="Y")
    return root


def dock_bay(led=None, disk=False):
    """Docking bay for bare SATA drives: a base, two walls and two end caps around an open-top slot, a
    status LED and a power button on the front. With `disk` a 3.5-inch drive stands in the slot, about
    a third of it inserted, its label facing the front; `led` is the colour of both LEDs (None: off)."""
    root = K.empty("dock")
    wall = K.mat("paper")
    K.box(0.80, 0.46, 0.05, K.mat("slate"), bevel=0.02, parent=root, name="base")
    K.box(0.76, 0.14, 0.14, wall, bevel=0.018, at=(0, -0.14, 0.05), parent=root, name="front")
    K.box(0.76, 0.14, 0.22, wall, bevel=0.018, at=(0, 0.14, 0.05), parent=root, name="back")
    for sx in (-0.34, 0.34):
        K.box(0.08, 0.16, 0.14, wall, bevel=0.015, at=(sx, 0, 0.05), parent=root, name="cap")
    K.box(0.60, 0.15, 0.012, K.mat("dark"), bevel=0.004, at=(0, 0, 0.05), parent=root, name="floor")
    K.box(0.36, 0.045, 0.02, K.mat("slate"), bevel=0.004, at=(0, 0, 0.062), parent=root, name="connector")
    # Front: power button (ring and mark) and status LED.
    K.cyl(0.04, 0.012, K.mat("mid", rough=0.4), parent=root, at=(-0.30, -0.222, 0.12), axis="Y", name="button")
    K.cyl(0.018, 0.014, K.mat("glyph", rough=0.4), parent=root, at=(-0.30, -0.224, 0.12), axis="Y", name="buttonmark")
    K.cyl(0.024, 0.012, K.mat(led or "mid", emission=1.6 if led else 0.0, rough=0.3), parent=root,
          at=(0.30, -0.222, 0.12), axis="Y", name="led")
    if disk:
        K.box(0.52, 0.115, 0.80, K.mat("paper"), bevel=0.02, at=(0, 0, 0.09), parent=root, name="drive")
        K.box(0.40, 0.01, 0.40, K.mat("light"), bevel=0.004, at=(0, -0.0575, 0.42), parent=root, name="label")
        K.cyl(0.15, 0.008, K.mat("grey"), parent=root, at=(0, -0.0675, 0.58), axis="Y", name="platter")
        K.cyl(0.13, 0.01, K.mat("light"), parent=root, at=(0, -0.0695, 0.58), axis="Y", name="platter2")
        K.cyl(0.05, 0.014, K.mat("paper"), parent=root, at=(0, -0.0715, 0.58), axis="Y", name="hub")
        K.box(0.22, 0.01, 0.03, K.mat("grey"), bevel=0.004, at=(0, -0.0625, 0.37), parent=root, name="line")
        K.cyl(0.028, 0.012, K.mat(led or "mid", emission=1.6 if led else 0.0, rough=0.3), parent=root,
              at=(0.19, -0.0695, 0.83), axis="Y", name="driveled")
    return root


def coins():
    root = K.empty("coins")
    g = K.gold()
    for i, (dx, dy, n) in enumerate([(0, 0, 5), (0.34, 0.08, 3), (-0.3, 0.12, 2)]):
        for k in range(n):
            K.cyl(0.14, 0.035, g, bevel=0.008, parent=root, at=(dx + 0.01 * (k % 2), dy, k * 0.037))
    return root


# name -> (builder, zoom, lift)
def sprites():
    return {
        "laptop": (lambda: K.laptop("lines"), 1.35, 0.0),
        "phone": (lambda: K.phone("rows"), 2.4, 0.0),
        "tablet": (lambda: K.tablet(), 1.9, 0.0),
        "monitor": (lambda: K.monitor("lines"), 1.4, 0.0),
        "nas": (lambda: nas_state("green"), 1.7, 0.0),
        "nas-warn": (lambda: nas_state("gold"), 1.7, 0.0),
        "shelf": (lambda: K.shelf(), 1.25, 0.0),
        "dock": (lambda: dock_bay(), 2.1, 0.0),
        "dock-disk": (lambda: dock_bay("green", True), 2.1, 0.0),
        "dock-disk-busy": (lambda: dock_bay("gold", True), 2.1, 0.0),
        "dock-disk-bad": (lambda: dock_bay("red", True), 2.1, 0.0),
        "usb": (lambda: K.usb_stick(), 3.0, 0.0),
        "cloud": (lambda: K.cloud(), 1.7, 0.25),
        "bucket": (lambda: K.bucket(), 2.0, 0.0),
        "archive": (lambda: K.archive(), 1.8, 0.0),
        "lock": (lambda: K.padlock(), 3.2, 0.0),
        "coins": (lambda: coins(), 3.6, 0.0),
    }


def pick_device(wanted):
    if wanted != "AUTO":
        return wanted
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=memory.free", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=10).stdout.strip().splitlines()
        free = int(out[0]) if out else 0
    except Exception:
        free = 0
    if free >= 2500:
        return "OPTIX"
    print(f"GPU has only {free} MiB free: rendering on the CPU")
    return "CPU"


def render_one(name, theme, builder, zoom, lift, samples, device, raw):
    K.new_scene(GRID, GRID, scale=4, samples=samples, gpu=device, theme=theme)
    sc = bpy.context.scene
    sc.render.film_transparent = True
    sc.render.image_settings.color_mode = "RGBA"
    for ob in bpy.data.objects:
        if ob.name.startswith("floor"):
            ob.is_shadow_catcher = True
    root = builder()
    root.scale = tuple(s * zoom for s in root.scale)
    K.place(root, AX, AY, 0.0, 0.0, lift * zoom)
    K.render(raw)


def fade_edges(im, margin=0.14):
    """The shadow catcher's shadow is cut by the image border. Fade the translucent
    pixels (the shadow; the object itself is opaque) to nothing towards the border."""
    from PIL import Image
    import numpy as np
    a = np.asarray(im).astype("float32")
    h, w = a.shape[:2]
    ys, xs = np.mgrid[0:h, 0:w].astype("float32")
    d = np.minimum(np.minimum(xs, w - 1 - xs), np.minimum(ys, h - 1 - ys)) / (margin * min(h, w))
    t = np.clip(d, 0.0, 1.0)
    fade = t * t * (3 - 2 * t)
    alpha = a[..., 3] / 255.0
    # Opaque pixels keep their alpha; the more translucent, the more the fade applies.
    keep = np.clip((alpha - 0.85) / 0.15, 0.0, 1.0)
    a[..., 3] = 255.0 * alpha * (keep + (1 - keep) * fade)
    return Image.fromarray(a.clip(0, 255).astype("uint8"), "RGBA")


def convert(work, out, names, themes):
    from PIL import Image
    os.makedirs(out, exist_ok=True)
    total = 0
    for name in names:
        for theme in themes:
            suf = "" if theme == "light" else "-dark"
            raw = os.path.join(work, f"{name}{suf}.png")
            if not os.path.exists(raw):
                continue
            im = fade_edges(Image.open(raw).convert("RGBA"))
            for tag, size, q in (("@2x", 1024, 80), ("", 512, 84)):
                r = im.resize((size, size), Image.LANCZOS) if im.size[0] != size else im
                p = os.path.join(out, f"{name}{suf}{tag}.webp")
                r.save(p, "WEBP", quality=q, method=6, exact=True)
                total += os.path.getsize(p)
    print(f"sprites: {total // 1024} KB in {out}")


def main():
    argv = sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else sys.argv[1:]
    o = {"only": None, "samples": 96, "device": "AUTO", "work": os.path.join(tempfile.gettempdir(), "varsto-viz"),
         "out": OUT, "themes": ["light", "dark"], "convert_only": False}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--only":
            o["only"] = argv[i + 1].split(","); i += 2
        elif a == "--samples":
            o["samples"] = int(argv[i + 1]); i += 2
        elif a == "--device":
            o["device"] = argv[i + 1].upper(); i += 2
        elif a == "--work":
            o["work"] = argv[i + 1]; i += 2
        elif a == "--out":
            o["out"] = os.path.abspath(argv[i + 1]); i += 2
        elif a == "--theme":
            o["themes"] = ["light", "dark"] if argv[i + 1] == "both" else [argv[i + 1]]; i += 2
        elif a == "--convert-only":
            o["convert_only"] = True; i += 1
        else:
            raise SystemExit(f"unknown option {a}")
    os.makedirs(o["work"], exist_ok=True)
    if K is None:
        names = o["only"] or [n for n in ALL_NAMES]
        convert(o["work"], o["out"], names, o["themes"])
        return
    table = sprites()
    names = o["only"] or list(table)
    if not o["convert_only"]:
        device = pick_device(o["device"])
        for name in names:
            builder, zoom, lift = table[name]
            for theme in o["themes"]:
                suf = "" if theme == "light" else "-dark"
                render_one(name, theme, builder, zoom, lift, o["samples"], device,
                           os.path.join(o["work"], f"{name}{suf}.png"))
                print("rendered", name + suf, flush=True)
    manifest = {n: {"ax": AX / GRID, "ay": AY / GRID, "span_m": round(GRID / table[n][1] / 100, 4)} for n in table}
    os.makedirs(o["out"], exist_ok=True)
    with open(os.path.join(o["out"], "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1)
    subprocess.run(["python3", os.path.abspath(__file__), "--work", o["work"], "--out", o["out"],
                    "--only", ",".join(names), "--theme", "both" if len(o["themes"]) == 2 else o["themes"][0],
                    "--convert-only"], check=True)


ALL_NAMES = ["laptop", "phone", "tablet", "monitor", "nas", "nas-warn", "shelf", "dock", "dock-disk", "dock-disk-busy", "dock-disk-bad", "usb", "cloud", "bucket", "archive", "lock", "coins"]

if __name__ == "__main__":
    main()
