#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Compose the text layer over a rendered scene and write WebP + PNG.

    python3 compose.py <render.png> <layout.json> <out-base>

Writes <out-base>.webp (lossy, quality 88) and <out-base>.png. The layout JSON
comes from render_all.py (scene_kit.layout()): grid size, queued text items and
the projected bounding boxes of the objects. Text is drawn with Inter (OFL) at
2x: node titles 28 px semi-bold, sub-labels 24 px regular muted, one caption
line centred at the bottom. Any text that would overlap an object is reported.
"""
from __future__ import annotations

import json
import os
import sys

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
FONTS = os.path.join(HERE, "fonts")

STYLES = {  # name: (font file, size at 2x, colour)
    "title": ("Inter-SemiBold.ttf", 28, "#334155"),
    "sub": ("Inter-Regular.ttf", 24, "#6b7a90"),
    "caption": ("Inter-Regular.ttf", 24, "#6b7a90"),
    "row": ("Inter-Regular.ttf", 24, "#334155"),
    "white": ("Inter-SemiBold.ttf", 26, "#ffffff"),
    "small": ("Inter-SemiBold.ttf", 22, "#1f8f57"),
    "accent": ("Inter-SemiBold.ttf", 26, "#2b57d6"),
    "sealtxt": ("Inter-SemiBold.ttf", 20, "#ffffff"),
    "sealname": ("Inter-SemiBold.ttf", 24, "#1b3a9a"),
    "letter": ("Inter-SemiBold.ttf", 22, "#2b57d6"),
    "hero_title": ("Inter-SemiBold.ttf", 48, "#1b3a9a"),
    "hero_sub": ("Inter-Regular.ttf", 30, "#6b7a90"),
}
HERO_STYLES = {"title": ("Inter-SemiBold.ttf", 32, "#334155"), "sub": ("Inter-Regular.ttf", 26, "#6b7a90")}
ANCHORS = {"m": "ms", "s": "ls", "e": "rs"}
SCALE = 2
_fonts: dict = {}


def font(file: str, size: int):
    key = (file, size)
    if key not in _fonts:
        _fonts[key] = ImageFont.truetype(os.path.join(FONTS, file), size)
    return _fonts[key]


def hex_rgba(h: str, alpha: int = 255):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4)) + (alpha,)


def overlaps(a, b, pad=2):
    return not (a[2] + pad < b[0] or b[2] + pad < a[0] or a[3] + pad < b[1] or b[3] + pad < a[1])


def compose(render_png: str, layout_json: str, out_base: str) -> list[str]:
    lay = json.load(open(layout_json))
    im = Image.open(render_png).convert("RGBA")
    W, H = lay["w"] * SCALE, lay["h"] * SCALE
    if im.size != (W, H):
        im = im.resize((W, H), Image.LANCZOS)
    layer = Image.new("RGBA", im.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    hero = lay["w"] > 640
    styles = dict(STYLES, **(HERO_STYLES if hero else {}))
    warnings = []
    obj_boxes = {k: tuple(v * SCALE for v in b) for k, b in lay["boxes"].items() if not k.startswith(("card:", "ui:"))}

    for it in lay["texts"]:
        if it["type"] == "rule":
            d.line([(it["x0"] * SCALE, it["y0"] * SCALE), (it["x1"] * SCALE, it["y1"] * SCALE)],
                   fill=hex_rgba(it["color"]), width=max(1, round(it["width"] * SCALE)))
        elif it["type"] == "pill":
            x, y, w, h = (it[k] * SCALE for k in ("x", "y", "w", "h"))
            d.rounded_rectangle([x, y, x + w, y + h], radius=h / 2, fill=hex_rgba(it["fill"], it.get("alpha", 255)))
            f, size, _ = styles[it["style"]]
            d.text((x + w / 2, y + h / 2), it["text"], font=font(f, size), fill=hex_rgba(it["color"]), anchor="mm")
        elif it["type"] == "text":
            f, size, col = styles[it["style"]]
            if it.get("color"):
                col = it["color"]
            fnt = font(f, size)
            pos = (it["x"] * SCALE, it["y"] * SCALE)
            anchor = ANCHORS[it["anchor"]]
            d.text(pos, it["text"], font=fnt, fill=hex_rgba(col), anchor=anchor)
            tb = d.textbbox(pos, it["text"], font=fnt, anchor=anchor)
            if tb[0] < 4 or tb[2] > W - 4:
                warnings.append(f"text outside frame: {it['text']!r} {tb}")
            for name, ob in obj_boxes.items():
                if not it.get("free") and overlaps(tb, ob, pad=0):
                    warnings.append(f"text {it['text']!r} overlaps object {name}")
    out = Image.alpha_composite(im, layer).convert("RGB")
    os.makedirs(os.path.dirname(out_base), exist_ok=True)
    out.save(out_base + ".png", optimize=True, compress_level=9)
    out.save(out_base + ".webp", quality=88, method=6)
    return warnings


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(2)
    for w in compose(*sys.argv[1:4]):
        print("warning:", w)


if __name__ == "__main__":
    main()
