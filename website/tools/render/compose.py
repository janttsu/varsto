#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Compose the text layer over a rendered scene and write WebP + PNG, and check
the layout for overlapping elements.

    python3 compose.py <render.png> <layout.json> <out-base>   compose (and check)
    python3 compose.py --check <layout.json>                   check only

Writes <out-base>.webp (lossy, quality 88) and <out-base>.png. The layout JSON
comes from render_all.py (scene_kit.layout()): grid size, queued text items and
the projected boxes of every element (kind object, card, ui, badge). Text is
drawn with Inter (OFL) at 2x: node titles 28 px semi-bold, sub-labels 24 px
regular muted, one caption line centred at the bottom.

Overlap rules (all boxes in screen space, text boxes measured with the real font):
- two objects, cards, texts or UI pieces must not intersect;
- a badge attached to a parent may touch the parent only on its silhouette edge:
  the badge centre must lie outside the parent box (or on it); a badge must not
  touch anything else;
- a UI piece on a card may overlap that card (and a nested card its parent card);
- a text may lie on a card only when it is fully inside the card; a text marked
  free (letters on disks, seal initials) may lie on its element.
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


def intersects(a, b, pad=0.0):
    return not (a[2] + pad <= b[0] or b[2] + pad <= a[0] or a[3] + pad <= b[1] or b[3] + pad <= a[1])


def inside(a, b, tol=0.5):
    return a[0] >= b[0] - tol and a[1] >= b[1] - tol and a[2] <= b[2] + tol and a[3] <= b[3] + tol


def styles_for(lay):
    return dict(STYLES, **(HERO_STYLES if lay["w"] > 640 else {}))


def text_boxes(lay):
    """Screen boxes (grid px) of every text and pill item, measured with the real font."""
    styles = styles_for(lay)
    probe = ImageDraw.Draw(Image.new("RGB", (8, 8)))
    out = []
    for i, it in enumerate(lay["texts"]):
        if it["type"] == "text":
            f, size, _ = styles[it["style"]]
            tb = probe.textbbox((it["x"] * SCALE, it["y"] * SCALE), it["text"], font=font(f, size), anchor=ANCHORS[it["anchor"]])
            out.append({"name": f"text:{it['text'][:28]}", "box": tuple(v / SCALE for v in tb), "free": bool(it.get("free"))})
        elif it["type"] == "pill":
            out.append({"name": f"pill:{it['text']}", "box": (it["x"], it["y"], it["x"] + it["w"], it["y"] + it["h"]), "free": False})
    return out


def check(lay) -> list[str]:
    """All unintended overlaps in a layout, as human-readable lines."""
    W, H = lay["w"], lay["h"]
    els = [{"name": n, "box": tuple(v["box"]), "kind": v["kind"], "parent": v.get("parent")} for n, v in lay["boxes"].items()]
    texts = text_boxes(lay)
    problems = []

    def is_ancestor(parent_name, el):
        p = el.get("parent")
        seen = 0
        while p and seen < 5:
            if p == parent_name:
                return True
            p = lay["boxes"].get(p, {}).get("parent")
            seen += 1
        return False

    for el in els + texts:
        b = el["box"]
        if b[0] < 2 or b[1] < 2 or b[2] > W - 2 or b[3] > H - 2:
            problems.append(f"outside frame: {el['name']} {tuple(round(v) for v in b)}")
    for i, a in enumerate(els):
        for b in els[i + 1:]:
            if not intersects(a["box"], b["box"]):
                continue
            ka, kb = a["kind"], b["kind"]
            verdict = None
            for x, y in ((a, b), (b, a)):
                if x["kind"] == "badge" and y["name"] == x["parent"]:
                    cx, cy = (x["box"][0] + x["box"][2]) / 2, (x["box"][1] + x["box"][3]) / 2
                    on_face = y["box"][0] + 2 < cx < y["box"][2] - 2 and y["box"][1] + 2 < cy < y["box"][3] - 2
                    verdict = f"badge over face: {x['name']} on {y['name']}" if on_face else ""
                    break
                if x["kind"] in ("ui", "card") and y["kind"] in ("card", "ui") and is_ancestor(y["name"], x):
                    verdict = ""
                    break
            if verdict is None:
                verdict = f"overlap: {a['name']} ({ka}) x {b['name']} ({kb})"
            if verdict:
                problems.append(verdict)
    for i, t in enumerate(texts):
        for u in texts[i + 1:]:
            if intersects(t["box"], u["box"]):
                problems.append(f"overlap: {t['name']} x {u['name']}")
        for el in els:
            if not intersects(t["box"], el["box"]):
                continue
            if el["kind"] == "card" and inside(t["box"], el["box"]):
                continue
            if t["free"]:
                continue
            problems.append(f"overlap: {t['name']} x {el['name']} ({el['kind']})")
    return problems


def compose(render_png: str, layout_json: str, out_base: str) -> list[str]:
    lay = json.load(open(layout_json))
    im = Image.open(render_png).convert("RGBA")
    W, H = lay["w"] * SCALE, lay["h"] * SCALE
    if im.size != (W, H):
        im = im.resize((W, H), Image.LANCZOS)
    layer = Image.new("RGBA", im.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    styles = styles_for(lay)
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
            d.text((it["x"] * SCALE, it["y"] * SCALE), it["text"], font=font(f, size), fill=hex_rgba(col), anchor=ANCHORS[it["anchor"]])
    out = Image.alpha_composite(im, layer).convert("RGB")
    os.makedirs(os.path.dirname(out_base), exist_ok=True)
    out.save(out_base + ".png", optimize=True, compress_level=9)
    out.save(out_base + ".webp", quality=88, method=6)
    return check(lay)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        problems = check(json.load(open(sys.argv[2])))
    elif len(sys.argv) == 4:
        problems = compose(*sys.argv[1:4])
    else:
        print(__doc__)
        sys.exit(2)
    for w in problems:
        print("warning:", w)
    print(f"{len(problems)} overlap problem(s)")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
