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
import math
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
# Dark theme: the same fonts with the site's dark text colours (text #eceef2, muted
# #9aa3b2, accent #8aa9ff). Explicit colours of single items are mapped by DARK_COLOURS.
DARK_TEXT = {"#334155": "#e3e7ee", "#6b7a90": "#9aa3b2", "#1f8f57": "#6fd39b", "#2b57d6": "#8aa9ff",
             "#1b3a9a": "#aac0ff", "#ffffff": "#ffffff"}
DARK_STYLE_COLOURS = {"row": "#d3d8e1", "letter": "#e3e9ff"}
DARK_COLOURS = {"#c2414a": "#ff8f95", "#1f8f57": "#6fd39b", "#e8edf7": "#2e3644", "#e2e8f0": "#2e3644"}
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


# ---------------------------------------------------------------- geometry (grid px, convex polygons)
def rect_poly(b):
    return [(b[0], b[1]), (b[2], b[1]), (b[2], b[3]), (b[0], b[3])]


def _seg_dist(p, q, a, b):
    """Distance between segments pq and ab."""
    def pt_seg(c, u, v):
        dx, dy = v[0] - u[0], v[1] - u[1]
        L = dx * dx + dy * dy
        t = 0.0 if L == 0 else max(0.0, min(1.0, ((c[0] - u[0]) * dx + (c[1] - u[1]) * dy) / L))
        return math.hypot(c[0] - u[0] - t * dx, c[1] - u[1] - t * dy)

    def orient(u, v, w):
        return (v[0] - u[0]) * (w[1] - u[1]) - (v[1] - u[1]) * (w[0] - u[0])
    o1, o2, o3, o4 = orient(p, q, a), orient(p, q, b), orient(a, b, p), orient(a, b, q)
    if (o1 > 0) != (o2 > 0) and (o3 > 0) != (o4 > 0) and o1 * o2 < 0 and o3 * o4 < 0:
        return 0.0
    return min(pt_seg(p, a, b), pt_seg(q, a, b), pt_seg(a, p, q), pt_seg(b, p, q))


def _point_in(pt, poly):
    """Point inside a convex polygon (either winding)."""
    sign = 0
    n = len(poly)
    if n < 3:
        return False
    for i in range(n):
        u, v = poly[i], poly[(i + 1) % n]
        c = (v[0] - u[0]) * (pt[1] - u[1]) - (v[1] - u[1]) * (pt[0] - u[0])
        if c != 0:
            if sign == 0:
                sign = 1 if c > 0 else -1
            elif (c > 0) != (sign > 0):
                return False
    return True


def _edges(poly):
    n = len(poly)
    return [(poly[i], poly[(i + 1) % n]) for i in range(n)] if n > 1 else [(poly[0], poly[0])]


def poly_dist(A, B):
    """Distance between two convex polygons (0 when they overlap)."""
    if any(_point_in(p, B) for p in A) or any(_point_in(p, A) for p in B):
        return 0.0
    return min(_seg_dist(p, q, a, b) for p, q in _edges(A) for a, b in _edges(B))


def line_dist(line, B):
    """Distance between an open polyline and a convex polygon."""
    if any(_point_in(p, B) for p in line):
        return 0.0
    return min(_seg_dist(p, q, a, b) for p, q in zip(line, line[1:]) for a, b in _edges(B))


def _area(P):
    return abs(sum(P[i][0] * P[(i + 1) % len(P)][1] - P[(i + 1) % len(P)][0] * P[i][1] for i in range(len(P)))) / 2 if len(P) > 2 else 0.0


def overlap_area(A, B):
    """Area of the intersection of two convex polygons (Sutherland-Hodgman)."""
    def ccw(P):
        s = sum(P[i][0] * P[(i + 1) % len(P)][1] - P[(i + 1) % len(P)][0] * P[i][1] for i in range(len(P)))
        return P if s > 0 else P[::-1]
    if len(A) < 3 or len(B) < 3:
        return 0.0
    out = ccw(list(A))
    for a, b in _edges(ccw(list(B))):
        inp, out = out, []
        if not inp:
            break

        def side(p):
            return (b[0] - a[0]) * (p[1] - a[1]) - (b[1] - a[1]) * (p[0] - a[0])

        def cut(p, q):
            sp, sq = side(p), side(q)
            t = sp / (sp - sq)
            return (p[0] + t * (q[0] - p[0]), p[1] + t * (q[1] - p[1]))
        for i, p in enumerate(inp):
            q = inp[(i + 1) % len(inp)]
            if side(q) >= 0:
                if side(p) < 0:
                    out.append(cut(p, q))
                out.append(q)
            elif side(p) >= 0:
                out.append(cut(p, q))
    return _area(out)


def styles_for(lay):
    st = dict(STYLES, **(HERO_STYLES if lay["w"] > 640 else {}))
    if lay.get("theme") == "dark":
        st = {k: (f, size, DARK_STYLE_COLOURS.get(k) or DARK_TEXT.get(c, c)) for k, (f, size, c) in st.items()}
    return st


def colour(lay, c):
    """An explicit item colour for the layout's theme."""
    return DARK_COLOURS.get(c.lower(), c) if lay.get("theme") == "dark" else c


def text_boxes(lay):
    """Screen boxes (grid px) of every text and pill item, measured with the real font."""
    styles = styles_for(lay)
    probe = ImageDraw.Draw(Image.new("RGB", (8, 8)))
    out = []
    for i, it in enumerate(lay["texts"]):
        if it["type"] == "text" and it["text"].strip():
            f, size, _ = styles[it["style"]]
            tb = probe.textbbox((it["x"] * SCALE, it["y"] * SCALE), it["text"], font=font(f, size), anchor=ANCHORS[it["anchor"]])
            out.append({"name": f"text:{it['text'][:28]}", "box": tuple(v / SCALE for v in tb), "free": bool(it.get("free"))})
        elif it["type"] == "pill":
            out.append({"name": f"pill:{it['text']}", "box": (it["x"], it["y"], it["x"] + it["w"], it["y"] + it["h"]), "free": False})
    return out


# Clearances in grid px (1 grid px = 2 output px).
TEXT_GAP = 6        # text to any object, UI piece, badge, card edge or link
TEXT_TEXT_GAP = 4   # text to text
OBJ_GAP = 4         # element to element (hull to hull)
CARD_INSET = 6      # UI pieces and texts on a card keep this far from its edge
LINK_CARD_GAP = 4   # a link stops this far from a card it does not run on
FRAME_TEXT = 6      # texts keep this far from the picture edge
FRAME_OBJ = 2       # elements stay inside the picture
LINK_OBJ_GAP = 3    # a link (and its arrow head) stays clear of badges and UI pieces (links start and
                    # end at objects by design, and an object's hull is coarse, so objects are not checked)
BADGE_COVER = {"card": 0.30, "object": 0.02}   # max share of a badge lying over its parent


def check(lay) -> list[str]:
    """All unintended overlaps in a layout, as human-readable lines."""
    W, H = lay["w"], lay["h"]
    els, links = [], []
    for n, v in lay["boxes"].items():
        e = {"name": n, "box": tuple(v["box"]), "kind": v["kind"], "parent": v.get("parent"), "free": bool(v.get("free"))}
        if v["kind"] == "link":
            e["poly"], e["r"], e["heads"], e["head_r"] = v["poly"], v["r"], v.get("heads", []), v.get("head_r", 0)
            links.append(e)
            continue
        e["hull"] = [tuple(p) for p in v.get("hull") or rect_poly(e["box"])]
        if e["kind"] == "card":
            e["hull"] = rect_poly(e["box"])
        els.append(e)
    by_name = {e["name"]: e for e in els}
    texts = text_boxes(lay)
    for t in texts:
        t["hull"] = rect_poly(t["box"])
    problems = []

    def ancestors(el):
        out, p = [], el.get("parent")
        while p and len(out) < 6:
            out.append(p)
            p = lay["boxes"].get(p, {}).get("parent")
        return out

    def r(b):
        return tuple(round(v) for v in b)

    # 1. frame
    for el in els:
        b = el["box"]
        if b[0] < FRAME_OBJ or b[1] < FRAME_OBJ or b[2] > W - FRAME_OBJ or b[3] > H - FRAME_OBJ:
            problems.append(f"outside frame: {el['name']} {r(b)}")
    for t in texts:
        b = t["box"]
        if b[0] < FRAME_TEXT or b[1] < FRAME_TEXT or b[2] > W - FRAME_TEXT or b[3] > H - FRAME_TEXT:
            problems.append(f"text at/over the frame edge: {t['name']} {r(b)}")

    # 2. elements against elements
    for i, a in enumerate(els):
        for b in els[i + 1:]:
            if a["free"] or b["free"]:
                continue
            pair = None
            for x, y in ((a, b), (b, a)):
                if x["kind"] == "badge" and y["name"] == x["parent"]:
                    pair = ("badge", x, y)
                    break
                if y["name"] in ancestors(x) and x["kind"] in ("ui", "card") and y["kind"] in ("card", "ui"):
                    pair = ("on", x, y)
                    break
            if pair and pair[0] == "badge":
                x, y = pair[1], pair[2]
                cover = overlap_area(x["hull"], y["hull"]) / max(_area(x["hull"]), 1e-6)
                limit = BADGE_COVER["card" if y["kind"] == "card" else "object"]
                if cover > limit:
                    problems.append(f"badge covers its parent: {x['name']} over {y['name']} ({cover:.0%} > {limit:.0%})")
                continue
            if pair and pair[0] == "on":
                x, y = pair[1], pair[2]
                inner = (y["box"][0] + CARD_INSET, y["box"][1] + CARD_INSET, y["box"][2] - CARD_INSET, y["box"][3] - CARD_INSET)
                if y["kind"] == "card" and not inside(x["box"], inner):
                    problems.append(f"sticks out of its card: {x['name']} {r(x['box'])} on {y['name']} {r(y['box'])}")
                continue
            d = poly_dist(a["hull"], b["hull"])
            if d < OBJ_GAP:
                what = "overlap" if d == 0 else f"touching ({d:.1f} px)"
                problems.append(f"{what}: {a['name']} ({a['kind']}) x {b['name']} ({b['kind']})")

    # 3. texts against texts and elements
    for i, t in enumerate(texts):
        for u in texts[i + 1:]:
            if intersects(t["box"], u["box"], TEXT_TEXT_GAP):
                problems.append(f"text too close to text: {t['name']} x {u['name']}")
        for el in els:
            if t["free"] or not intersects(t["box"], el["box"], TEXT_GAP):
                continue
            if el["kind"] == "card" and inside(t["box"], el["box"]):
                inner = (el["box"][0] + CARD_INSET, el["box"][1] + CARD_INSET, el["box"][2] - CARD_INSET, el["box"][3] - CARD_INSET)
                if not inside(t["box"], inner):
                    problems.append(f"text too close to its card edge: {t['name']} on {el['name']}")
                continue
            if el["kind"] == "card" and any(inside(t["box"], by_name[c]["box"]) for c in by_name if by_name[c]["kind"] == "card"
                                            and el["name"] in ancestors(by_name[c])):
                continue  # text on a nested card that lies on this card
            d = poly_dist(t["hull"], el["hull"])
            if d < TEXT_GAP:
                what = "overlap" if d == 0 else f"too close ({d:.1f} px)"
                problems.append(f"{what}: {t['name']} x {el['name']} ({el['kind']})")

    # 4. links against texts and cards
    for ln in links:
        for t in texts:
            if not intersects(t["box"], ln["box"], TEXT_GAP + ln["head_r"]):
                continue
            d = line_dist(ln["poly"], t["hull"]) - ln["r"]
            dh = min([poly_dist([tuple(h)], t["hull"]) - ln["head_r"] for h in ln["heads"]] or [99])
            if min(d, dh) < TEXT_GAP:
                problems.append(f"link too close to text: {ln['name']} x {t['name']} ({max(min(d, dh), 0):.1f} px)")
        for el in els:
            if el["kind"] in ("badge", "ui") and not el["free"] and intersects(el["box"], ln["box"], LINK_OBJ_GAP + ln["head_r"]):
                d = line_dist(ln["poly"], el["hull"]) - ln["r"]
                dh = min([poly_dist([tuple(h)], el["hull"]) - ln["head_r"] for h in ln["heads"]] or [99])
                if min(d, dh) < LINK_OBJ_GAP:
                    problems.append(f"link touches {el['kind']}: {ln['name']} x {el['name']} ({max(min(d, dh), 0):.1f} px)")
            if el["kind"] != "card" or not intersects(el["box"], ln["box"], LINK_CARD_GAP + ln["head_r"]):
                continue
            if all(_point_in(p, el["hull"]) for p in ln["poly"]):
                continue  # runs on the card
            edge = _edges(el["hull"])
            d = min(_seg_dist(p, q, a, b) for p, q in zip(ln["poly"], ln["poly"][1:]) for a, b in edge) - ln["r"]
            dh = min([min(_seg_dist(tuple(h), tuple(h), a, b) for a, b in edge) - ln["head_r"] for h in ln["heads"]] or [99])
            if min(d, dh) < LINK_CARD_GAP:
                problems.append(f"link touches a card: {ln['name']} x {el['name']} ({max(min(d, dh), 0):.1f} px)")
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
                   fill=hex_rgba(colour(lay, it["color"])), width=max(1, round(it["width"] * SCALE)))
        elif it["type"] == "pill":
            x, y, w, h = (it[k] * SCALE for k in ("x", "y", "w", "h"))
            d.rounded_rectangle([x, y, x + w, y + h], radius=h / 2, fill=hex_rgba(it["fill"], it.get("alpha", 255)))
            f, size, _ = styles[it["style"]]
            d.text((x + w / 2, y + h / 2), it["text"], font=font(f, size), fill=hex_rgba(colour(lay, it["color"])), anchor="mm")
        elif it["type"] == "text":
            f, size, col = styles[it["style"]]
            if it.get("color"):
                col = colour(lay, it["color"])
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
