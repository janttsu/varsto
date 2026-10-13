#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Varsto logo fan items for 3D printing (Bambu Lab P1S + AMS), generated from brand/render.py.

    python3 generate.py                 # write every item into this directory
    python3 generate.py --out DIR       # write somewhere else
    python3 generate.py --tile vault    # tile in Vault blue (PLA Basic Blue) instead of Cobalt Blue
    python3 generate.py --only coaster  # one item (keychain, coaster, magnet, standee, badge)

Every item is written as
    <item>.3mf               Bambu Studio project: P1S 0.4 nozzle, PLA Basic presets, AMS slots set
    stl/<item>-<colour>.stl  one STL per colour part, all in the same coordinates (other slicers)
and a preview PNG in previews/ (needs Pillow).

The glyph (ring arcs + keyhole) and the wordmark (Inter SemiBold, -0.03 em tracking) use the
exact construction from brand/render.py, not traced pixels. Colours are separate parts of one
object, so the slicer prints them as one piece with AMS colour changes.

Colour-change strategy: the white glyph and the black wordmark sit on top of the blue body, so
the blue layers come first and the light colours only appear in the top layers. Where an item
has both, the glyph stands on a thin black underlay that shares its layers with the black text:
blue -> black -> white is then only two filament changes for the whole print. The coaster is the
exception: it is printed face down with a flush inlay, so its first layers hold all three colours.

Requires: manifold3d, numpy, fonttools, uharfbuzz (kerning), Pillow (previews).
"""
from __future__ import annotations

import argparse
import json
import math
import struct
import sys
import uuid
import zipfile
from pathlib import Path

import numpy as np
from manifold3d import CrossSection, FillRule, JoinType, Manifold

HERE = Path(__file__).resolve().parent
BRAND = HERE.parent
ROOT = BRAND.parent
FONT = ROOT / "website" / "tools" / "render" / "fonts" / "Inter-SemiBold.ttf"
SETTINGS = HERE / "p1s-project-settings.json"

sys.path.insert(0, str(BRAND))
import render as brand  # noqa: E402  (the logo geometry: TIERS, GAP_ANGLES, GRID)

# ---------------------------------------------------------------- printer (Bambu Lab P1S)
BED = 256.0
EXCLUDE = (18.0, 28.0)   # Bambu Studio's no-print area at the front left corner
PURGE_Y = 5.0            # the start G-code's nozzle load line runs at plate Y 3.0..3.5
LAYER = 0.2              # 0.20 mm Standard; every height below is a multiple of it
SEG = 0.25               # chord length for arcs (mm)

# ---------------------------------------------------------------- filaments (AMS slots)
# Hex values from Bambu Studio 2.08 resources/profiles/BBL/filament/filaments_color_codes.json
FILAMENTS = {
    "cobalt": ("PLA Basic Cobalt Blue", "10604", "#0056B8"),
    "vault": ("PLA Basic Blue", "10601", "#0A2989"),
    "white": ("PLA Basic Jade White", "10100", "#FFFFFF"),
    "black": ("PLA Basic Black", "10101", "#000000"),
}
SLOT = {"blue": 1, "white": 2, "black": 3}
# Flush volume (mm³) when changing from row to column filament: blue, white, black.
# Dark to white needs the most; Bambu Studio's "Flushing volumes > Auto-calculate" may refine it.
FLUSH = [[0, 560, 160],
         [220, 0, 140],
         [320, 680, 0]]

PREVIEW_RGB = {"blue": None, "white": "#f4f4f1", "black": "#1a1a1a"}  # blue = chosen tile filament


# ---------------------------------------------------------------- 2D geometry
def _n(r: float, sweep_deg: float = 360.0) -> int:
    return max(12, int(math.ceil(abs(math.radians(sweep_deg)) * r / SEG)))


def circle(r: float, cx: float = 0.0, cy: float = 0.0) -> CrossSection:
    n = _n(r)
    t = np.linspace(0, 2 * math.pi, n, endpoint=False)
    return CrossSection([np.c_[cx + r * np.cos(t), cy + r * np.sin(t)]])


def rounded_rect(w: float, h: float, r: float) -> CrossSection:
    """Rectangle centred on the origin with corner radius r."""
    pts = []
    ax, ay = w / 2 - r, h / 2 - r
    for cx, cy, a0 in ((ax, -ay, -90), (ax, ay, 0), (-ax, ay, 90), (-ax, -ay, 180)):
        n = _n(r, 90)
        for i in range(n + 1):
            a = math.radians(a0 + 90 * i / n)
            pts.append((cx + r * math.cos(a), cy + r * math.sin(a)))
    return CrossSection([np.array(pts)])


def tile(size: float) -> CrossSection:
    """The logo tile: square with the brand corner radius (rx 57 on the 256 grid)."""
    return rounded_rect(size, size, brand.TIERS["large"]["rx"] * size / brand.GRID)


def glyph(size: float, cx: float = 0.0, cy: float = 0.0, tier: str = "large") -> CrossSection:
    """Ring arcs + keyhole for a tile of `size` mm centred at (cx, cy); y points up."""
    t = brand.TIERS[tier]
    s = size / brand.GRID

    def P(x: float, y: float) -> tuple[float, float]:   # SVG grid (y down, centre 128) -> mm
        return cx + (x - brand.C) * s, cy - (y - brand.C) * s

    C = brand.C
    R, W = t["R"], t["W"]
    h = W / 2
    g = math.degrees(math.asin((t["gap"] / 2 + h) / R))
    a, b = brand.GAP_ANGLES
    shapes = CrossSection()
    for a0, a1 in ((a + g, b - g), (b + g, a + 360 - g)):
        n = _n((R + h) * s, a1 - a0)
        ang = np.radians(np.linspace(a0, a1, n + 1))
        outer = [P(C + (R + h) * math.cos(q), C + (R + h) * math.sin(q)) for q in ang]
        inner = [P(C + (R - h) * math.cos(q), C + (R - h) * math.sin(q)) for q in ang[::-1]]
        poly = np.array(outer + inner)
        shapes += CrossSection([poly], FillRule.NonZero)
        for q in (ang[0], ang[-1]):                       # round caps
            ex, ey = P(C + R * math.cos(q), C + R * math.sin(q))
            shapes += circle(h * s, ex, ey)
    # keyhole: head + tapered stem with rounded bottom corners
    hx, hy = P(C, C - t["dot_dy"])
    shapes += circle(t["dot_r"] * s, hx, hy)
    ht, hb, rr = t["stem_top"], t["stem_bot"], t["stem_rr"]
    gy = C - t["dot_dy"]
    y1 = C + t["stem_end"]
    stem = [P(C - ht, gy), P(C + ht, gy)]
    for ccx, a0 in ((C + hb - rr, 0), (C - hb + rr, 90)):
        n = _n(rr * s, 90)
        for i in range(n + 1):
            q = math.radians(a0 + 90 * i / n)
            stem.append(P(ccx + rr * math.cos(q), y1 - rr + rr * math.sin(q)))
    shapes += CrossSection([np.array(stem)], FillRule.NonZero)
    return shapes


def ring_outer(size: float) -> float:
    t = brand.TIERS["large"]
    return (t["R"] + t["W"] / 2) * size / brand.GRID


class _FlattenPen:
    """fontTools pen that flattens outlines into polygons (font units, y up)."""

    def __init__(self, glyphset):
        from fontTools.pens.basePen import BasePen

        outer = self

        class Pen(BasePen):
            def _moveTo(self, p):
                outer.cur = [p]

            def _lineTo(self, p):
                outer.cur.append(p)

            def _curveToOne(self, p1, p2, p3):
                p0 = outer.cur[-1]
                for i in range(1, 9):
                    u = i / 8
                    outer.cur.append(tuple(
                        (1 - u) ** 3 * p0[k] + 3 * (1 - u) ** 2 * u * p1[k] + 3 * (1 - u) * u * u * p2[k] + u ** 3 * p3[k]
                        for k in (0, 1)))

            def _qCurveToOne(self, p1, p2):
                p0 = outer.cur[-1]
                for i in range(1, 7):
                    u = i / 6
                    outer.cur.append(tuple((1 - u) ** 2 * p0[k] + 2 * (1 - u) * u * p1[k] + u * u * p2[k] for k in (0, 1)))

            def _closePath(self):
                if len(outer.cur) > 2:
                    outer.contours.append(np.array(outer.cur, dtype=float))
                outer.cur = []

            _endPath = _closePath

        self.contours: list[np.ndarray] = []
        self.cur: list = []
        self.pen = Pen(glyphset)


def wordmark(text: str, cap: float, tracking_em: float = -0.03) -> tuple[CrossSection, float]:
    """Text in Inter SemiBold as outlines: baseline at y=0, left edge at x=0. Returns (shape, width)."""
    from fontTools.ttLib import TTFont

    font = TTFont(str(FONT))
    upem = font["head"].unitsPerEm
    k = cap / font["OS/2"].sCapHeight
    order = font.getGlyphOrder()
    gs = font.getGlyphSet()
    runs = []
    try:
        import uharfbuzz as hb

        face = hb.Face(hb.Blob.from_file_path(str(FONT)))
        hbfont = hb.Font(face)
        hbfont.scale = (upem, upem)
        buf = hb.Buffer()
        buf.add_str(text)
        buf.guess_segment_properties()
        hb.shape(hbfont, buf, {"kern": True, "liga": True, "calt": True})
        x = 0.0
        for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
            runs.append((order[info.codepoint], x + pos.x_offset, pos.y_offset))
            x += pos.x_advance + tracking_em * upem
    except ImportError:
        print("warning: uharfbuzz missing, wordmark set without kerning", file=sys.stderr)
        cmap, hmtx, x = font.getBestCmap(), font["hmtx"], 0.0
        for ch in text:
            runs.append((cmap[ord(ch)], x, 0.0))
            x += hmtx[cmap[ord(ch)]][0] + tracking_em * upem
    out = CrossSection()
    for name, gx, gy in runs:
        fp = _FlattenPen(gs)
        gs[name].draw(fp.pen)
        polys = [(c + (gx, gy)) * k for c in fp.contours]
        out += CrossSection(polys, FillRule.NonZero)
    lo = out.bounds()
    return out.translate((-lo[0], 0)), lo[2] - lo[0]


# ---------------------------------------------------------------- 3D helpers
def prism(cs: CrossSection, z0: float, z1: float) -> Manifold:
    return Manifold.extrude(cs, z1 - z0).translate([0, 0, z0])


def slab(cs: CrossSection, h: float, top: float = 0.0, bottom: float = 0.0) -> Manifold:
    """Convex outline extruded to h with 45° chamfers on the top and bottom edges."""
    eps = 0.01
    layers = []
    if bottom > 0:
        layers.append(prism(cs.offset(-bottom, JoinType.Round), 0, eps))
    layers.append(prism(cs, bottom, h - top))
    if top > 0:
        layers.append(prism(cs.offset(-top, JoinType.Round), h - eps, h))
    return Manifold.batch_hull(layers) if len(layers) > 1 else layers[0]


def snap(z: float) -> float:
    n = round(z / LAYER)
    assert abs(n * LAYER - z) < 1e-6, f"{z} is not a multiple of the {LAYER} mm layer height"
    return z


def raised(cs_glyph: CrossSection, cs_text: CrossSection | None, z: float,
           white_h: float = 1.0, black_h: float = 0.6, underlay_inset: float = 0.25) -> dict[str, Manifold]:
    """White glyph (and black text) standing on a top surface at z.

    Without text the glyph sits directly on the blue (one colour change). With text, the glyph
    stands on a black underlay that is printed in the same layers as the text, so the layer order
    is blue -> black -> white (two changes). The underlay is inset a little so the white top hides
    most of it; from the side it reads as a thin shadow line."""
    snap(z), snap(white_h), snap(black_h)
    if cs_text is None:
        return {"white": prism(cs_glyph, z, z + white_h)}
    under = cs_glyph.offset(-underlay_inset, JoinType.Round)
    return {
        "black": prism(cs_text, z, z + black_h) + prism(under, z, z + black_h),
        "white": prism(cs_glyph, z + black_h, z + black_h + white_h),
    }


# ---------------------------------------------------------------- items
# Each item returns plates: [ {name, objects: [ {name, parts: {colour: Manifold}, settings,
#   display: 4x4 transform from print pose to display pose (previews)} ], pause_z: [...] } ]

def keychain(text: bool) -> dict:
    """Tag with a reinforced ring lug at the top; with text the tag grows down to hold the wordmark."""
    T = 40.0                   # logo square
    body_h = 2.4 if text else 3.0
    lug_r, hole_r = 6.0, 2.5   # 3.5 mm solid ring around a 5 mm hole, full thickness
    if text:
        cap = 6.4
        words, ww = wordmark("Varsto", cap)
        assert ww <= T - 6, ww
        ring_bottom = -ring_outer(T)
        base_y = ring_bottom - 3.6 - cap        # 3.6 mm under the ring, then cap height
        bottom = base_y - 4.6
        top = T / 2
        h = top - bottom
        outline = rounded_rect(T, h, brand.TIERS["large"]["rx"] * T / brand.GRID).translate((0, (top + bottom) / 2))
        words = words.translate((-ww / 2, base_y))
    else:
        top = T / 2
        outline = tile(T)
        words = None
    lug_y = top + 2.0
    outline = CrossSection.batch_hull([outline, circle(lug_r, 0, lug_y)])
    body = slab(outline, body_h, top=0.4, bottom=0.2) - prism(circle(hole_r, 0, lug_y), -1, 10)
    # 0.4 mm chamfers on the hole edges so a split ring slides in
    n = _n(hole_r)
    body -= Manifold.cylinder(0.8, hole_r - 0.4, hole_r + 0.4, n).translate([0, lug_y, body_h - 0.4])
    body -= Manifold.cylinder(0.8, hole_r + 0.4, hole_r - 0.4, n).translate([0, lug_y, -0.4])
    parts = {"blue": body, **raised(glyph(T), words, body_h)}
    return {"plates": [{"name": "Keychain", "objects": [
        {"name": "Varsto keychain", "parts": parts, "settings": {"wall_loops": "3", "sparse_infill_density": "25%"}}]}]}


def coaster(text: bool, cork: bool = True) -> dict:
    """95 mm coaster with a flush inlay, printed face down (the textured plate becomes the top)."""
    S, H = 95.0, 5.0
    inlay_w, inlay_b = 0.8, 0.6          # white 4 layers, black 3 layers
    outline = tile(S)
    gsize = 76.0 if text else 80.0
    gy = 7.0 if text else 0.0
    gcs = glyph(gsize, 0, gy)
    body = slab(outline, H, top=1.0, bottom=0.6)        # display pose: top face at z = H
    parts = {}
    cut = prism(gcs, H - inlay_w, H + 1)
    parts["white"] = prism(gcs, H - inlay_w, H) ^ body
    if text:
        cap = 9.0
        words, ww = wordmark("Varsto", cap)
        words = words.translate((-ww / 2, gy - ring_outer(gsize) - 5.0 - cap))
        cut += prism(words, H - inlay_b, H + 1)
        parts["black"] = prism(words, H - inlay_b, H) ^ body
    body -= cut
    if cork:   # recess for a self-adhesive cork or felt sheet (cut to 83 x 83 mm, rounded corners)
        body -= prism(rounded_rect(S - 12, S - 12, 15.0), -1, 1.0)
    parts["blue"] = body
    flip = np.array([[1, 0, 0, 0], [0, -1, 0, 0], [0, 0, -1, H]], float)   # 180° about X: face down
    parts = {k: v.transform(flip) for k, v in parts.items()}
    return {"plates": [{"name": "Coaster (face down)", "objects": [
        {"name": "Varsto coaster", "parts": parts, "display": flip,
         "settings": {"top_shell_layers": "4", "sparse_infill_density": "15%"}}]}], "prime_tower": True}


MAGNET_D, MAGNET_H = 10.0, 2.0       # 10 x 2 mm round neodymium magnet
POCKET_D, POCKET_H = 10.3, 2.2
POCKET_FLOOR = 0.6


def magnet(text: bool) -> dict:
    """Fridge magnet with magnets embedded during a pause (see README)."""
    pocket_top = POCKET_FLOOR + POCKET_H                   # 2.8: pause before the layer above
    body_h = pocket_top + 0.8
    if text:
        # The tile is invisible on a blue magnet, so the ring (not the tile) is sized like the
        # lockup's mark: ring diameter D, then a 0.25 D gap and the wordmark at cap 0.48 D.
        D = 24.0
        cap = 0.48 * D
        words, ww = wordmark("Varsto", cap)
        margin = 6.0
        gap = 0.25 * D
        w = D + gap + ww + 2 * margin
        h = D + 2 * margin
        x0 = -w / 2 + margin
        gsize = D * brand.GRID / (2 * (brand.TIERS["large"]["R"] + brand.TIERS["large"]["W"] / 2))
        gcs = glyph(gsize, x0 + D / 2, 0)
        words = words.translate((x0 + D + gap, -cap / 2))
        outline = rounded_rect(w, h, 8.0)
        pockets = [(x0 + D / 2, 0.0), (x0 + D + gap + ww / 2, 0.0)]
    else:
        S = 50.0
        outline, gcs, words, pockets = tile(S), glyph(S), None, [(0.0, 0.0)]
    body = slab(outline, body_h, top=0.6, bottom=0.2)
    for px, py in pockets:
        body -= prism(circle(POCKET_D / 2, px, py), POCKET_FLOOR, pocket_top)
    parts = {"blue": body, **raised(gcs, words, body_h)}
    return {"plates": [{"name": "Fridge magnet", "pause_z": [pocket_top + LAYER], "objects": [
        {"name": "Varsto fridge magnet", "parts": parts, "settings": {"wall_loops": "3"}}]}],
        "magnets": len(pockets)}


def standee(text_colour: str) -> dict:
    """Logo tile with a tab (plate 1) that plugs into a base carrying the wordmark (plate 2)."""
    T, body_h = 60.0, 3.2
    tab_w, tab_h = 30.0, 7.0
    clear = 0.3
    tile_m = slab(tile(T), body_h, top=0.4, bottom=0.2) + prism(
        CrossSection.square([tab_w, tab_h + 2]).translate((-tab_w / 2, -T / 2 - tab_h)), 0, body_h)
    tile_parts = {"blue": tile_m, "white": prism(glyph(T), body_h, body_h + 1.0)}

    cap = 11.0
    words, ww = wordmark("Varsto", cap)
    L, D, H = max(T + 30, ww + 24), 42.0, 10.0
    base = slab(rounded_rect(L, D, 6.0), H, top=1.2, bottom=0.2)
    lean = 12.0                                    # tile leans back
    slot_depth = tab_h + 0.5
    slot = Manifold.cube([tab_w + 2 * clear, body_h + 2 * clear, 2 * slot_depth], center=True)
    slot = slot.rotate([-lean, 0, 0]).translate([0, 10.0, H])
    base -= slot
    words = words.translate((-ww / 2, -D / 2 + 4.5))
    base_parts = {"blue": base, text_colour: prism(words, H, H + 0.8)}
    # display pose for the preview: stand the tile in the slot
    a = math.radians(90 - lean)
    rot = np.array([[1, 0, 0], [0, math.cos(a), -math.sin(a)], [0, math.sin(a), math.cos(a)]])
    # the middle of the tile's bottom edge (print pose) lands on the slot mouth (base frame)
    stand = np.c_[rot, np.array([0, 10.0, H]) - rot @ np.array([0, -T / 2, body_h / 2])]
    return {"plates": [
        {"name": "Standee tile", "objects": [{"name": "Varsto standee tile", "parts": tile_parts,
                                              "display": stand, "settings": {"wall_loops": "3"}}]},
        {"name": "Standee base", "objects": [{"name": "Varsto standee base", "parts": base_parts,
                                              "settings": {}}]},
    ], "assemble": True}


def badge() -> dict:
    """30 mm badge blanks: one with a groove for a glue-on pin back, one with a magnet pocket."""
    T, body_h = 30.0, 3.0
    objs = []
    pin = slab(tile(T), body_h, top=0.4, bottom=0.2) - prism(
        rounded_rect(22.5, 6.2, 1.0).translate((0, 4.0)), -1, 1.0)
    objs.append({"name": "Varsto badge (pin back)", "parts": {"blue": pin, "white": prism(glyph(T), body_h, body_h + 1.0)},
                 "settings": {"wall_loops": "3"}})
    mag = slab(tile(T), body_h, top=0.4, bottom=0.2) - prism(circle(POCKET_D / 2, 0, 0), -1, POCKET_H)
    objs.append({"name": "Varsto badge (magnet)", "parts": {"blue": mag, "white": prism(glyph(T), body_h, body_h + 1.0)},
                 "settings": {"wall_loops": "3"}})
    return {"plates": [{"name": "Badges", "objects": objs}]}


# ---------------------------------------------------------------- checks
def check_plate(name: str, placed: list[tuple[str, Manifold]]) -> None:
    ex, ey = EXCLUDE
    for oname, m in placed:
        assert m.status().name == "NoError", (oname, m.status())
        x0, y0, z0, x1, y1, z1 = m.bounding_box()
        assert 1.0 <= x0 and x1 <= BED - 1.0 and y1 <= BED - 1.0 and z1 <= 250.0, (oname, m.bounding_box())
        assert y0 >= PURGE_Y, f"{oname}: too close to the purge line"
        assert not (x0 < ex + 1 and y0 < ey + 1), f"{oname}: inside the excluded corner"


def first_layer_area(m: Manifold) -> float:
    return m.slice(LAYER / 2).area()


def min_island_area(m: Manifold) -> float:
    return min(abs(c.area()) for c in m.slice(LAYER / 2).decompose())


# ---------------------------------------------------------------- 3MF (Bambu Studio)
NS = ('xmlns="http://schemas.microsoft.com/3dmanufacturing/core/2015/02" '
      'xmlns:BambuStudio="http://schemas.bambulab.com/package/2021" '
      'xmlns:p="http://schemas.microsoft.com/3dmanufacturing/production/2015/06" requiredextensions="p"')
EYE = "1 0 0 0 1 0 0 0 1"


def _mesh(m: Manifold) -> tuple[np.ndarray, np.ndarray]:
    mesh = m.to_mesh()
    return np.asarray(mesh.vert_properties)[:, :3].astype(float), np.asarray(mesh.tri_verts)


def _mesh_xml(m: Manifold) -> tuple[str, int]:
    v, t = _mesh(m)
    out = ["   <mesh>\n    <vertices>\n"]
    out += [f'     <vertex x="{x:.4f}" y="{y:.4f}" z="{z:.4f}"/>\n' for x, y, z in v]
    out.append("    </vertices>\n    <triangles>\n")
    out += [f'     <triangle v1="{a}" v2="{b}" v3="{c}"/>\n' for a, b, c in t]
    out.append("    </triangles>\n   </mesh>\n")
    return "".join(out), len(t)


ORDER = ("blue", "black", "white")   # part order inside an object (bottom colour first)


def project_settings(item: dict, tile_hex: str) -> dict:
    cfg = json.loads(SETTINGS.read_text())
    n = len(cfg["filament_settings_id"])
    assert n == 3, "p1s-project-settings.json must hold three filaments"
    cfg["filament_colour"] = [tile_hex, FILAMENTS["white"][2], FILAMENTS["black"][2]]
    cfg["flush_volumes_matrix"] = [str(FLUSH[i][j]) for i in range(n) for j in range(n)]
    cfg["curr_bed_type"] = "Textured PEI Plate"
    nplates = len(item["plates"])
    cfg["enable_prime_tower"] = "1" if item.get("prime_tower") else "0"
    cfg["wipe_tower_x"] = [str(item.get("tower_xy", (195.0, 200.0))[0])] * nplates
    cfg["wipe_tower_y"] = [str(item.get("tower_xy", (195.0, 200.0))[1])] * nplates
    diff = cfg["different_settings_to_system"]
    diff[0] = "" if item.get("prime_tower") else "enable_prime_tower"   # system default is on
    return cfg


def write_3mf(path: Path, item: dict, title: str, tile_hex: str) -> None:
    counter = iter(range(1, 1 << 30))

    def new_uuid() -> uuid.UUID:   # deterministic, so regenerating gives identical files
        return uuid.uuid5(uuid.NAMESPACE_URL, f"varsto-3d/{path.name}/{next(counter)}")

    stride = BED * 1.2
    cols = math.ceil(math.sqrt(len(item["plates"])))
    files: dict[str, str] = {}
    objs, items, settings, plates, assemble, rels = [], [], [], [], [], []
    next_id = 1
    obj_no = 0
    custom = []
    for pi, plate in enumerate(item["plates"]):
        ox, oy = (pi % cols) * stride, -(pi // cols) * stride
        inst = []
        for obj in plate["objects"]:
            obj_no += 1
            sub = []
            body = []
            for colour in ORDER:
                if colour not in obj["parts"]:
                    continue
                mx, faces = _mesh_xml(obj["parts"][colour])
                sub.append((next_id, colour, faces))
                body.append(f'  <object id="{next_id}" p:UUID="{new_uuid()}" type="model">\n{mx}  </object>\n')
                next_id += 1
            oid = next_id
            next_id += 1
            fname = f"3D/Objects/object_{obj_no}.model"
            files[fname] = (
                f'<?xml version="1.0" encoding="UTF-8"?>\n<model unit="millimeter" xml:lang="en-US" {NS}>\n'
                ' <metadata name="BambuStudio:3mfVersion">1</metadata>\n <resources>\n'
                + "".join(body) + ' </resources>\n <build/>\n</model>\n')
            rels.append(f' <Relationship Target="/{fname}" Id="rel-{obj_no}" '
                        'Type="http://schemas.microsoft.com/3dmanufacturing/2013/01/3dmodel"/>\n')
            comps = "".join(f'    <component p:path="/{fname}" objectid="{sid}" p:UUID="{new_uuid()}" '
                            f'transform="{EYE} 0 0 0"/>\n' for sid, _, _ in sub)
            objs.append(f'  <object id="{oid}" p:UUID="{new_uuid()}" type="model">\n   <components>\n'
                        f'{comps}   </components>\n  </object>\n')
            px, py = obj["pos"]
            items.append(f'  <item objectid="{oid}" p:UUID="{new_uuid()}" '
                         f'transform="{EYE} {px + ox:.4f} {py + oy:.4f} 0" printable="1"/>\n')
            parts_xml = "".join(
                f'    <part id="{sid}" subtype="normal_part">\n'
                f'      <metadata key="name" value="{obj["name"]} - {colour}"/>\n'
                '      <metadata key="matrix" value="1 0 0 0 0 1 0 0 0 0 1 0 0 0 0 1"/>\n'
                f'      <metadata key="extruder" value="{SLOT[colour]}"/>\n'
                f'      <mesh_stat face_count="{faces}" edges_fixed="0" degenerate_facets="0" '
                'facets_removed="0" facets_reversed="0" backwards_edges="0"/>\n    </part>\n'
                for sid, colour, faces in sub)
            settings.append(
                f'  <object id="{oid}">\n    <metadata key="name" value="{obj["name"]}"/>\n'
                '    <metadata key="extruder" value="1"/>\n'
                + "".join(f'    <metadata key="{k}" value="{v}"/>\n' for k, v in obj.get("settings", {}).items())
                + parts_xml + '  </object>\n')
            inst.append(oid)
            assemble.append(f'   <assemble_item object_id="{oid}" instance_id="0" '
                            f'transform="{EYE} {px + ox:.4f} {py + oy:.4f} 0" offset="0 0 0" />\n')
        plates.append(
            f'  <plate>\n    <metadata key="plater_id" value="{pi + 1}"/>\n'
            f'    <metadata key="plater_name" value="{plate["name"]}"/>\n'
            '    <metadata key="locked" value="false"/>\n'
            + "".join('    <model_instance>\n'
                      f'      <metadata key="object_id" value="{oid}"/>\n'
                      '      <metadata key="instance_id" value="0"/>\n'
                      f'      <metadata key="identify_id" value="{100 * (pi + 1) + k}"/>\n'
                      '    </model_instance>\n' for k, oid in enumerate(inst))
            + '  </plate>\n')
        if plate.get("pause_z"):
            layers = "".join(f'<layer top_z="{z:g}" type="1" extruder="1" color="" extra="" gcode="M400 U1"/>\n'
                             for z in plate["pause_z"])
            custom.append(f'<plate>\n<plate_info id="{pi + 1}"/>\n{layers}<mode value="MultiAsSingle"/>\n</plate>\n')

    files["3D/3dmodel.model"] = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n<model unit="millimeter" xml:lang="en-US" {NS}>\n'
        ' <metadata name="Application">BambuStudio-02.08.02.61</metadata>\n'
        ' <metadata name="BambuStudio:3mfVersion">1</metadata>\n'
        f' <metadata name="Title">{title}</metadata>\n'
        ' <resources>\n' + "".join(objs) + ' </resources>\n'
        f' <build p:UUID="{new_uuid()}">\n' + "".join(items) + ' </build>\n</model>\n')
    files["3D/_rels/3dmodel.model.rels"] = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
        + "".join(rels) + '</Relationships>\n')
    files["Metadata/model_settings.config"] = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<config>\n' + "".join(settings) + "".join(plates)
        + '  <assemble>\n' + "".join(assemble) + '  </assemble>\n</config>\n')
    files["Metadata/project_settings.config"] = json.dumps(project_settings(item, tile_hex), indent=4)
    if custom:
        files["Metadata/custom_gcode_per_layer.xml"] = (
            '<?xml version="1.0" encoding="utf-8"?>\n<custom_gcodes_per_layer>\n' + "".join(custom)
            + '</custom_gcodes_per_layer>\n')
    files_head = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">\n'
            ' <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>\n'
            ' <Default Extension="model" ContentType="application/vnd.ms-package.3dmanufacturing-3dmodel+xml"/>\n'
            ' <Default Extension="png" ContentType="image/png"/>\n'
            ' <Default Extension="gcode" ContentType="text/x.gcode"/>\n</Types>\n'),
        "_rels/.rels": (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">\n'
            ' <Relationship Target="/3D/3dmodel.model" Id="rel-1" '
            'Type="http://schemas.microsoft.com/3dmanufacturing/2013/01/3dmodel"/>\n</Relationships>\n'),
    }
    tmp = path.with_suffix(".3mf.tmp")
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in {**files_head, **files}.items():
            info = zipfile.ZipInfo(k, date_time=(2026, 1, 1, 0, 0, 0))   # reproducible archive
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, v)
    tmp.replace(path)


def write_stl(path: Path, m: Manifold) -> None:
    v, t = _mesh(m)
    tri = v[t]
    nrm = np.cross(tri[:, 1] - tri[:, 0], tri[:, 2] - tri[:, 0])
    nrm /= np.maximum(np.linalg.norm(nrm, axis=1, keepdims=True), 1e-12)
    rec = np.zeros(len(t), dtype=[("n", "<f4", 3), ("v", "<f4", (3, 3)), ("a", "<u2")])
    rec["n"], rec["v"] = nrm, tri
    with open(path, "wb") as f:
        f.write(b"Varsto fan item".ljust(80, b" "))
        f.write(struct.pack("<I", len(t)))
        f.write(rec.tobytes())


# ---------------------------------------------------------------- previews
def preview(path: Path, objects: list[dict], tile_hex: str, title: str, px: int = 900) -> None:
    """Small z-buffer rasteriser (orthographic, flat shading): exact occlusion, no GL needed."""
    from PIL import Image, ImageDraw

    def rgb(h: str) -> np.ndarray:
        h = h.lstrip("#")
        return np.array([int(h[i:i + 2], 16) for i in (0, 2, 4)], float) / 255

    tris, cols = [], []
    for obj in objects:
        for colour, m in obj["parts"].items():
            d = obj.get("display_inv")
            if d is not None:
                m = m.transform(d)
            v, t = _mesh(m)
            tris.append(v[t])
            cols.append(np.repeat(rgb(PREVIEW_RGB[colour] or tile_hex)[None], len(t), 0))
    tri, col = np.concatenate(tris), np.concatenate(cols)
    # view: azimuth -30° (from the front right), elevation 35°
    az, el = math.radians(-30), math.radians(35)
    rz = np.array([[math.cos(az), -math.sin(az), 0], [math.sin(az), math.cos(az), 0], [0, 0, 1]])
    rx = np.array([[1, 0, 0], [0, math.cos(-math.pi / 2 + el), -math.sin(-math.pi / 2 + el)],
                   [0, math.sin(-math.pi / 2 + el), math.cos(-math.pi / 2 + el)]])
    R = rx @ rz
    nrm = np.cross(tri[:, 1] - tri[:, 0], tri[:, 2] - tri[:, 0])
    nrm /= np.maximum(np.linalg.norm(nrm, axis=1, keepdims=True), 1e-12)
    light = np.array([-0.4, -0.5, 0.77])
    light /= np.linalg.norm(light)
    shade = 0.42 + 0.58 * np.clip(nrm @ light, 0, 1)
    fc = np.clip(col * shade[:, None], 0, 1)
    p = tri @ R.T                                    # x right, y up, z towards the viewer
    lo, hi = p.reshape(-1, 3).min(0), p.reshape(-1, 3).max(0)
    ss = 2 * px
    scale = 0.86 * ss / max(hi[0] - lo[0], hi[1] - lo[1])
    cx, cy = (lo[0] + hi[0]) / 2, (lo[1] + hi[1]) / 2
    X = (p[..., 0] - cx) * scale + ss / 2
    Y = ss / 2 - (p[..., 1] - cy) * scale + 0.03 * ss
    Z = p[..., 2]
    img = np.ones((ss, ss, 3)) * rgb("#e9ebef")
    zb = np.full((ss, ss), -np.inf)
    for i in range(len(tri)):
        xs, ys, zs = X[i], Y[i], Z[i]
        x0, x1 = max(int(xs.min()), 0), min(int(xs.max()) + 1, ss - 1)
        y0, y1 = max(int(ys.min()), 0), min(int(ys.max()) + 1, ss - 1)
        if x1 < x0 or y1 < y0:
            continue
        gx, gy = np.meshgrid(np.arange(x0, x1 + 1) + 0.5, np.arange(y0, y1 + 1) + 0.5)
        d = (ys[1] - ys[2]) * (xs[0] - xs[2]) + (xs[2] - xs[1]) * (ys[0] - ys[2])
        if abs(d) < 1e-12:
            continue
        w0 = ((ys[1] - ys[2]) * (gx - xs[2]) + (xs[2] - xs[1]) * (gy - ys[2])) / d
        w1 = ((ys[2] - ys[0]) * (gx - xs[2]) + (xs[0] - xs[2]) * (gy - ys[2])) / d
        w2 = 1 - w0 - w1
        inside = (w0 >= -1e-9) & (w1 >= -1e-9) & (w2 >= -1e-9)
        if not inside.any():
            continue
        z = w0 * zs[0] + w1 * zs[1] + w2 * zs[2]
        sub = zb[y0:y1 + 1, x0:x1 + 1]
        upd = inside & (z > sub)
        sub[upd] = z[upd]
        img[y0:y1 + 1, x0:x1 + 1][upd] = fc[i]
    im = Image.fromarray((img * 255).astype(np.uint8)).resize((px, px), Image.LANCZOS)
    ImageDraw.Draw(im).text((16, 12), title, fill=(40, 44, 52))
    im.save(path, optimize=True)


# ---------------------------------------------------------------- build
def items() -> dict[str, dict]:
    return {
        "keychain": keychain(True),
        "keychain-2colour": keychain(False),
        "coaster": coaster(True),
        "coaster-2colour": coaster(False),
        "magnet": magnet(True),
        "magnet-2colour": magnet(False),
        "standee": standee("black"),
        "standee-2colour": standee("white"),
        "badge": badge(),
    }


def place(item: dict) -> None:
    """Lay the objects of each plate out in a row near the plate centre, clear of the purge line."""
    for plate in item["plates"]:
        objs = plate["objects"]
        gap = 12.0
        widths = []
        for o in objs:
            # recentre each object: XY bbox centred at the origin, bottom at z = 0
            lo = np.min([m.bounding_box()[:3] for m in o["parts"].values()], axis=0)
            hi = np.max([m.bounding_box()[3:] for m in o["parts"].values()], axis=0)
            shift = [-(lo[0] + hi[0]) / 2, -(lo[1] + hi[1]) / 2, -lo[2]]
            o["parts"] = {k: v.translate(shift) for k, v in o["parts"].items()}
            o["shift"] = np.array(shift)
            widths.append((hi[0] - lo[0], hi[1] - lo[1]))
        total = sum(w for w, _ in widths) + gap * (len(objs) - 1)
        x = BED / 2 - total / 2
        for o, (w, h) in zip(objs, widths):
            o["pos"] = (x + w / 2, BED / 2 + 4.0)
            x += w + gap
        check_plate(plate["name"], [(o["name"], _union(list(o["parts"].values())).translate([*o["pos"], 0]))
                                    for o in objs])


def _union(ms: list[Manifold]) -> Manifold:
    out = ms[0]
    for m in ms[1:]:
        out += m
    return out


def display_inverse(o: dict) -> np.ndarray | None:
    """Transform from the placed print pose back to the display pose (previews)."""
    d = o.get("display")
    if d is None:
        return None
    # print pose = display_pose -> (d) -> shift; preview wants d^-1 after undoing the shift
    A = np.vstack([d, [0, 0, 0, 1]])
    S = np.eye(4)
    S[:3, 3] = -o["shift"]
    return (np.linalg.inv(A) @ S)[:3]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", type=Path, default=HERE)
    ap.add_argument("--tile", choices=("cobalt", "vault"), default="cobalt")
    ap.add_argument("--only", action="append")
    ap.add_argument("--no-preview", action="store_true")
    a = ap.parse_args()
    tile_hex = FILAMENTS[a.tile][2]
    suffix = "" if a.tile == "cobalt" else f"-{a.tile}"
    (a.out / "stl").mkdir(parents=True, exist_ok=True)
    (a.out / "previews").mkdir(parents=True, exist_ok=True)
    sfile = a.out / f"summary{suffix}.json"
    summary = json.loads(sfile.read_text()) if a.only and sfile.exists() else {}
    for name, item in items().items():
        if a.only and not any(name == o or name.startswith(o + "-") for o in a.only):
            continue
        place(item)
        stem = f"varsto-{name}{suffix}"
        write_3mf(a.out / f"{stem}.3mf", item, f"Varsto {name}", tile_hex)
        info = []
        for plate in item["plates"]:
            for o in plate["objects"]:
                oname = o["name"].lower().replace("varsto ", "").replace(" ", "-").replace("(", "").replace(")", "")
                multi = sum(len(p["objects"]) for p in item["plates"]) > 1
                for colour, m in o["parts"].items():
                    fn = f"{stem}-{oname}-{colour}.stl" if multi else f"{stem}-{colour}.stl"
                    write_stl(a.out / "stl" / fn, m)
                u = _union(list(o["parts"].values()))
                x0, y0, z0, x1, y1, z1 = u.bounding_box()
                info.append({"object": o["name"], "size_mm": [round(x1 - x0, 1), round(y1 - y0, 1), round(z1 - z0, 1)],
                             "first_layer_mm2": round(first_layer_area(u), 1),
                             "smallest_first_layer_island_mm2": round(min_island_area(u), 1),
                             "volume_cm3": {k: round(v.volume() / 1000, 2) for k, v in o["parts"].items()}})
                o["display_inv"] = display_inverse(o)
        summary[stem] = info
        if not a.no_preview:
            objs = [o for p in item["plates"] for o in p["objects"]]
            if not item.get("assemble"):
                objs = [{**o, "parts": {k: v.translate([o["pos"][0] - BED / 2, o["pos"][1] - BED / 2, 0])
                                        for k, v in o["parts"].items()}, "display_inv": None if o.get("display") is None
                         else display_inverse({**o, "shift": o["shift"] + [o["pos"][0] - BED / 2, o["pos"][1] - BED / 2, 0]})}
                        for o in objs]
            preview(a.out / "previews" / f"{stem}.png", objs if not item.get("assemble") else _assembled(objs),
                    tile_hex, f"Varsto {name}")
        print(f"{stem}: " + "; ".join(f'{i["object"]} {i["size_mm"]}' for i in info))
    sfile.write_text(json.dumps(dict(sorted(summary.items())), indent=2) + "\n")


def _assembled(objs: list[dict]) -> list[dict]:
    """Standee preview: tile in display pose placed into the base's slot."""
    out = []
    for o in objs:
        o2 = dict(o)
        if o.get("display") is None:
            o2["display_inv"] = None
            # base: undo the recentring so tile and base share the base's original frame
            o2["parts"] = {k: v.translate((-o["shift"]).tolist()) for k, v in o["parts"].items()}
        else:
            # tile: undo recentring, then stand it up (display transform)
            A = np.vstack([o["display"], [0, 0, 0, 1]])
            S = np.eye(4)
            S[:3, 3] = -o["shift"]
            o2["display_inv"] = (A @ S)[:3]
        out.append(o2)
    return out


if __name__ == "__main__":
    main()
