#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Varsto brand assets, generated from one geometry.

    python3 brand/render.py            # write every SVG, PNG, ICO, ICNS and the Android icons
    python3 brand/render.py --check    # parse every SVG and verify the PNG sizes
    python3 brand/render.py --sheet out.png   # contact sheet for a visual review

The mark is "the dial": a round vault door (two arcs of one ring, the sync
loop) with a keyhole in the middle, white on a blue tile. Every size is drawn
from the same construction with size-specific weights (tiers), so 16 px is as
crisp as 1024 px. See README.md in this directory for the rules.

Requires: rsvg-convert (librsvg), magick (ImageMagick 7), Pillow, fontTools,
uharfbuzz (kerning for the wordmark; without it the letters are not kerned).
"""
from __future__ import annotations

import argparse
import math
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.dom import minidom

BRAND = Path(__file__).resolve().parent
ROOT = BRAND.parent
PNG = BRAND / "png"
WEB = ROOT / "website" / "public"
ANDROID_RES = ROOT / "apps" / "android" / "app" / "src" / "main" / "res"
FONT = ROOT / "website" / "tools" / "render" / "fonts" / "Inter-SemiBold.ttf"

# Palette (website/public/assets/css/site.css uses the same blues)
DEEP = "#1b3a9a"      # vault blue: gradient end, dark accents
PRIMARY = "#2b57d6"   # signal blue: the tile
GRAD_BOTTOM = "#2146b2"  # 60 % of the way from PRIMARY to DEEP, app icon only
WHITE = "#ffffff"
INK = "#16181d"       # wordmark on light, mono mark
PAPER = "#eceef2"     # wordmark on dark

GRID = 256.0          # master grid; every tier is expressed in these units
C = GRID / 2

# Tiers: the same construction with weights tuned per pixel size.
#   rx        tile corner radius
#   R, W      ring centre-line radius and stroke width
#   gap       visible gap between the two arcs (cap to cap)
#   dot_r     keyhole head radius; dot_dy its centre above the tile centre
#   stem_top / stem_bot  half-widths of the keyhole stem (top hides in the head)
#   stem_end  stem bottom, below the tile centre; stem_rr its corner radius
TIERS = {
    # 128 px and up, and all vector uses
    "large": dict(rx=57, R=70, W=20, gap=24, dot_r=22, dot_dy=16, stem_top=10, stem_bot=14, stem_end=40, stem_rr=4),
    # 32 to 64 px
    "medium": dict(rx=57, R=72, W=24, gap=32, dot_r=24, dot_dy=15, stem_top=12, stem_bot=16, stem_end=42, stem_rr=4),
    # 16 to 24 px (favicon, tray)
    "small": dict(rx=56, R=78, W=30, gap=52, dot_r=30, dot_dy=18, stem_top=16, stem_bot=16, stem_end=46, stem_rr=4),
    # macOS menu bar template, 22 pt (glyph only, about 2 px stroke at 1x)
    "menubar": dict(rx=0, R=72, W=20, gap=34, dot_r=23, dot_dy=15, stem_top=11, stem_bot=15, stem_end=41, stem_rr=4),
}
GAP_ANGLES = (-45.0, 135.0)  # gap centres: upper right and lower left


def tier_for(px: int) -> str:
    if px <= 24:
        return "small"
    if px <= 64:
        return "medium"
    return "large"


def _f(v: float) -> str:
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s == "-0" else s


def _pt(cx: float, cy: float, r: float, deg: float) -> tuple[float, float]:
    a = math.radians(deg)
    return cx + r * math.cos(a), cy + r * math.sin(a)


def arc_path(cx: float, cy: float, R: float, W: float, a0: float, a1: float) -> str:
    """Filled annular sector from angle a0 to a1 (degrees, clockwise on screen) with round caps."""
    h = W / 2
    ro, ri = R + h, R - h
    big = 1 if (a1 - a0) > 180 else 0
    po0, po1 = _pt(cx, cy, ro, a0), _pt(cx, cy, ro, a1)
    pi0, pi1 = _pt(cx, cy, ri, a0), _pt(cx, cy, ri, a1)
    return (
        f"M{_f(po0[0])} {_f(po0[1])}"
        f"A{_f(ro)} {_f(ro)} 0 {big} 1 {_f(po1[0])} {_f(po1[1])}"
        f"A{_f(h)} {_f(h)} 0 0 1 {_f(pi1[0])} {_f(pi1[1])}"
        f"A{_f(ri)} {_f(ri)} 0 {big} 0 {_f(pi0[0])} {_f(pi0[1])}"
        f"A{_f(h)} {_f(h)} 0 0 1 {_f(po0[0])} {_f(po0[1])}Z"
    )


def ring_paths(t: dict, cx: float = C, cy: float = C) -> list[str]:
    g = math.degrees(math.asin((t["gap"] / 2 + t["W"] / 2) / t["R"]))
    a, b = GAP_ANGLES
    return [
        arc_path(cx, cy, t["R"], t["W"], a + g, b - g),
        arc_path(cx, cy, t["R"], t["W"], b + g, a + 360 - g),
    ]


def keyhole_path(t: dict, cx: float = C, cy: float = C) -> str:
    r = t["dot_r"]
    hy = cy - t["dot_dy"]
    head = f"M{_f(cx + r)} {_f(hy)}A{_f(r)} {_f(r)} 0 1 1 {_f(cx - r)} {_f(hy)}A{_f(r)} {_f(r)} 0 1 1 {_f(cx + r)} {_f(hy)}Z"
    ht, hb, rr = t["stem_top"], t["stem_bot"], t["stem_rr"]
    y1 = cy + t["stem_end"]
    stem = (
        f"M{_f(cx - ht)} {_f(hy)}L{_f(cx + ht)} {_f(hy)}L{_f(cx + hb)} {_f(y1 - rr)}"
        f"A{_f(rr)} {_f(rr)} 0 0 1 {_f(cx + hb - rr)} {_f(y1)}L{_f(cx - hb + rr)} {_f(y1)}"
        f"A{_f(rr)} {_f(rr)} 0 0 1 {_f(cx - hb)} {_f(y1 - rr)}Z"
    )
    return head + stem


def glyph_path(t: dict, cx: float = C, cy: float = C) -> str:
    """Ring arcs and keyhole as one path (nonzero fill, all subpaths clockwise)."""
    return "".join(ring_paths(t, cx, cy)) + keyhole_path(t, cx, cy)


def svg(view: float, body: str, *, width: float | None = None, height: float | None = None, defs: str = "") -> str:
    w = _f(width if width is not None else view)
    h = _f(height if height is not None else view)
    d = f"\n  <defs>{defs}</defs>" if defs else ""
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="Varsto">'
        f"{d}\n{body}\n</svg>\n"
    )


def tile_rect(t: dict, fill: str, size: float = GRID, x: float = 0, y: float = 0) -> str:
    """Tile of `size` with the corner radius from an already scaled tier dict."""
    rx = t["rx"]
    return f'  <rect x="{_f(x)}" y="{_f(y)}" width="{_f(size)}" height="{_f(size)}" rx="{_f(rx)}" fill="{fill}"/>'


def mark_svg(tier: str, *, gradient: bool = False, view: float = GRID) -> str:
    """The mark on its tile. `view` scales the whole drawing (16 for the favicon)."""
    t = TIERS[tier]
    s = view / GRID
    tt = {k: v * s for k, v in t.items()}
    cx = cy = view / 2
    defs = ""
    fill = PRIMARY
    if gradient:
        defs = (
            f'<linearGradient id="tile" x1="0" y1="0" x2="0" y2="1">'
            f'<stop offset="0" stop-color="{PRIMARY}"/><stop offset="1" stop-color="{GRAD_BOTTOM}"/></linearGradient>'
        )
        fill = "url(#tile)"
    body = tile_rect(tt, fill, view) + f'\n  <path fill="{WHITE}" d="{glyph_path(tt, cx, cy)}"/>'
    return svg(view, body, defs=defs)


def glyph_only_svg(tier: str, color: str, view: float = GRID, scale_to: float | None = None) -> str:
    """The glyph without a tile. `scale_to` sets the outer ring diameter in view units."""
    t = TIERS[tier]
    s = view / GRID
    if scale_to is not None:
        s = scale_to / (2 * (t["R"] + t["W"] / 2))
    tt = {k: v * s for k, v in t.items()}
    cx = cy = view / 2
    return svg(view, f'  <path fill="{color}" d="{glyph_path(tt, cx, cy)}"/>')


def macos_svg(px: int) -> str:
    """Apple-style canvas: tile at 80.5 % with a soft shadow, transparent around it."""
    t = TIERS[tier_for(int(px * 0.805))]
    size = px * 0.805
    off = (px - size) / 2
    s = size / GRID
    tt = {k: v * s for k, v in t.items()}
    cx = cy = px / 2
    blur = px * 0.011
    dy = px * 0.0085
    defs = (
        f'<linearGradient id="tile" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0" stop-color="{PRIMARY}"/><stop offset="1" stop-color="{GRAD_BOTTOM}"/></linearGradient>'
        f'<filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">'
        f'<feGaussianBlur stdDeviation="{_f(blur)}"/></filter>'
    )
    shadow = (
        f'  <rect x="{_f(off)}" y="{_f(off + dy)}" width="{_f(size)}" height="{_f(size)}" rx="{_f(tt["rx"])}" '
        f'fill="#000" fill-opacity="0.28" filter="url(#shadow)"/>'
    )
    body = shadow + "\n" + tile_rect(tt, "url(#tile)", size, off, off) + f'\n  <path fill="{WHITE}" d="{glyph_path(tt, cx, cy)}"/>'
    return svg(px, body, defs=defs)


# ---------------------------------------------------------------- wordmark

def text_paths(text: str, size: float, x: float, baseline: float, tracking_em: float, fill: str) -> tuple[str, float]:
    """Inter SemiBold set as outlines. Returns (svg path elements, advance width)."""
    from fontTools.pens.svgPathPen import SVGPathPen
    from fontTools.pens.transformPen import TransformPen
    from fontTools.ttLib import TTFont

    font = TTFont(str(FONT))
    upem = font["head"].unitsPerEm
    order = font.getGlyphOrder()
    glyphs = font.getGlyphSet()
    k = size / upem
    runs: list[tuple[str, float, float]] = []  # (glyph name, x offset, y offset) in font units
    try:
        import uharfbuzz as hb

        face = hb.Face(hb.Blob.from_file_path(str(FONT)))
        hbfont = hb.Font(face)
        hbfont.scale = (upem, upem)
        buf = hb.Buffer()
        buf.add_str(text)
        buf.guess_segment_properties()
        hb.shape(hbfont, buf, {"kern": True, "liga": True, "calt": True})
        pen_x = 0.0
        for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
            runs.append((order[info.codepoint], pen_x + pos.x_offset, pos.y_offset))
            pen_x += pos.x_advance + tracking_em * upem
    except ImportError:
        print("warning: uharfbuzz missing, wordmark set without kerning", file=sys.stderr)
        cmap = font.getBestCmap()
        hmtx = font["hmtx"]
        pen_x = 0.0
        for ch in text:
            name = cmap[ord(ch)]
            runs.append((name, pen_x, 0.0))
            pen_x += hmtx[name][0] + tracking_em * upem
    pen_x -= tracking_em * upem  # no tracking after the last letter
    out = []
    for name, gx, gy in runs:
        spen = SVGPathPen(glyphs, ntos=_f)
        tpen = TransformPen(spen, (k, 0, 0, -k, x + gx * k, baseline - gy * k))
        glyphs[name].draw(tpen)
        out.append(f'  <path fill="{fill}" d="{spen.getCommands()}"/>')
    return "\n".join(out), pen_x * k


def wordmark_svg(text_fill: str) -> str:
    """Lockup: tile mark M = 96, clear gap 0.4 M, cap height 0.6 M centred on the mark."""
    M = 96.0
    gap = 0.4 * M
    cap = 0.6 * M
    from fontTools.ttLib import TTFont

    font = TTFont(str(FONT))
    cap_units = font["OS/2"].sCapHeight / font["head"].unitsPerEm
    size = cap / cap_units
    baseline = M / 2 + cap / 2
    t = {k: v * M / GRID for k, v in TIERS["large"].items()}
    paths, adv = text_paths("Varsto", size, M + gap, baseline, -0.03, text_fill)
    width = M + gap + adv
    body = tile_rect(t, PRIMARY, M) + f'\n  <path fill="{WHITE}" d="{glyph_path(t, M / 2, M / 2)}"/>\n' + paths
    return svg(width, body, width=width, height=M)


# ---------------------------------------------------------------- rasters

def run(*cmd: str) -> None:
    subprocess.run(cmd, check=True)


def rsvg(src: Path, dst: Path, px: int) -> None:
    run("rsvg-convert", "-w", str(px), "-h", str(px), str(src), "-o", str(dst))


def render_mark_png(px: int, dst: Path, tmp: Path, *, gradient: bool, margin: float = 0.0) -> None:
    """Full-bleed tile (margin 0) or a tile inset by `margin` of the canvas, transparent around."""
    tier = tier_for(px)
    if margin:
        t = TIERS[tier]
        size = GRID * (1 - 2 * margin)
        off = (GRID - size) / 2
        s = size / GRID
        tt = {k: v * s for k, v in t.items()}
        fill = PRIMARY
        defs = ""
        if gradient:
            defs = (
                f'<linearGradient id="tile" x1="0" y1="0" x2="0" y2="1">'
                f'<stop offset="0" stop-color="{PRIMARY}"/><stop offset="1" stop-color="{GRAD_BOTTOM}"/></linearGradient>'
            )
            fill = "url(#tile)"
        body = tile_rect(tt, fill, size, off, off) + f'\n  <path fill="{WHITE}" d="{glyph_path(tt, C, C)}"/>'
        doc = svg(GRID, body, defs=defs)
    else:
        doc = mark_svg(tier, gradient=gradient)
    src = tmp / f"mark-{tier}-{int(gradient)}-{margin}.svg"
    src.write_text(doc)
    rsvg(src, dst, px)


ICNS_TYPES = [  # (type, pixel size)
    (b"icp4", 16), (b"icp5", 32), (b"icp6", 64), (b"ic07", 128), (b"ic08", 256), (b"ic09", 512),
    (b"ic10", 1024), (b"ic11", 32), (b"ic12", 64), (b"ic13", 256), (b"ic14", 512),
]


def write_icns(dst: Path, tmp: Path) -> None:
    """Apple icon container with PNG payloads (iconutil-equivalent, no Mac needed)."""
    chunks = []
    cache: dict[int, bytes] = {}
    for kind, px in ICNS_TYPES:
        if px not in cache:
            src = tmp / f"macos-{px}.svg"
            src.write_text(macos_svg(px))
            png = tmp / f"macos-{px}.png"
            rsvg(src, png, px)
            cache[px] = png.read_bytes()
        data = cache[px]
        chunks.append(kind + struct.pack(">I", 8 + len(data)) + data)
    body = b"".join(chunks)
    dst.write_bytes(b"icns" + struct.pack(">I", 8 + len(body)) + body)


def android_vectors() -> dict[str, str]:
    """Adaptive icon layers: 108 dp viewport, glyph (large tier) at 52 dp outer diameter."""
    t = TIERS["large"]
    scale = 52.0 / (2 * (t["R"] + t["W"] / 2))
    tr = (108 - GRID * scale) / 2
    head = '<?xml version="1.0" encoding="utf-8"?>\n<vector xmlns:android="http://schemas.android.com/apk/res/android" android:width="108dp" android:height="108dp" android:viewportWidth="108" android:viewportHeight="108">\n'
    group = f'    <group android:scaleX="{scale:.5f}" android:scaleY="{scale:.5f}" android:translateX="{tr:.3f}" android:translateY="{tr:.3f}">\n'
    paths = "".join(f'        <path android:fillColor="#FFFFFF" android:pathData="{p}" />\n' for p in ring_paths(t) + [keyhole_path(t)])
    fg = head + group + paths + "    </group>\n</vector>\n"
    mono = head + group + paths.replace("#FFFFFF", "#000000") + "    </group>\n</vector>\n"
    bg = head + f'    <path android:fillColor="{PRIMARY.upper()}" android:pathData="M0,0h108v108h-108z" />\n</vector>\n'
    launcher = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
        '    <background android:drawable="@drawable/ic_launcher_background" />\n'
        '    <foreground android:drawable="@drawable/ic_launcher_foreground" />\n'
        '    <monochrome android:drawable="@drawable/ic_launcher_monochrome" />\n'
        "</adaptive-icon>\n"
    )
    return {
        "drawable/ic_launcher_foreground.xml": fg,
        "drawable/ic_launcher_monochrome.xml": mono,
        "drawable/ic_launcher_background.xml": bg,
        "mipmap-anydpi-v26/ic_launcher.xml": launcher,
    }


ANDROID_DENSITIES = {"mdpi": 48, "hdpi": 72, "xhdpi": 96, "xxhdpi": 144, "xxxhdpi": 192}
PNG_SIZES = (16, 32, 48, 64, 128, 256, 512, 1024)


def build() -> list[Path]:
    written: list[Path] = []

    def put(path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        written.append(path)

    # vectors
    put(BRAND / "logo.svg", mark_svg("large"))
    put(BRAND / "appicon.svg", mark_svg("large", gradient=True))
    put(BRAND / "logo-small.svg", mark_svg("small", view=16))
    put(BRAND / "logo-mono.svg", glyph_only_svg("large", INK))
    put(BRAND / "logo-dark.svg", glyph_only_svg("large", WHITE))
    put(BRAND / "menubar-template.svg", glyph_only_svg("menubar", "#000000", view=22, scale_to=18))
    put(BRAND / "wordmark.svg", wordmark_svg(INK))
    put(BRAND / "wordmark-dark.svg", wordmark_svg(PAPER))
    put(WEB / "assets" / "img" / "logo.svg", mark_svg("large"))
    put(WEB / "favicon.svg", mark_svg("small", view=16))
    for rel, text in android_vectors().items():
        put(ANDROID_RES / rel, text)

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        PNG.mkdir(exist_ok=True)
        for px in PNG_SIZES:
            dst = PNG / f"logo-{px}.png"
            render_mark_png(px, dst, tmp, gradient=px >= 128)
            written.append(dst)
        ico = BRAND / "varsto.ico"
        run("magick", *(str(PNG / f"logo-{px}.png") for px in (16, 32, 48, 256)), str(ico))
        written.append(ico)
        icns = BRAND / "Varsto.icns"
        write_icns(icns, tmp)
        written.append(icns)
        for density, px in ANDROID_DENSITIES.items():
            dst = ANDROID_RES / f"mipmap-{density}" / "ic_launcher.png"
            dst.parent.mkdir(parents=True, exist_ok=True)
            render_mark_png(px, dst, tmp, gradient=True, margin=1 / 24)
            written.append(dst)
    return written


def check() -> int:
    from PIL import Image

    bad = 0
    svgs = sorted(BRAND.glob("*.svg")) + [WEB / "favicon.svg", WEB / "assets" / "img" / "logo.svg"]
    for p in svgs:
        try:
            minidom.parse(str(p))
        except Exception as e:  # noqa: BLE001
            print(f"FAIL parse {p}: {e}")
            bad += 1
            continue
        with tempfile.NamedTemporaryFile(suffix=".png") as tf:
            r = subprocess.run(["rsvg-convert", str(p), "-o", tf.name], capture_output=True)
        if r.returncode:
            print(f"FAIL render {p}: {r.stderr.decode().strip()}")
            bad += 1
    for px in PNG_SIZES:
        p = PNG / f"logo-{px}.png"
        if not p.exists() or Image.open(p).size != (px, px):
            print(f"FAIL size {p}")
            bad += 1
    for density, px in ANDROID_DENSITIES.items():
        p = ANDROID_RES / f"mipmap-{density}" / "ic_launcher.png"
        if not p.exists() or Image.open(p).size != (px, px):
            print(f"FAIL size {p}")
            bad += 1
    icns = BRAND / "Varsto.icns"
    data = icns.read_bytes()
    if data[:4] != b"icns" or struct.unpack(">I", data[4:8])[0] != len(data):
        print(f"FAIL icns header {icns}")
        bad += 1
    print("check: OK" if not bad else f"check: {bad} problem(s)")
    return 1 if bad else 0


def sheet(out: Path) -> None:
    """Contact sheet: mark at 16/32/64/256 on light and dark, zoomed 16/32, lockups, menu bar."""
    from PIL import Image, ImageDraw

    W, H = 1400, 1180
    img = Image.new("RGBA", (W, H), "#fbfbfa")
    d = ImageDraw.Draw(img)
    d.rectangle([700, 0, W, H], fill="#0d0f12")

    def paste(src: Image.Image, x: int, y: int) -> None:
        img.alpha_composite(src.convert("RGBA"), (x, y))

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        for side, bg in ((0, "#fbfbfa"), (700, "#0d0f12")):
            x = side + 40
            for px in (16, 32, 64, 256):
                paste(Image.open(PNG / f"logo-{px}.png"), x, 40 + (256 - px) // 2)
                x += px + 40
            # zoomed 1:1 pixels of 16 and 32
            for i, px in enumerate((16, 32)):
                z = Image.open(PNG / f"logo-{px}.png").resize((px * 8, px * 8), Image.NEAREST)
                paste(z, side + 40 + i * 300, 340)
            # lockup
            wm = BRAND / ("wordmark.svg" if side == 0 else "wordmark-dark.svg")
            png = tmp / f"wm-{side}.png"
            run("rsvg-convert", "-h", "72", str(wm), "-o", str(png))
            paste(Image.open(png), side + 40, 640)
            run("rsvg-convert", "-h", "28", str(wm), "-o", str(png))
            paste(Image.open(png), side + 40, 740)
            # menu bar template at 1x and 2x, inverted on dark (as macOS does)
            for i, (px, label) in enumerate(((22, "1x"), (44, "2x"))):
                png = tmp / f"mb-{px}.png"
                run("rsvg-convert", "-w", str(px), "-h", str(px), str(BRAND / "menubar-template.svg"), "-o", str(png))
                m = Image.open(png).convert("RGBA")
                if side:
                    r, g, b, a = m.split()
                    m = Image.merge("RGBA", (a.point(lambda _: 255), a.point(lambda _: 255), a.point(lambda _: 255), a))
                bar = Image.new("RGBA", (260, 28 if px == 22 else 56), "#e8e8ea" if side == 0 else "#2a2a2e")
                bar.alpha_composite(m, (12, (bar.height - px) // 2))
                paste(bar, side + 40 + i * 300, 820)
            # glyph-only variants
            png = tmp / f"glyph-{side}.png"
            run("rsvg-convert", "-w", "96", "-h", "96", str(BRAND / ("logo-mono.svg" if side == 0 else "logo-dark.svg")), "-o", str(png))
            paste(Image.open(png), side + 40, 920)
            # macOS canvas 128
            png = tmp / f"mac-{side}.png"
            (tmp / "mac.svg").write_text(macos_svg(128))
            rsvg(tmp / "mac.svg", png, 128)
            paste(Image.open(png), side + 180, 904)
            # android adaptive preview: circle mask of fg over bg
            fg_svg = tmp / "fg.svg"
            t = TIERS["large"]
            fg_svg.write_text(svg(108, f'  <circle cx="54" cy="54" r="36" fill="{PRIMARY}"/>\n  <path fill="{WHITE}" d="{glyph_path({k: v * (52 / 160) for k, v in t.items()}, 54, 54)}"/>'))
            rsvg(fg_svg, png, 128)
            paste(Image.open(png), side + 340, 904)
    img.convert("RGB").save(out)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="validate the generated files instead of writing them")
    ap.add_argument("--sheet", type=Path, help="write a contact sheet PNG for review")
    args = ap.parse_args()
    if args.check:
        return check()
    if args.sheet:
        sheet(args.sheet)
        print(f"wrote {args.sheet}")
        return 0
    for tool in ("rsvg-convert", "magick"):
        if not shutil.which(tool):
            print(f"{tool} not found", file=sys.stderr)
            return 1
    for p in build():
        print(f"wrote {p.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
