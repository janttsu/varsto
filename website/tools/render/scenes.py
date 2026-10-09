# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""The illustration compositions, one function per output file.

Coordinates are the design grid of the old SVGs (640 x 320, hero 1200 x 600), so
each scene keeps the same story, elements and reading order. Text is not
modelled: every label is queued through scene_kit.text() and drawn by compose.py
in a band under each node (node() computes the band from the projected bounding
box of the object, so labels never overlap the objects). UI pieces that sit on a
card (icons, badges, seals) are parented to the card with on_card().
"""
from __future__ import annotations

import math

from mathutils import Vector

import scene_kit as K

SCENES = {}


def scene(name, w=640, h=320):
    def deco(fn):
        SCENES[name] = (w, h, fn)
        return fn
    return deco


def node(root, x, y, hc, title=None, sub=None, lift=0.0, rot=0.0, gap=20, name=None, label_x=None):
    """Place an object so its mid-height point hc shows at (x, y); label it below."""
    K.place(root, x, y, hc, rot, lift)
    bb = K.register_box(name or root.name, root, "object")
    cx = label_x if label_x is not None else (bb[0] + bb[2]) / 2
    yy = bb[3] + gap
    if title:
        K.text(cx, yy, title, "title")
        yy += 18
    for s in ([sub] if isinstance(sub, str) else (sub or [])):
        K.text(cx, yy, s, "sub")
        yy += 18
    return root


def free_node(root, x, y, hc=0.0, lift=0.0, rot=0.0, kind="object", name=None):
    K.place(root, x, y, hc, rot, lift)
    K.register_box(name or root.name, root, kind)
    return root


def bb_node(root, x, y, depth_h=0.35, lift=0.0, name=None, toward=0.12, kind="object"):
    """Free-floating billboard (camera-facing) element at grid point (x, y)."""
    K.billboard(root, x, y, depth_h, lift, toward)
    K.register_box(name or root.name, root, kind)
    return root


def ui(card, root, x, y, toward=0.05, kind="ui"):
    """UI piece on a card's face (may overlap the card, nothing else)."""
    K.on_card(card, root, x, y, toward)
    K.register_box(root.name, root, kind, parent=card["box_name"])
    return root


def corner_point(parent, corner, dx=0.0, dy=0.0):
    x0, y0, x1, y1 = K.box_of(parent)
    x = {"l": x0, "r": x1, "c": (x0 + x1) / 2}[corner[1]]
    y = {"t": y0, "b": y1, "c": (y0 + y1) / 2}[corner[0]]
    return x + dx, y + dy


def badge_at(parent, kind, corner="tr", dx=0.0, dy=0.0, depth_h=0.6, r=11.5):
    """Check / cross badge attached to a corner of parent (sits on its silhouette edge)."""
    x, y = corner_point(parent, corner, dx, dy)
    b = K.badge(kind, r)
    K.billboard(b, x, y, depth_h, 0.0, 0.3)
    K.register_box(b.name, b, "badge", parent=parent["box_name"])
    return b


def lock_at(parent, corner="tr", dx=0.0, dy=0.0, scale=0.9, lift=None):
    """Padlock attached to a corner of parent. The lock stands in the world (its
    centre is 0.15*scale above its origin), floating so the centre meets the corner."""
    x, y = corner_point(parent, corner, dx, dy)
    p = K.padlock(scale=scale)
    hc = 0.17 * scale
    lift = 0.6 if lift is None else lift
    K.place(p, x, y, hc, lift=lift)
    K.register_box(p.name, p, "badge", parent=parent["box_name"])
    return p


def attached(parent, root, corner, dx=0.0, dy=0.0, hc=0.0, lift=0.5, billboard=False, depth_h=0.6):
    """Any element attached to a parent's corner (registered as a badge)."""
    x, y = corner_point(parent, corner, dx, dy)
    if billboard:
        K.billboard(root, x, y, depth_h, 0.0, 0.3)
    else:
        K.place(root, x, y, hc, lift=lift)
    K.register_box(root.name, root, "badge", parent=parent["box_name"])
    return root


def card_at(x0, y0, w, h, tone="white", r=12, depth_h=0.2, kind="card", parent=None):
    """UI card whose top-left corner is at (x0, y0) in grid px. A camera-facing
    plane is tilted, so a tall card is lifted until its lower edge clears the floor."""
    c = K.card(w, h, r, tone)
    depth_h = max(depth_h, h / 2 * K.PX * K.S.U.z + 0.1)
    K.billboard(c, x0 + w / 2, y0 + h / 2, depth_h, toward=0.0)
    K.register_box(c.name, c, kind, parent=parent)
    return c


def blocks(cols, rows, s=0.1, g=0.06):
    """A few standing ciphertext blocks (attach them to a cloud or stick)."""
    g_ = K.empty("fblocks")
    K.cipher_blocks(g_, cols, rows, s=s, g=g, h=0.05, plane="xz")
    return g_


def floating_blocks(x, y, cols, rows, lift=0.5, s=0.1, g=0.06):
    return free_node(blocks(cols, rows, s, g), x, y, 0.0, lift=lift)


def L(*pts, **kw):
    return K.link(list(pts), **kw)


# ============================================================ features
@scene("features/ledger")
def ledger():
    lp = node(K.laptop("cipher"), 100, 96, 0.35, "Laptop")
    cl = node(K.cloud(), 320, 88, 0.3, "Your storage", lift=0.22)
    lock_at(cl, "tr", dx=0, dy=0, lift=0.8)
    mo = node(K.monitor("cipher"), 540, 96, 0.4, "Desktop")
    L((166, 88), (206, 72), (236, 72), (266, 84))
    L((376, 84), (412, 72), (446, 72), (482, 88))
    for y, txt in ((190, '#41 laptop · stored block 7f3a on "box"'), (228, "#42 desktop · fetched 7f3a, hash verified")):
        card_at(110, y, 420, 30, r=8)
        K.text(124, y + 20, txt, "row", "s")
        K.pill2d(462, y + 7, 56, 16, "signed", fill="#2bb673", color="#1f8f57", style="small", alpha=40)
    K.caption("Signed ledgers on every device: they converge without meeting.")


@scene("features/transferrer")
def transferrer():
    node(K.laptop("cipher"), 110, 112, 0.35, "Home PC")
    node(K.monitor("cipher"), 530, 112, 0.4, "Office PC")
    u = K.usb_stick()
    u.scale = (1.3,) * 3
    st = node(u, 320, 146, 0.06, "Transferrer", "USB stick or disk marked as carrier", rot=-20)
    floating_blocks(300, 70, 3, 1, lift=0.6)
    lock_at(st, "tr", dx=0, dy=0, lift=0.45)
    L((166, 106), (208, 92), (242, 92), (268, 118))
    L((372, 118), (402, 92), (438, 92), (476, 106))
    K.caption("Carries only the missing encrypted blocks; no cloud needed.")


@scene("features/untrusted")
def untrusted():
    lp = node(K.laptop("lines"), 108, 122, 0.35, "You", "holds the keys")
    attached(lp, K.key(scale=0.8, upright=False), "tr", dx=0, dy=0, billboard=True, depth_h=0.7)
    sp = node(K.storage_panel(), 320, 116, 0.63, "Shared storage")
    lock_at(sp, "tr", dx=0, dy=0, lift=1.0)
    ns = node(K.nas(), 526, 134, 0.26, "Your friend's NAS", "stores and verifies, cannot open")
    badge_at(ns, "ok", "tr", dx=0, dy=0)
    L((176, 118), (246, 118), arrows=("start", "end"))
    L((398, 122), (470, 122))
    K.caption("A replica token: it stores and verifies, but can never read.")


def _sel_row(card, y, icon, name, status, done, x_icon=274, x_name=292, x_status=540, x_mark=558):
    ic = K.file_icon(0.42) if icon == "fi" else K.folder_icon(0.42)
    ui(card, ic, x_icon, y)
    K.text(x_name, y + 5, name, "title", "s")
    K.text(x_status, y + 4.5, status, "sub", "e")
    if done:
        ui(card, K.badge("ok", 9.8), x_mark, y)
    else:
        ui(card, K.cloud_icon(0.7), x_mark, y)


@scene("features/selective")
def selective():
    node(K.phone("rows"), 110, 140, 0.42, "Phone")
    c = card_at(250, 62, 330, 184)
    for y in (110, 154, 198):
        K.rule2d(262, y, 568, y)
    _sel_row(c, 88, "fi", "holiday-2025.mp4", "placeholder · 2.1 GB", False)
    _sel_row(c, 132, "fi", "contract.pdf", "downloaded", True)
    _sel_row(c, 176, "fo", "raw-photos/", "placeholder · 48 GB", False)
    _sel_row(c, 220, "fi", "notes.md", "downloaded", True)
    L((142, 122), (176, 108), (206, 100), (244, 96))
    K.caption("See everything, download what you open, free space in one tap.")


@scene("features/sharing")
def sharing():
    lp = node(K.laptop("cipher"), 106, 146, 0.35, "You")
    node(K.laptop("cipher"), 534, 146, 0.35, "Another Varsto user")
    node(K.folder(), 320, 140, 0.4, "project/")
    L((172, 146), (238, 146))
    L((402, 146), (468, 146))
    L((150, 100), (220, 30), (420, 30), (486, 100))
    c = card_at(262, 44, 116, 24, r=12, depth_h=0.9)
    ui(c, K.key(scale=0.55, upright=False), 288, 56)
    K.text(342, 60.5, "folder key", "accent")
    K.caption("One folder key is handed over; the rest of the vault stays shut.")


@scene("features/background")
def background():
    bar = bb_node(K.bar(608, 30), 320, 35, 0.6, toward=0.0, kind="card")
    for x, w in ((30, 40), (78, 30), (116, 36)):
        ui(bar, K.bar(w, 8, "#64748b", r=4, t=0.012), x + w / 2, 35, toward=0.02)
    ui(bar, K.tray_icon(), 510, 35, toward=0.02)
    for x in (546, 566):
        ui(bar, K.dot(4.5, "mid"), x, 35, toward=0.02)
    ui(bar, K.bar(28, 8, "mid", r=4, t=0.012), 598, 35, toward=0.02)
    tray = card_at(380, 56, 244, 172, r=10, depth_h=0.3)
    ui(tray, K.dot(5, "green"), 402, 76)
    K.text(414, 81, "Varsto", "title", "s")
    K.text(396, 100, "Up to date · last sync 12 s ago", "sub", "s")
    K.rule2d(392, 112, 612, 112)
    for i, item in enumerate(("Open Varsto", "Sync now", "Pause syncing", "Check for updates")):
        y = 138 + i * 24
        ui(tray, K.dot(3.5, "blue300"), 400, y - 4)
        K.text(414, y, item, "row", "s")
    for i, (name, where) in enumerate((("macOS", "menu bar"), ("Windows", "system tray"), ("Linux", "tray or indicator"))):
        y = 72 + i * 52
        c = card_at(40, y, 220, 40, r=10, depth_h=0.3)
        ui(c, K.badge("ok", 10.5), 66, y + 20)
        K.text(86, y + 25, name, "title", "s")
        K.text(244, y + 24.5, where, "sub", "e")
    K.caption("Watches your folders, syncs in seconds, updates with one click.")


@scene("features/cold")
def cold():
    node(K.laptop("cipher"), 100, 116, 0.35, "Laptop")
    cl = node(K.cloud(), 320, 106, 0.3, "Hot storage", "S3, NAS: read and write", lift=0.22)
    attached(cl, blocks(3, 1), "bl", dx=0, dy=-12, lift=0.3)
    node(K.archive(), 530, 112, 0.25, "Cold archive", ["Glacier: written,", "never read by surprise"])
    L((166, 108), (206, 94), (236, 94), (266, 104))
    L((376, 104), (412, 94), (446, 94), (482, 108))
    K.caption("Prices steer placement; cold reads happen only on your say-so.")


@scene("features/disks")
def disks():
    sh = K.shelf()
    node(sh, 140, 136, 0.56, "Disks on a shelf", "group A at home, group B elsewhere")
    for z, letter in ((0.035 + 0.12, "A"), (0.395 + 0.12, "A"), (0.755 + 0.12, "B")):
        x, y = K.project(sh.matrix_world @ Vector((0.0, -0.08, z + 0.012)))
        K.text(x, y + 4, letter, "letter", free=True)
    lock_at(sh, "tr", dx=0, dy=0, lift=1.2)
    node(K.laptop("cipher"), 420, 130, 0.35, "PC with a USB dock", label_x=470)
    node(K.dock(), 544, 170, 0.05, rot=-20)
    L((488, 162), (507, 170), solid=True, arrows=(), tone="mid", h=0.03, r=0.008)
    L((236, 128), (290, 110), (324, 110), (360, 118))
    K.caption("Old drives become counted, verified copies: attach, fill, eject.")


@scene("features/mobile")
def mobile():
    cl = node(K.cloud(), 320, 86, 0.3, lift=0.2)
    lock_at(cl, "tr", dx=0, dy=0, lift=0.75)
    ph = node(K.phone("cipher"), 200, 160, 0.42, "Phone", "nothing stored in clear text")
    lock_at(ph, "tr", dx=0, dy=0, scale=0.8, lift=0.65)
    node(K.tablet(), 440, 160, 0.43, "Tablet")
    L((286, 96), (258, 106), (234, 116), (216, 126), arrows=("start", "end"))
    L((356, 96), (384, 106), (406, 116), (420, 126), arrows=("start", "end"))
    K.caption("Same encrypted core; files decrypt only when you open them.")


def _seal(card, x, y, initials, name):
    ui(card, K.seal(), x, y)
    K.text(x, y + 3.5, initials, "sealtxt", free=True)
    K.text(x, y + 34, name, "sealname")


@scene("features/pq")
def pq():
    c1 = card_at(40, 56, 260, 176)
    K.text(170, 84, "Ledger batch #42", "title")
    K.rule2d(56, 96, 284, 96)
    g = K.empty("cardblocks")
    K.cipher_blocks(g, 15, 3, s=0.11, g=0.045, h=0.02)
    ui(c1, g, 170, 124, toward=0.01)
    _seal(c1, 110, 184, "Ed", "Ed25519")
    _seal(c1, 230, 184, "ML", "ML-DSA-65")
    K.text(170, 254, "both signatures must verify", "sub")
    c2 = card_at(340, 56, 260, 176)
    K.text(470, 84, "Share token", "title")
    K.rule2d(356, 96, 584, 96)
    pill = ui(c2, K.card(212, 38, 19, "blue100"), 470, 131, toward=0.02, kind="card")
    lk = K.padlock(scale=0.7)
    lk.location = K.card_point(c2, 388, 131, 0.2) - Vector((0, 0, 0.12))
    K.register_box(lk.name, lk, "ui", parent=pill["box_name"])
    K.text(482, 135.5, "folder key, sealed", "row")
    _seal(c2, 410, 184, "X", "X25519")
    _seal(c2, 530, 184, "ML", "ML-KEM-768")
    K.text(470, 254, "opens only on the requesting device", "sub")
    K.caption("Classical and post-quantum together: breaking one is not enough.")


# ============================================================ use cases
@scene("usecases/plane")
def plane():
    p = K.plane(0.9)
    free_node(p, 62, 44, 0.0, lift=0.9, rot=-15, name="plane")
    L((100, 44), (600, 44), h=0.9, tone="grey", arrows=(), dash=7, gap=6, r=0.009)
    K.text(112, 70, "in flight, no internet", "sub", "s")
    node(K.phone("cipher"), 196, 160, 0.42, "Phone")
    node(K.laptop("cipher"), 446, 158, 0.35, "Laptop")
    L((226, 136), (266, 100), (350, 100), (390, 130), tone="blue600", arrows=("start", "end"), solid=True, h=0.5)
    K.text(300, 92, "hotspot / LAN, direct transfer", "sub", free=True)
    f = bb_node(K.file_icon(1.0), 310, 166, 0.45)
    attached(f, K.padlock(scale=0.6), "tr", dx=2, dy=0, hc=0.1, lift=0.6)
    cl = node(K.cloud(scale=0.7, alpha_tone="#eef1f7"), 320, 238, 0.22, lift=0.1)
    badge_at(cl, "x", "tl", dx=0, dy=0)
    K.caption("cloud catches up when the network returns")


@scene("usecases/stolen")
def stolen():
    lp = node(K.laptop("lock"), 150, 148, 0.35, "Stolen laptop", "Strongroom stays locked")
    badge_at(lp, "x", "tr", dx=0, dy=0, depth_h=0.8)
    node(K.phone("rows_red"), 480, 158, 0.42, "Your phone")
    L((456, 120), (420, 64), (250, 54), (214, 104))
    K.text(332, 60, "revoke + wipe", "title")
    cl = node(K.cloud(scale=0.7), 320, 240, 0.22, lift=0.1)
    badge_at(cl, "ok", "tr", dx=0, dy=0)
    K.caption("data still restorable from your storages")


@scene("usecases/provider")
def provider():
    ca = node(K.cloud(alpha_tone="#e3e8f2"), 124, 94, 0.3, "Provider A closed", lift=0.2)
    badge_at(ca, "x", "tr", dx=0, dy=0)
    cb = node(K.cloud(), 320, 94, 0.3, "Provider B", lift=0.2)
    attached(cb, blocks(3, 1), "bl", dx=0, dy=-12, lift=0.3)
    badge_at(cb, "ok", "tr", dx=0, dy=0)
    dk = node(K.disk(), 514, 112, 0.06, "Disk at home", rot=-15)
    badge_at(dk, "ok", "tr", dx=0, dy=0)
    node(K.laptop("alert", scale=0.65), 320, 230, 0.23)
    L((320, 198), (320, 166))
    L((368, 206), (420, 188), (456, 166), (486, 146))
    K.caption("alert: 1 of 3 copies lost, repairing to a new storage")


@scene("usecases/fire")
def fire():
    h = K.house()
    node(h, 150, 176, 0.4, "Home", "PC, NAS and disks lost together")
    K.flame(0.9, at=(0.16, -0.12, 0.66), parent=h)
    K.flame(0.6, at=(-0.2, -0.08, 0.58), parent=h)
    L((206, 152), (262, 88), (398, 88), (452, 154))
    h2 = node(K.house(), 500, 176, 0.4, "Relatives, other city")
    badge_at(h2, "ok", "tr", dx=0, dy=0, depth_h=0.9)
    cl = node(K.cloud(scale=0.7), 330, 222, 0.22, None, "plus a cloud bucket", lift=0.1, gap=14)
    badge_at(cl, "ok", "tr", dx=0, dy=0)
    K.caption("placement rule: one copy in another place")


@scene("usecases/camera")
def camera():
    ph = node(K.phone("photos"), 140, 150, 0.42, "Camera roll full")
    attached(ph, K.camera_icon(), "tr", dx=0, dy=0, billboard=True, depth_h=0.8)
    L((182, 132), (224, 110), (280, 104), (312, 112))
    cl = node(K.cloud(), 372, 120, 0.3, "Encrypted upload", lift=0.2)
    attached(cl, blocks(3, 1), "bl", dx=0, dy=-12, lift=0.3)
    lock_at(cl, "tr", dx=0, dy=0, lift=0.7)
    L((432, 142), (470, 160), (496, 182), (508, 204))
    dk = node(K.disk(), 530, 230, 0.06, None, "second copy verified", rot=-15, gap=18)
    badge_at(dk, "ok", "tr", dx=0, dy=0)
    K.caption("Originals are deleted only after the policy is met and verified.")


def _tree_row(card, y, indent, name, size, status, done, top=False):
    x = 262 + indent
    ui(card, K.folder_icon(0.42), x, y)
    K.text(x + 16, y + 5 if top else y + 4.5, name, "title" if top else "row", "s")
    K.text(470, y + 4.5, size, "sub", "e")
    K.text(556, y + 4.5, status, "sub", "e")
    if done:
        ui(card, K.badge("ok", 9.8), 572, y)
    elif status:
        ui(card, K.cloud_icon(0.7), 572, y)


@scene("usecases/newdevice")
def newdevice():
    ph = node(K.phone("tree"), 130, 150, 0.42, "New phone", "joined with a key")
    attached(ph, K.key(scale=0.6, upright=False), "tr", dx=2, dy=0, billboard=True, depth_h=0.8)
    c = card_at(240, 54, 350, 200)
    K.rule2d(266, 92, 266, 152, color="#e2e8f0", width=2)
    _tree_row(c, 80, 0, "Photos/", "", "", False, top=True)
    _tree_row(c, 110, 24, "2019/", "48 GB", "placeholder", False)
    _tree_row(c, 140, 24, "2024/", "31 GB", "placeholder", False)
    _tree_row(c, 170, 24, "2026/", "2.1 GB", "downloaded", True)
    _tree_row(c, 200, 0, "Documents/", "400 MB", "downloaded", True, top=True)
    _tree_row(c, 230, 0, "Video/", "1.2 TB", "placeholder", False, top=True)
    L((168, 150), (194, 140), (214, 132), (234, 124))
    K.caption("A 128 GB phone can see a 2 TB vault. Tap a file to fetch it.")


@scene("usecases/cheapest")
def cheapest():
    bb_node(K.card(440, 40, 14, "blue600"), 388, 58, 0.6, toward=0.0, kind="card")
    K.text(388, 63, 'You: "What is the cheapest place to keep the 2019 videos?"', "white")
    c = card_at(32, 96, 500, 148, r=14)
    ui(c, K.sparkle(), 58, 120)
    K.text(76, 125, "Assistant (MCP)", "title", "s")
    K.text(48, 150, "310 GB, read twice a year. Cold tier at provider C would cost about a third of", "sub", "s")
    K.text(48, 168, "the current hot bucket; restore takes hours and costs per GB.", "sub", "s")
    K.text(48, 194, "Proposed: move 2019 videos to provider C cold; keep one hot copy at home.", "row", "s")
    ui(c, K.card(92, 26, 13, "blue600"), 94, 221, toward=0.02, kind="card")
    K.text(94, 225.3, "Confirm", "white")
    K.caption("Open, dated price data; nothing moves without your confirmation.")


@scene("usecases/sensitive")
def sensitive():
    node(K.phone("cipher"), 100, 150, 0.42, None, "no clear text on the phone")
    c = K.framed_card(200, 160, 14)
    K.billboard(c, 312, 138, 160 / 2 * K.PX * K.S.U.z + 0.1, toward=0.0)
    K.register_box(c.name, c, "card")
    K.text(312, 90, "Taxes/ (Strongroom)", "title")
    lk = K.padlock(scale=1.4)
    lk.location = K.card_point(c, 312, 128, 0.35) - Vector((0, 0, 0.24))
    K.register_box(lk.name, lk, "ui", parent=c["box_name"])
    kg = K.empty("keygroup")
    K.on_card(c, kg, 312, 196, 0.07)
    for R, r, tone in ((12, 0.005, "gold"), (18, 0.004, "#f3c98a")):
        rg = K.ring(R, r, tone)
        rg.parent = kg
        rg.location = (-0.095, 0, 0)
    ky = K.key(scale=0.55, upright=False)
    ky.parent = kg
    ky.location = (0, 0, 0.0)
    K.register_box(kg.name, kg, "ui", parent=c["box_name"])
    L((420, 154), (462, 154), tone="grey", arrows=(), dash=7, gap=6, r=0.009, h=0.5)
    bb_node(K.badge("x"), 441, 154, 0.55, kind="object")
    card_at(474, 120, 126, 68)
    K.text(537, 148, "AI assistant", "title")
    K.text(537, 168, "cannot see it", "sub")
    K.caption("opens only with a touch of your security key")


@scene("usecases/reader")
def reader():
    node(K.monitor("photos"), 150, 142, 0.4, "Desktop", "has the photos, makes thumbnails")
    L((208, 122), (240, 100), (264, 96), (288, 104))
    cl = node(K.cloud(), 340, 112, 0.3, None, "thumbs/<folder>/<hash>.enc", lift=0.2, gap=16)
    attached(cl, blocks(3, 1), "bl", dx=0, dy=-12, lift=0.3)
    lock_at(cl, "tr", dx=0, dy=0, lift=0.7)
    L((396, 128), (426, 144), (452, 148), (478, 148))
    node(K.phone("thumbs"), 512, 154, 0.42, "Phone", "previews, files are placeholders")
    K.caption("Thumbnails stay encrypted; the storage sees only ciphertext.")


# ============================================================ encryption page
def labels(root, title=None, sub=None, gap=20, label_x=None):
    """Title and sub-labels in a band under an element already placed and registered."""
    bb = K.box_of(root)
    cx = label_x if label_x is not None else (bb[0] + bb[2]) / 2
    yy = bb[3] + gap
    if title:
        K.text(cx, yy, title, "title")
        yy += 18
    for s in ([sub] if isinstance(sub, str) else (sub or [])):
        K.text(cx, yy, s, "sub")
        yy += 18
    return root


def slabs(widths, tones, h=0.3, t=0.06, g=0.045):
    """A row of standing slabs of different widths (content-defined chunks), facing -Y."""
    root = K.empty("slabs")
    x = -(sum(widths) + g * (len(widths) - 1)) / 2
    for w, tone in zip(widths, tones):
        K.box(w, t, h, K.mat(tone), bevel=0.02, at=(x + w / 2, 0, 0), parent=root, name="slab")
        x += w + g
    return root


def word_bars(card, x0, y0, cols, rows, w=40, pitch_x=50, pitch_y=16, tone="grey"):
    """Rows of short bars on a card standing for printed words."""
    for r in range(rows):
        for c in range(cols):
            ui(card, K.bar(w - (r * 7 + c * 11) % 14, 7, tone, r=3.5, t=0.012), x0 + c * pitch_x, y0 + r * pitch_y, toward=0.02)


def _seal_small(card, x, y, initials):
    ui(card, K.seal(13), x, y)
    K.text(x, y + 3.5, initials, "sealtxt", free=True)


@scene("encryption/hierarchy")
def hierarchy():
    v = card_at(20, 70, 150, 150)
    ui(v, K.key(scale=0.95, upright=False), 95, 112)
    K.text(95, 162, "Vault key", "title")
    K.text(95, 184, "random, 256 bits", "sub")
    K.text(95, 202, "in keys.enc", "sub")
    p = card_at(222, 22, 220, 116)
    K.text(332, 46, "Vault-wide keys", "title")
    K.rule2d(236, 57, 428, 57)
    for i, (a, b) in enumerate((("ledger", "replica"), ("registry", "peer auth"), ("folder record", "beacon tag"))):
        y = 80 + i * 20
        for x, s in ((238, a), (344, b)):
            ui(p, K.dot(3, "blue300"), x, y - 4)
            K.text(x + 8, y, s, "row", "s")
    f = card_at(222, 168, 220, 96)
    ui(f, K.key(scale=0.5, upright=False), 260, 210)
    K.text(290, 207, "Folder key", "title", "s")
    K.text(290, 227, "random, one per folder", "sub", "s")
    m = card_at(490, 22, 130, 116)
    ui(m, K.folder_icon(0.6), 555, 52)
    K.text(555, 92, "Metadata key", "title")
    K.text(555, 110, "manifests,", "sub")
    K.text(555, 126, "thumbnails", "sub")
    c = card_at(490, 168, 130, 96)
    g = K.empty("cardblocks")
    K.cipher_blocks(g, 5, 2, s=0.1, g=0.045, h=0.02)
    ui(c, g, 555, 194, toward=0.01)
    K.text(555, 232, "Chunk keys", "title")
    K.text(555, 250, "one per chunk", "sub")
    L((174, 120), (194, 104), (198, 82), (216, 80))
    L((300, 142), (300, 164))
    K.text(310, 157, "seals", "sub", "s")
    L((446, 200), (464, 190), (466, 90), (484, 80))
    L((446, 216), (484, 216))
    K.caption("Keys derive by purpose; each folder has its own random key.")


@scene("encryption/pipeline")
def pipeline():
    K.text(236, 34, "on your device", "sub")
    K.text(548, 34, "leaves the device", "sub")
    L((444, 26), (444, 250), h=0.0, tone="grey", arrows=(), dash=7, gap=6, r=0.009)
    f = K.file_icon(1.5)
    bb_node(f, 66, 112, 0.45)
    labels(f, "File", "report.pdf")
    widths = (0.2, 0.11, 0.26, 0.15)
    ch = free_node(slabs(widths, ("#dfe6f6", "#d3dcef", "#dfe6f6", "#d3dcef")), 196, 120, 0.15, lift=0.1)
    labels(ch, "Chunks", ["cut by content,", "compressed"], gap=26)
    en = free_node(slabs(widths, ("blue300", "#6f90f0", "#b8c9ff", "blue600")), 344, 120, 0.15, lift=0.1)
    labels(en, "Encrypted", ["key per chunk,", "named by hash"], gap=26)
    lock_at(en, "tr", dx=0, dy=0, scale=0.75, lift=0.75)
    cl = node(K.cloud(), 548, 114, 0.3, "Your storage", ["sees hashes and sizes,", "never names or content"], lift=0.22)
    attached(cl, blocks(3, 1), "bl", dx=0, dy=-12, lift=0.3)
    L((100, 114), (136, 114))
    L((258, 114), (284, 114))
    L((404, 112), (440, 100), (462, 98), (490, 106))
    K.caption("Every file is ciphertext before it leaves your device.")


def _batch(x0, y0, n, tone="white"):
    c = card_at(x0, y0, 140, 100, tone=tone)
    K.text(x0 + 70, y0 + 24, f"Batch #{n}", "title")
    K.rule2d(x0 + 14, y0 + 34, x0 + 126, y0 + 34)
    g = K.empty("cardblocks")
    K.cipher_blocks(g, 7, 2, s=0.09, g=0.04, h=0.02)
    ui(c, g, x0 + 70, y0 + 52, toward=0.01)
    _seal_small(c, x0 + 46, y0 + 80, "Ed")
    _seal_small(c, x0 + 94, y0 + 80, "ML")
    return c


@scene("encryption/chain")
def chain():
    _batch(20, 22, 40)
    _batch(196, 22, 41)
    _batch(372, 22, 42)
    d = _batch(196, 152, "41", tone="#fdeef0")
    badge_at(d, "x", "tr", dx=0, dy=0)
    L((164, 72), (192, 72), solid=True, h=0.5)
    L((340, 72), (368, 72), solid=True, h=0.5)
    L((116, 128), (122, 176), (156, 200), (190, 200), tone="red", h=0.4)
    K.text(350, 196, "rolled back: fork,", "sub", "s", color="#c2414a")
    K.text(350, 214, "detected and fenced", "sub", "s", color="#c2414a")
    node(K.laptop("cipher", scale=0.62), 570, 184, 0.22, "Other devices", "verify and merge")
    K.caption("Each batch is signed twice and chained to the one before.")


@scene("encryption/sealed")
def sealed():
    node(K.laptop("cipher", scale=0.85), 92, 150, 0.3, "Recipient", "keeps the private half")
    node(K.laptop("cipher", scale=0.85), 548, 150, 0.3, "You", "seal the folder key")
    t = card_at(210, 36, 220, 60)
    K.text(320, 60, "1  Request code", "title")
    K.text(320, 82, "X25519 + ML-KEM-768 public", "sub")
    L((132, 104), (150, 74), (176, 66), (204, 66))
    L((436, 66), (464, 66), (490, 74), (508, 104))
    K.text(320, 138, "travels over any channel", "sub")
    s = card_at(210, 168, 220, 60)
    lk = K.padlock(scale=0.6)
    lk.location = K.card_point(s, 238, 206, 0.2) - Vector((0, 0, 0.1))
    K.register_box(lk.name, lk, "ui", parent=s["box_name"])
    ui(s, K.key(scale=0.45, upright=False), 270, 198)
    K.text(354, 194, "2  Sealed token", "title")
    K.text(354, 214, "one folder key", "sub")
    L((508, 196), (490, 214), (464, 222), (436, 222))
    L((204, 222), (176, 222), (150, 214), (132, 196))
    K.text(320, 250, "only the requesting device can open it", "sub")
    K.caption("Hybrid key exchange: the token is safe on any channel.")


@scene("encryption/strongroom")
def strongroom():
    u = K.usb_stick()
    u.scale = (1.4,) * 3
    node(u, 92, 150, 0.06, "Security key", "one touch", rot=-20)
    st = card_at(196, 30, 224, 112)
    K.text(308, 54, "Stored", "title")
    K.rule2d(210, 66, 406, 66)
    for i, s in enumerate(("credential id", "per-folder salt")):
        y = 90 + i * 22
        ui(st, K.dot(3, "blue300"), 218, y - 4)
        K.text(230, y, s, "row", "s")
    lk = K.padlock(scale=0.4)
    lk.location = K.card_point(st, 218, 130, 0.15) - Vector((0, 0, 0.07))
    K.register_box(lk.name, lk, "ui", parent=st["box_name"])
    K.text(230, 134, "wrapped folder key", "row", "s")
    mem = card_at(196, 170, 224, 80)
    ui(mem, K.key(scale=0.5, upright=False), 228, 210)
    K.text(258, 205, "Unlocked", "title", "s")
    K.text(258, 226, "in memory, 15 minutes", "sub", "s")
    no = card_at(456, 30, 164, 180)
    K.text(538, 54, "No other path", "title")
    K.rule2d(470, 66, 606, 66)
    for i, s in enumerate(("passphrase", "vault key", "stolen backup")):
        y = 100 + i * 38
        ui(no, K.badge("x", 10), 482, y)
        K.text(500, y + 4.5, s, "row", "s")
    L((132, 124), (152, 100), (170, 86), (190, 86))
    L((132, 168), (152, 196), (170, 210), (190, 210))
    K.caption("Without the physical key there is no path to the folder key.")


@scene("encryption/recovery")
def recovery():
    k = card_at(24, 34, 196, 210)
    K.text(122, 60, "Recovery kit", "title")
    K.rule2d(38, 72, 206, 72)
    word_bars(k, 62, 92, 3, 8, w=44, pitch_x=60, pitch_y=17)
    K.text(122, 262, "24 words, with checksum", "sub")
    K.text(246, 143, "or", "sub")
    shares = []
    for i in range(3):
        y0 = 30 + i * 76
        s = card_at(272, y0, 120, 58)
        K.text(332, y0 + 22, f"Share {i + 1}", "title")
        word_bars(s, 304, y0 + 38, 2, 1, w=44, pitch_x=56, tone="grey")
        shares.append(s)
    for s in shares[:2]:
        badge_at(s, "ok", "tr", dx=0, dy=0)
    ped = K.pedestal(0.42, 0.08)
    ky = K.key(scale=1.25, upright=True)
    ky.parent = ped
    ky.location = (0, 0, 0.4)
    ky.rotation_euler = (0, 0, math.radians(K.AZ_DEG))
    node(ped, 534, 96, 0.2, "Vault key", "any two shares rebuild it")
    L((398, 60), (436, 58), (462, 64), (482, 78))
    L((398, 136), (430, 136), (456, 110), (478, 98))
    L((398, 211), (440, 211), tone="grey", arrows=(), dash=7, gap=6, r=0.009, h=0.5)
    bb_node(K.badge("x"), 419, 211, 0.55, kind="object")
    K.text(452, 215, "alone reveals nothing", "sub", "s")
    K.caption("No account, no reset: the kit is the vault key on paper.")


# ============================================================ hero (1200 x 600)
@scene("hero", 1200, 600)
def hero():
    kx, ky = 600, 214
    glow = K.empty("glow")
    K.cyl(1.5, 0.004, K.mat("#f1f4fe", rough=1.0, sheen=0.0), parent=glow)
    K.place(glow, kx, ky + 44, 0.0)
    ped = K.pedestal(0.8, 0.14)
    k = K.key(scale=2.6, upright=True)
    k.parent = ped
    k.location = (0, 0, 0.78)
    k.rotation_euler = (0, 0, math.radians(K.AZ_DEG))
    node(ped, kx, ky + 44, 0.07)
    K.text(kx, 58, "Your keys", "hero_title")
    K.text(kx, 90, "never leave your devices", "hero_sub")
    big = 1.25
    nodes = [
        (112, 396, K.laptop("cipher", scale=1.15), 0.4, "Laptop", None, "tr", (0, 0)),
        (316, 424, K.shelf(), 0.56 * big, "Disks on a shelf", "offline, counted, verified", "tr", (0, 0)),
        (506, 438, K.bucket(), 0.35 * big, "S3 bucket", "hot copy, any provider", "tr", (0, 0)),
        (694, 438, K.archive(), 0.25 * big, "Cold archive", "never read by surprise", "tr", (0, 0)),
        (884, 424, K.nas(), 0.26 * big, "NAS at home", "or a friend's, or a server", "tr", (0, 0)),
        (1086, 396, K.phone("cipher", scale=1.15), 0.5, "Phone", None, "tr", (2, 0)),
    ]
    placed = []
    for x, y, root, hc, title, sub, corner, (dx, dy) in nodes:
        if not root.name.startswith(("laptop", "phone")):
            root.scale = (big,) * 3
        node(root, x, y, hc, title, sub, gap=24)
        lock_at(root, corner, dx=dx, dy=dy, scale=1.1, lift=1.0)
        placed.append((x, y, root))
    for x, y, root in placed:
        bx0, by0, bx1, by1 = K.box_of(root)
        ex, ey = (bx0 + bx1) / 2, by0 - 14
        dx, dy = ex - kx, ey - ky
        n = (dx * dx + dy * dy) ** 0.5
        sx, sy = kx + dx / n * 95, ky + dy / n * 95
        L((sx, sy), (kx + dx / n * 170, ky + dy / n * 170), (ex, ey - 60), (ex, ey), h=0.45, dash=8, gap=6, r=0.014)
