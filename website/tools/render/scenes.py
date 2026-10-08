# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""The 20 illustration compositions, one function per output file.

Coordinates are the design grid of the old SVGs (640 x 320, hero 1200 x 600), so
each scene keeps the same story, elements and reading order. Text is not
modelled: every label is queued through scene_kit.text() and drawn by compose.py
in a band under each node (node() computes the band from the projected bounding
box of the object, so labels never overlap the objects). UI pieces that sit on a
card (icons, badges, seals) are parented to the card with on_card().
"""
from __future__ import annotations

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
    bb = K.register_box(name or root.name, root)
    cx = label_x if label_x is not None else (bb[0] + bb[2]) / 2
    yy = bb[3] + gap
    if title:
        K.text(cx, yy, title, "title")
        yy += 18
    for s in ([sub] if isinstance(sub, str) else (sub or [])):
        K.text(cx, yy, s, "sub")
        yy += 18
    return root


def bb_node(root, x, y, depth_h=0.35, lift=0.0, name=None, toward=0.12):
    """Free-floating billboard (camera-facing) UI object at grid point (x, y)."""
    K.billboard(root, x, y, depth_h, lift, toward)
    K.register_box(name or "ui:" + root.name, root)
    return root


def ui(card, root, x, y, toward=0.05):
    """UI object on a card's face."""
    K.on_card(card, root, x, y, toward)
    K.register_box("ui:" + root.name, root)
    return root


def lock_near(x, y, lift=0.55, scale=1.0):
    """Floating padlock badge next to an object."""
    p = K.padlock(scale=scale)
    K.place(p, x, y, 0.15 * scale, lift=lift)
    K.register_box("ui:" + p.name, p)
    return p


def card_at(x0, y0, w, h, tone="white", r=12, depth_h=0.2):
    """UI card whose top-left corner is at (x0, y0) in grid px. A camera-facing
    plane is tilted, so a tall card is lifted until its lower edge clears the floor."""
    c = K.card(w, h, r, tone)
    depth_h = max(depth_h, h / 2 * K.PX * K.S.U.z + 0.1)
    K.billboard(c, x0 + w / 2, y0 + h / 2, depth_h, toward=0.0)
    K.register_box("card:" + c.name, c)
    return c


def floating_blocks(x, y, cols, rows, lift=0.5, s=0.1, g=0.06):
    g_ = K.empty("fblocks")
    K.cipher_blocks(g_, cols, rows, s=s, g=g, h=0.05, plane="xz")
    K.place(g_, x, y, 0.0, lift=lift)
    K.register_box("ui:" + g_.name, g_)
    return g_


def L(*pts, **kw):
    return K.link(list(pts), **kw)


# ============================================================ features
@scene("features/ledger")
def ledger():
    node(K.laptop("cipher"), 100, 96, 0.35, "Laptop")
    node(K.cloud(), 320, 88, 0.3, "Your storage", lift=0.22)
    lock_near(356, 52, lift=0.78)
    node(K.monitor("cipher"), 540, 96, 0.4, "Desktop")
    L((162, 88), (206, 72), (236, 72), (268, 84))
    L((374, 84), (412, 72), (446, 72), (484, 88))
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
    node(u, 320, 140, 0.06, "Transferrer", "USB stick or disk marked as carrier", rot=-20)
    floating_blocks(318, 72, 3, 1, lift=0.6)
    lock_near(364, 100, lift=0.5, scale=0.9)
    L((166, 106), (208, 92), (242, 92), (274, 110))
    L((368, 110), (402, 92), (438, 92), (476, 106))
    K.caption("Carries only the missing encrypted blocks; no cloud needed.")


@scene("features/untrusted")
def untrusted():
    node(K.laptop("lines"), 110, 118, 0.35, "You", "holds the keys")
    bb_node(K.key(scale=0.9, upright=False), 156, 76, 0.6, toward=0.4)
    node(K.storage_panel(), 320, 112, 0.63, "Shared storage")
    lock_near(394, 64, lift=1.0, scale=0.9)
    node(K.nas(), 520, 128, 0.26, "Your friend's NAS", "stores and verifies, cannot open")
    bb_node(K.badge("ok"), 562, 90, 0.6)
    L((172, 116), (246, 116), arrows=("start", "end"))
    L((396, 118), (474, 118))
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
    node(K.laptop("cipher"), 110, 142, 0.35, "You")
    node(K.laptop("cipher"), 530, 142, 0.35, "Another Varsto user")
    node(K.folder(), 320, 136, 0.4, "project/")
    L((170, 142), (240, 142))
    L((400, 142), (470, 142))
    L((150, 96), (220, 26), (420, 26), (486, 96))
    c = card_at(262, 40, 116, 24, r=12, depth_h=0.9)
    ui(c, K.key(scale=0.55, upright=False), 288, 52)
    K.text(342, 56.5, "folder key", "accent")
    K.caption("One folder key is handed over; the rest of the vault stays shut.")


@scene("features/background")
def background():
    bar = bb_node(K.bar(608, 30), 320, 35, 0.6, toward=0.0)
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
    node(K.cloud(), 320, 106, 0.3, "Hot storage", "S3, NAS: read and write", lift=0.22)
    floating_blocks(304, 128, 3, 1, lift=0.58)
    node(K.archive(), 530, 112, 0.25, "Cold archive", ["Glacier: written,", "never read by surprise"])
    L((162, 108), (206, 94), (236, 94), (268, 104))
    L((374, 104), (412, 94), (446, 94), (484, 108))
    K.caption("Prices steer placement; cold reads happen only on your say-so.")


@scene("features/disks")
def disks():
    sh = K.shelf()
    node(sh, 140, 136, 0.56, "Disks on a shelf", "group A at home, group B elsewhere")
    for z, letter in ((0.035 + 0.12, "A"), (0.395 + 0.12, "A"), (0.755 + 0.12, "B")):
        x, y = K.project(sh.matrix_world @ Vector((0.0, -0.08, z + 0.012)))
        K.text(x, y + 4, letter, "letter", free=True)
    lock_near(230, 70, lift=1.25, scale=0.9)
    node(K.laptop("cipher"), 420, 130, 0.35, "PC with a USB dock", label_x=470)
    node(K.dock(), 540, 168, 0.05, rot=-20)
    L((488, 162), (505, 168), solid=True, arrows=(), tone="mid", h=0.03, r=0.008)
    L((234, 128), (290, 110), (324, 110), (360, 118))
    K.caption("Old drives become counted, verified copies: attach, fill, eject.")


@scene("features/mobile")
def mobile():
    node(K.cloud(), 320, 72, 0.3, lift=0.2)
    lock_near(358, 42, lift=0.72, scale=0.9)
    node(K.phone("cipher"), 200, 156, 0.42, "Phone", "nothing stored in clear text")
    lock_near(232, 110, lift=0.58, scale=0.8)
    node(K.tablet(), 440, 156, 0.43, "Tablet")
    L((286, 94), (258, 104), (234, 112), (216, 120), arrows=("start", "end"))
    L((356, 94), (384, 104), (406, 112), (420, 120), arrows=("start", "end"))
    K.caption("Same encrypted core; files decrypt only when you open them.")


def _seal(card, x, y, initials, name):
    ui(card, K.seal(), x, y)
    K.text(x, y + 3.5, initials, "sealtxt")
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
    ui(c2, K.card(212, 38, 19, "blue100"), 470, 131, toward=0.02)
    lk = K.padlock(scale=0.7)
    p = K.card_point(c2, 388, 131, 0.2)
    lk.location = p - Vector((0, 0, 0.12))
    K.register_box("ui:lock", lk)
    K.text(482, 135.5, "folder key, sealed", "row")
    _seal(c2, 410, 184, "X", "X25519")
    _seal(c2, 530, 184, "ML", "ML-KEM-768")
    K.text(470, 254, "opens only on the requesting device", "sub")
    K.caption("Classical and post-quantum together: breaking one is not enough.")


# ============================================================ use cases
@scene("usecases/plane")
def plane():
    p = K.plane(0.9)
    K.place(p, 62, 44, 0.0, lift=0.9, rot_z=-15)
    K.register_box("plane", p)
    L((100, 44), (600, 44), h=0.9, tone="grey", arrows=(), dash=7, gap=6, r=0.009)
    K.text(108, 68, "in flight, no internet", "sub", "s")
    node(K.phone("cipher"), 200, 158, 0.42, "Phone")
    node(K.laptop("cipher"), 440, 156, 0.35, "Laptop")
    L((230, 134), (268, 100), (350, 100), (386, 130), tone="blue600", arrows=("start", "end"), solid=True, h=0.5)
    # free: the laptop's bounding rectangle reaches here, the lid itself does not
    K.text(300, 92, "hotspot / LAN, direct transfer", "sub", free=True)
    bb_node(K.file_icon(1.0), 316, 164, 0.45)
    lock_near(340, 152, lift=0.55, scale=0.7)
    node(K.cloud(scale=0.7, alpha_tone="#eef1f7"), 320, 236, 0.22, lift=0.1)
    bb_node(K.badge("x"), 350, 218, 0.5)
    K.caption("cloud catches up when the network returns")


@scene("usecases/stolen")
def stolen():
    node(K.laptop("lock"), 150, 146, 0.35, "Stolen laptop", "Strongroom stays locked")
    bb_node(K.badge("x"), 208, 104, 0.7)
    node(K.phone("rows_red"), 480, 156, 0.42, "Your phone")
    L((456, 118), (420, 64), (250, 54), (212, 106))
    K.text(332, 60, "revoke + wipe", "title")
    node(K.cloud(scale=0.7), 320, 238, 0.22, lift=0.1)
    bb_node(K.badge("ok"), 350, 220, 0.5)
    K.caption("data still restorable from your storages")


@scene("usecases/provider")
def provider():
    node(K.cloud(alpha_tone="#e3e8f2"), 130, 94, 0.3, "Provider A closed", lift=0.2)
    bb_node(K.badge("x"), 168, 66, 0.6)
    node(K.cloud(), 320, 94, 0.3, "Provider B", lift=0.2)
    floating_blocks(304, 116, 3, 1, lift=0.58)
    bb_node(K.badge("ok"), 358, 66, 0.6)
    node(K.disk(), 510, 112, 0.06, "Disk at home", rot=-15)
    bb_node(K.badge("ok"), 550, 78, 0.6)
    node(K.laptop("alert", scale=0.65), 320, 230, 0.23)
    L((320, 198), (320, 162))
    L((368, 206), (420, 186), (456, 162), (486, 140))
    K.caption("alert: 1 of 3 copies lost, repairing to a new storage")


@scene("usecases/fire")
def fire():
    h = K.house()
    node(h, 150, 176, 0.4, "Home", "PC, NAS and disks lost together")
    K.flame(0.9, at=(0.16, -0.12, 0.66), parent=h)
    K.flame(0.6, at=(-0.2, -0.08, 0.58), parent=h)
    L((206, 152), (262, 88), (398, 88), (452, 154))
    node(K.house(), 500, 176, 0.4, "Relatives, other city")
    bb_node(K.badge("ok"), 546, 138, 0.7)
    node(K.cloud(scale=0.7), 330, 220, 0.22, None, "plus a cloud bucket", lift=0.1, gap=14)
    bb_node(K.badge("ok"), 360, 202, 0.5)
    K.caption("placement rule: one copy in another place")


@scene("usecases/camera")
def camera():
    node(K.phone("photos"), 140, 150, 0.42, "Camera roll full")
    bb_node(K.camera_icon(), 174, 104, 0.7)
    L((180, 132), (224, 110), (280, 104), (316, 114))
    node(K.cloud(), 372, 120, 0.3, "Encrypted upload", lift=0.2)
    floating_blocks(356, 142, 3, 1, lift=0.58)
    lock_near(410, 90, lift=0.62, scale=0.9)
    L((420, 140), (464, 158), (492, 180), (506, 202))
    node(K.disk(), 528, 226, 0.06, None, "second copy verified", rot=-15, gap=18)
    bb_node(K.badge("ok"), 562, 200, 0.45)
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
    node(K.phone("tree"), 130, 150, 0.42, "New phone", "joined with a key")
    bb_node(K.key(scale=0.6, upright=False), 166, 108, 0.7, toward=0.4)
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
    bb_node(K.card(440, 40, 14, "blue600"), 388, 58, 0.6, toward=0.0)
    K.text(388, 63, 'You: "What is the cheapest place to keep the 2019 videos?"', "white")
    c = card_at(32, 96, 500, 148, r=14)
    ui(c, K.sparkle(), 58, 120)
    K.text(76, 125, "Assistant (MCP)", "title", "s")
    K.text(48, 150, "310 GB, read twice a year. Cold tier at provider C would cost about a third of", "sub", "s")
    K.text(48, 168, "the current hot bucket; restore takes hours and costs per GB.", "sub", "s")
    K.text(48, 194, "Proposed: move 2019 videos to provider C cold; keep one hot copy at home.", "row", "s")
    ui(c, K.card(92, 26, 13, "blue600"), 94, 221, toward=0.02)
    K.text(94, 225.3, "Confirm", "white")
    K.caption("Open, dated price data; nothing moves without your confirmation.")


@scene("usecases/sensitive")
def sensitive():
    node(K.phone("cipher"), 110, 150, 0.42, None, "no clear text on the phone")
    c = K.framed_card(216, 160, 14)
    K.billboard(c, 320, 138, 160 / 2 * K.PX * K.S.U.z + 0.1, toward=0.0)
    K.register_box("card:strong", c)
    K.text(320, 92, "Taxes/ (Strongroom)", "title")
    lk = K.padlock(scale=1.6)
    lk.location = K.card_point(c, 320, 134, 0.35) - Vector((0, 0, 0.27))
    K.register_box("ui:lock", lk)
    ui(c, K.ring(12, 0.005), 310.5, 192)
    ui(c, K.ring(18, 0.004, "#f3c98a"), 310.5, 192)
    ui(c, K.key(scale=0.55, upright=False), 320, 192, toward=0.07)
    L((436, 154), (466, 154), tone="grey", arrows=(), dash=7, gap=6, r=0.009, h=0.5)
    bb_node(K.badge("x"), 450, 154, 0.55)
    card_at(470, 120, 130, 68)
    K.text(535, 148, "AI assistant", "title")
    K.text(535, 168, "cannot see it", "sub")
    K.caption("opens only with a touch of your security key")


@scene("usecases/reader")
def reader():
    node(K.monitor("photos"), 150, 142, 0.4, "Desktop", "has the photos, makes thumbnails")
    L((208, 122), (240, 100), (264, 96), (290, 104))
    node(K.cloud(), 340, 112, 0.3, None, "thumbs/<folder>/<hash>.enc", lift=0.2, gap=16)
    floating_blocks(324, 134, 3, 1, lift=0.58)
    lock_near(380, 86, lift=0.62, scale=0.9)
    L((390, 128), (422, 144), (452, 148), (482, 148))
    node(K.phone("thumbs"), 510, 154, 0.42, "Phone", "previews, files are placeholders")
    K.caption("Thumbnails stay encrypted; the storage sees only ciphertext.")


# ============================================================ hero (1200 x 600)
@scene("hero", 1200, 600)
def hero():
    kx, ky = 600, 214
    glow = K.empty("glow")
    K.cyl(1.5, 0.004, K.mat("#f1f4fe", rough=1.0, sheen=0.0), parent=glow)
    K.place(glow, kx, ky + 44, 0.0)
    node(K.pedestal(0.8, 0.14), kx, ky + 44, 0.07)
    k = K.key(scale=2.6, upright=True)
    K.place(k, kx, ky - 6, 0.0, lift=0.8, rot_z=K.AZ_DEG)
    K.register_box("key", k)
    K.text(kx, 58, "Your keys", "hero_title")
    K.text(kx, 90, "never leave your devices", "hero_sub")
    big = 1.35
    nodes = [
        (130, 392, K.laptop("cipher", scale=1.3), 0.45, "Laptop", None, (190, 318)),
        (318, 420, K.shelf(), 0.56 * big, "Disks on a shelf", "offline, counted, verified", (394, 312)),
        (506, 436, K.bucket(), 0.35 * big, "S3 bucket", "hot copy, any provider", (562, 368)),
        (694, 436, K.archive(), 0.25 * big, "Cold archive", "never read by surprise", (744, 376)),
        (882, 420, K.nas(), 0.26 * big, "NAS at home", "or a friend's, or a server", (936, 356)),
        (1070, 392, K.phone("cipher", scale=1.3), 0.55, "Phone", None, (1098, 302)),
    ]
    for x, y, root, hc, title, sub, lock in nodes:
        if not root.name.startswith(("laptop", "phone")):
            root.scale = (big,) * 3
        node(root, x, y, hc, title, sub, gap=24)
        lock_near(lock[0], lock[1], lift=0.9, scale=1.2)
    for x, y, root, hc, title, sub, lock in nodes:
        dx, dy = x - kx, y - ky
        n = (dx * dx + dy * dy) ** 0.5
        sx, sy = kx + dx / n * 95, ky + dy / n * 95
        ex, ey = x, y - 74
        L((sx, sy), (kx + dx / n * 170, ky + dy / n * 170), (ex, ey - 80), (ex, ey), h=0.45, dash=8, gap=6, r=0.014)
