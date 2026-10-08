#!/usr/bin/env python3
"""Generate the 18 Varsto illustration SVGs with one consistent design system."""
import os, re, sys

OUT = "./website/public/assets/img"

CLOUD = "M-38 16 A16 16 0 0 1 -30 -14 A22 22 0 0 1 10 -24 A19 19 0 0 1 40 -4 A14 14 0 0 1 38 16 Z"
PLANE = ("M21 16v-2l-8-5V3.5c0-.83-.67-1.5-1.5-1.5S10 2.67 10 3.5V9l-8 5v2l8-2.5V19l-2 1.5V22"
         "l3.5-1 3.5 1v-1.5L13 19v-5.5l8 2.5z")

# ---- reusable defs -------------------------------------------------------
BASE_DEFS = [
 '<linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#f8faff"/><stop offset="1" stop-color="#eef2ff"/></linearGradient>',
 '<pattern id="dots" width="18" height="18" patternUnits="userSpaceOnUse"><circle cx="9" cy="9" r="1" fill="#2b57d6" fill-opacity=".08"/></pattern>',
 '<linearGradient id="pg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#3d6ef2"/><stop offset="1" stop-color="#1b3a9a"/></linearGradient>',
 '<linearGradient id="wg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset="1" stop-color="#f1f4ff"/></linearGradient>',
 '<linearGradient id="sg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#f7f9ff"/><stop offset="1" stop-color="#dbe4ff"/></linearGradient>',
 '<linearGradient id="dg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#4b5a73"/><stop offset="1" stop-color="#1f2a3d"/></linearGradient>',
 '<filter id="sh" x="-20%" y="-20%" width="140%" height="160%"><feDropShadow dx="0" dy="2" stdDeviation="2.5" flood-color="#1b3a9a" flood-opacity=".14"/></filter>',
 '<marker id="ah" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 1 L9 5 L0 9 z" fill="#8aa9ff"/></marker>',
 '<marker id="ahp" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M0 1 L9 5 L0 9 z" fill="#2b57d6"/></marker>',
]

SYMBOLS = {
 "cb": '<pattern id="cb" width="28" height="28" patternUnits="userSpaceOnUse"><rect x="2" y="2" width="10" height="10" rx="2.5" fill="#8aa9ff" fill-opacity=".6"/><rect x="16" y="2" width="10" height="10" rx="2.5" fill="#8aa9ff" fill-opacity=".3"/><rect x="2" y="16" width="10" height="10" rx="2.5" fill="#8aa9ff" fill-opacity=".38"/><rect x="16" y="16" width="10" height="10" rx="2.5" fill="#8aa9ff" fill-opacity=".7"/></pattern>',
 "lock": '<g id="lock"><path d="M-5 -1 V-6.5 a5 5 0 0 1 10 0 V-1" fill="none" stroke="#1b3a9a" stroke-width="2.4" stroke-linecap="round"/><rect x="-8.5" y="-1.5" width="17" height="13.5" rx="3.2" fill="url(#pg)"/><circle cy="4" r="1.9" fill="#fff"/><rect x="-.9" y="4.5" width="1.8" height="3.6" rx=".9" fill="#fff"/></g>',
 "lockb": '<g id="lockb"><circle r="14" fill="#fff" stroke="#cbd5e1" stroke-width="1.5" filter="url(#sh)"/><use href="#lock" y="-3"/></g>',
 "ok": '<g id="ok"><circle r="11.5" fill="#fff"/><circle r="9.5" fill="#2bb673"/><path d="M-4.5 .2 L-1.2 3.4 L5 -3.6" stroke="#fff" stroke-width="2.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/></g>',
 "x": '<g id="x"><circle r="11.5" fill="#fff"/><circle r="9.5" fill="#e0535a"/><path d="M-3.6 -3.6 L3.6 3.6 M3.6 -3.6 L-3.6 3.6" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/></g>',
 "key": '<g id="key"><circle cx="-9" r="6.5" fill="none" stroke="#2b57d6" stroke-width="3"/><path d="M-2.5 0 H16 M10 0 v5 M15 0 v4" stroke="#2b57d6" stroke-width="3" fill="none" stroke-linecap="round"/></g>',
 "keyb": '<g id="keyb"><circle r="14" fill="#fff" stroke="#cbd5e1" stroke-width="1.5" filter="url(#sh)"/><use href="#key" transform="scale(.8)"/></g>',
 "laptop": '<g id="laptop" filter="url(#sh)"><rect x="-50" y="-36" width="100" height="66" rx="7" fill="url(#dg)"/><rect x="-45" y="-31" width="90" height="54" rx="3" fill="url(#sg)"/><rect x="-62" y="30" width="124" height="8" rx="4" fill="#cbd5e1"/><rect x="-12" y="30" width="24" height="3" rx="1.5" fill="#e8edf7"/></g>',
 "monitor": '<g id="monitor" filter="url(#sh)"><rect x="-50" y="-38" width="100" height="66" rx="7" fill="url(#dg)"/><rect x="-45" y="-33" width="90" height="56" rx="3" fill="url(#sg)"/><rect x="-7" y="28" width="14" height="10" fill="#94a3b8"/><rect x="-26" y="36" width="52" height="5" rx="2.5" fill="#cbd5e1"/></g>',
 "phone": '<g id="phone" filter="url(#sh)"><rect x="-22" y="-42" width="44" height="84" rx="9" fill="url(#dg)"/><rect x="-19" y="-36" width="38" height="70" rx="5" fill="url(#sg)"/><rect x="-6" y="-40.5" width="12" height="2.5" rx="1.25" fill="#7c8aa3"/><rect x="-8" y="37" width="16" height="2.5" rx="1.25" fill="#7c8aa3"/></g>',
 "tablet": '<g id="tablet" filter="url(#sh)"><rect x="-33" y="-43" width="66" height="86" rx="9" fill="url(#dg)"/><rect x="-29" y="-37" width="58" height="74" rx="4" fill="url(#sg)"/><circle cy="-40" r="1.3" fill="#7c8aa3"/></g>',
 "cloud": f'<g id="cloud" filter="url(#sh)"><path transform="translate(-3 10)" d="{CLOUD}" fill="url(#wg)" stroke="#8aa9ff" stroke-width="2" stroke-linejoin="round"/></g>',
 "disk": '<g id="disk" filter="url(#sh)"><rect x="-40" y="-15" width="80" height="30" rx="6" fill="url(#wg)" stroke="#cbd5e1" stroke-width="2"/><circle cx="-22" r="8" fill="none" stroke="#cbd5e1" stroke-width="2"/><circle cx="-22" r="2" fill="#cbd5e1"/><path d="M-8 -4 h14 M-8 4 h10" stroke="#cbd5e1" stroke-width="2" stroke-linecap="round"/><circle cx="26" r="6" fill="#2bb673" fill-opacity=".22"/><circle cx="26" r="3" fill="#2bb673"/></g>',
 "nas": '<g id="nas" filter="url(#sh)"><rect x="-40" y="-26" width="80" height="52" rx="7" fill="url(#wg)" stroke="#cbd5e1" stroke-width="2"/><rect x="-30" y="-16" width="60" height="12" rx="3" fill="#e2e8f0"/><rect x="-30" y="2" width="60" height="12" rx="3" fill="#e2e8f0"/><circle cx="22" cy="-10" r="5" fill="#2bb673" fill-opacity=".25"/><circle cx="22" cy="-10" r="2.5" fill="#2bb673"/><circle cx="22" cy="8" r="2.5" fill="#2bb673"/></g>',
 "usb": '<g id="usb" filter="url(#sh)"><rect x="-34" y="-12" width="52" height="24" rx="6" fill="url(#pg)"/><rect x="18" y="-8" width="18" height="16" rx="2" fill="#cbd5e1" stroke="#94a3b8" stroke-width="1.5"/><rect x="22" y="-4" width="4" height="3" fill="#64748b"/><rect x="22" y="1" width="4" height="3" fill="#64748b"/><circle cx="-24" r="2.5" fill="#8aa9ff"/></g>',
 "house": '<g id="house" filter="url(#sh)"><path d="M-34 -10 V34 H34 V-10" fill="url(#wg)" stroke="#cbd5e1" stroke-width="2"/><path d="M-44 -2 L0 -38 L44 -2" fill="none" stroke="#8aa9ff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/><rect x="-9" y="10" width="18" height="24" rx="2" fill="url(#pg)"/><rect x="-26" y="2" width="12" height="12" rx="2" fill="#dbe4ff" stroke="#8aa9ff" stroke-width="1.5"/><rect x="14" y="2" width="12" height="12" rx="2" fill="#dbe4ff" stroke="#8aa9ff" stroke-width="1.5"/></g>',
 "flame": '<g id="flame"><path d="M0 0 C-16 -6 -20 -26 -8 -40 C-8 -30 -3 -24 2 -22 C1 -34 8 -42 16 -48 C12 -34 26 -24 24 -10 C22 2 12 6 0 0Z" fill="#e0535a"/><path d="M4 -4 C-5 -8 -6 -20 1 -28 C1 -21 5 -18 7 -16 C7 -23 11 -26 14 -30 C12 -21 18 -16 16 -9 C15 -3 10 -1 4 -4Z" fill="#f6b4b7"/></g>',
 "file": '<g id="file" filter="url(#sh)"><path d="M-14 -20 h18 l10 10 v30 h-28 z" fill="url(#wg)" stroke="#8aa9ff" stroke-width="2" stroke-linejoin="round"/><path d="M4 -20 v10 h10" fill="none" stroke="#8aa9ff" stroke-width="2" stroke-linejoin="round"/></g>',
 "folder": '<g id="folder" filter="url(#sh)"><path d="M-70 -34 h44 l10 10 h86 a6 6 0 0 1 6 6 v52 a6 6 0 0 1 -6 6 h-140 a6 6 0 0 1 -6 -6 v-62 a6 6 0 0 1 6 -6z" fill="url(#wg)" stroke="#8aa9ff" stroke-width="2" stroke-linejoin="round"/></g>',
 "fi": '<g id="fi"><path d="M-6 -9 h8 l4 4 v14 h-12 z" fill="#fff" stroke="#8aa9ff" stroke-width="1.5" stroke-linejoin="round"/><path d="M2 -9 v4 h4" fill="none" stroke="#8aa9ff" stroke-width="1.5"/></g>',
 "fo": '<g id="fo"><path d="M-9 -7 h6 l2 2 h9 a1.5 1.5 0 0 1 1.5 1.5 v9 a1.5 1.5 0 0 1 -1.5 1.5 h-17 a1.5 1.5 0 0 1 -1.5 -1.5 v-11 a1.5 1.5 0 0 1 1.5 -1.5z" fill="#dbe4ff" stroke="#8aa9ff" stroke-width="1.5" stroke-linejoin="round"/></g>',
 "pc": f'<g id="pc"><path transform="translate(-.5 -1.5) scale(.2)" d="{CLOUD}" fill="none" stroke="#8aa9ff" stroke-width="9" stroke-linejoin="round"/></g>',
 "plane": f'<g id="plane"><path transform="rotate(90) scale(1.7) translate(-12 -12)" d="{PLANE}" fill="#8aa9ff"/></g>',
 "snow": '<g id="snow"><path d="M0 -13 V13 M-11.3 -6.5 L11.3 6.5 M-11.3 6.5 L11.3 -6.5" stroke="#8aa9ff" stroke-width="2" stroke-linecap="round"/><path d="M-3 -9 L0 -6 L3 -9 M-3 9 L0 6 L3 9 M-10.5 -1.5 L-7 -3 L-7 -6 M10.5 1.5 L7 3 L7 6 M-10.5 1.5 L-7 3 L-7 6 M10.5 -1.5 L7 -3 L7 -6" fill="none" stroke="#8aa9ff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></g>',
 "cam": '<g id="cam"><circle r="14" fill="#fff" stroke="#cbd5e1" stroke-width="1.5" filter="url(#sh)"/><rect x="-8" y="-5" width="16" height="11" rx="2.5" fill="url(#pg)"/><rect x="-3.5" y="-7.5" width="7" height="3" rx="1" fill="#1b3a9a"/><circle cy=".5" r="3" fill="#fff"/><circle cy=".5" r="1.4" fill="#2b57d6"/></g>',
 "seal": '<g id="seal"><circle r="19" fill="#fff" stroke="#cbd5e1" stroke-width="1.5" filter="url(#sh)"/><circle r="15" fill="url(#pg)"/><circle r="11" fill="none" stroke="#fff" stroke-opacity=".45" stroke-width="1"/></g>',
}
DEPS = {"lockb": ["lock"], "keyb": ["key"]}

STYLE = ("<style>text{font-family:system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}"
         ".t{font-size:14px;font-weight:600;fill:#334155}.s{font-size:12px;fill:#6b7a90}"
         ".n{font-size:12px;fill:#334155}.w{font-size:12px;font-weight:600;fill:#fff}"
         ".d{stroke:#8aa9ff;stroke-width:2;stroke-dasharray:6 5;fill:none;stroke-linecap:round;marker-end:url(#ah)}"
         ".dd{stroke:#8aa9ff;stroke-width:2;stroke-dasharray:6 5;fill:none;stroke-linecap:round;marker-end:url(#ah);marker-start:url(#ah)}"
         ".l{stroke:#2b57d6;stroke-width:2;fill:none;stroke-linecap:round;marker-end:url(#ahp);marker-start:url(#ahp)}"
         ".tr{stroke:#cbd5e1;stroke-width:2;stroke-dasharray:7 6;fill:none;stroke-linecap:round}"
         ".m{text-anchor:middle}.e{text-anchor:end}</style>")

# ---- helpers ---------------------------------------------------------------
def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def T(x, y, s, cls="s", anchor="m"):
    a = {"m": " m", "e": " e", "s": ""}[anchor]
    return f'<text x="{x}" y="{y}" class="{cls}{a}">{esc(s)}</text>'

def U(sym, x, y, extra=""):
    return f'<use href="#{sym}" x="{x}" y="{y}"{(" " + extra) if extra else ""}/>'

def P(d, cls="d"):
    return f'<path class="{cls}" d="{d}"/>'

def card(x, y, w, h, rx=12, stroke="#cbd5e1", sw=2, fill="url(#wg)"):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}" filter="url(#sh)"/>'

def blocks(x0, y0, cols, rows, s=9, g=5, hi=None):
    """Ciphertext blocks: small rounded squares in light blue with varied opacity."""
    ops = [".65", ".35", ".5", ".8", ".3", ".55"]
    out, i = [], 0
    for r in range(rows):
        for c in range(cols):
            x, y = x0 + c * (s + g), y0 + r * (s + g)
            if hi is not None and (c, r) == hi:
                out.append(f'<rect x="{x}" y="{y}" width="{s}" height="{s}" rx="2.5" fill="#2b57d6"/>')
            else:
                out.append(f'<rect x="{x}" y="{y}" width="{s}" height="{s}" rx="2.5" fill="#8aa9ff" fill-opacity="{ops[i % len(ops)]}"/>')
            i += 1
    return "".join(out)

def caption(*lines):
    if len(lines) == 1:
        return T(320, 294, lines[0])
    return T(320, 278, lines[0]) + T(320, 296, lines[1])

def pill(x, y, w, h, text, fill="url(#pg)", cls="w", stroke=None):
    st = f' stroke="{stroke}" stroke-width="1.5"' if stroke else ""
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{h/2}" fill="{fill}"{st} filter="url(#sh)"/>'
            + T(x + w / 2, y + h / 2 + 4.3, text, cls))

def build(aria, body):
    used = set(re.findall(r'href="#([a-z]+)"', body)) | set(re.findall(r'url\(#([a-z]+)\)', body))
    changed = True
    while changed:
        changed = False
        for k in list(used):
            for d in DEPS.get(k, []):
                if d not in used:
                    used.add(d); changed = True
    defs = BASE_DEFS + [SYMBOLS[k] for k in SYMBOLS if k in used]
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 320" width="640" height="320" role="img" '
            f'aria-label="{esc(aria)}">\n<defs>' + "".join(defs) + "</defs>\n" + STYLE +
            '\n<rect width="640" height="320" fill="url(#bg)"/><rect width="640" height="320" fill="url(#dots)"/>\n'
            + body + "\n</svg>\n")

FILES = {}

# ========================= FEATURES =========================================
FILES["features/ledger"] = ("Signed ledger: devices that are never online together still converge", "".join([
 U("laptop", 100, 86), blocks(68, 64, 5, 3, hi=(2, 1)), T(100, 142, "Laptop", "t"),
 U("cloud", 320, 76), U("lockb", 354, 56), T(320, 126, "Your storage", "t"),
 U("monitor", 540, 84), blocks(508, 62, 5, 3, hi=(2, 1)), T(540, 142, "Desktop", "t"),
 P("M156 72 C 200 58, 232 58, 266 68"), P("M376 68 C 410 58, 444 58, 484 72"),
 card(110, 160, 420, 30, 8), T(124, 180, '#41 laptop · stored block 7f3a on "box"', "n", "s"),
 f'<rect x="462" y="167" width="56" height="16" rx="8" fill="#2bb673" fill-opacity=".16"/><text x="490" y="179" class="m" style="font-size:11px;font-weight:600;fill:#1f8f57">signed</text>',
 card(110, 198, 420, 30, 8), T(124, 218, "#42 desktop · fetched 7f3a, hash verified", "n", "s"),
 f'<rect x="462" y="205" width="56" height="16" rx="8" fill="#2bb673" fill-opacity=".16"/><text x="490" y="217" class="m" style="font-size:11px;font-weight:600;fill:#1f8f57">signed</text>',
 caption("Each device keeps a signed, encrypted ledger of where every block is.",
         "Devices that never meet still converge."),
]))

FILES["features/transferrer"] = ("Transferrer: removable media carries what the other device lacks", "".join([
 U("laptop", 110, 110), blocks(78, 88, 5, 3), T(110, 168, "Home PC", "t"),
 U("monitor", 530, 108), blocks(498, 86, 5, 3), T(530, 168, "Office PC", "t"),
 f'<use href="#usb" transform="translate(320 96) scale(1.3)"/>', U("lockb", 290, 70),
 blocks(314, 58, 3, 1, s=10, g=5),
 T(320, 140, "Transferrer", "t"), T(320, 158, "USB stick or disk marked as carrier"),
 P("M158 96 C 204 84, 238 80, 272 86"), P("M370 86 C 404 80, 440 84, 478 96"),
 caption("Carries only the encrypted blocks the other device still lacks.",
         "Both ends have it? The block is removed from the stick. No cloud needed."),
]))

FILES["features/untrusted"] = ("Untrusted replica: a device that holds encrypted copies it cannot open", "".join([
 U("laptop", 110, 112),
 '<path d="M78 94 h46 M78 104 h32 M78 114 h46 M78 124 h22" stroke="#94a3b8" stroke-width="3" stroke-linecap="round"/>',
 U("keyb", 150, 80), T(110, 170, "You", "t"), T(110, 188, "holds the keys"),
 card(250, 56, 140, 126, 12, stroke="#8aa9ff"),
 '<rect x="262" y="68" width="116" height="102" rx="6" fill="url(#cb)"/>',
 U("lockb", 388, 58), T(320, 206, "Shared storage", "t"),
 U("nas", 520, 116), U("ok", 556, 92), T(520, 170, "Your friend's NAS", "t"), T(520, 188, "stores and verifies, cannot open"),
 P("M160 110 L 242 110", "dd"), P("M398 110 L 474 110"),
 caption("A replica token lets a device hold and verify your copies without any key to read them."),
]))

def sel_row(y, icon, name, status, done):
    out = [U(icon, 274, y), T(292, y + 5, name, "t", "s"), T(540, y + 4.5, status, "s", "e")]
    out.append(f'<use href="#ok" transform="translate(558 {y}) scale(.85)"/>' if done else U("pc", 558, y + 1))
    return "".join(out)

FILES["features/selective"] = ("Selective sync with placeholders", "".join([
 U("phone", 110, 140),
 '<rect x="93" y="112" width="34" height="9" rx="2" fill="#8aa9ff" fill-opacity=".3"/><rect x="93" y="126" width="34" height="9" rx="2" fill="#8aa9ff" fill-opacity=".75"/><rect x="93" y="140" width="34" height="9" rx="2" fill="#8aa9ff" fill-opacity=".3"/><rect x="93" y="154" width="34" height="9" rx="2" fill="#8aa9ff" fill-opacity=".75"/>',
 T(110, 206, "Phone", "t"),
 card(250, 52, 330, 184),
 '<path d="M262 100 H568 M262 144 H568 M262 188 H568" stroke="#e8edf7" stroke-width="1.5"/>',
 sel_row(78, "fi", "holiday-2025.mp4", "placeholder · 2.1 GB", False),
 sel_row(122, "fi", "contract.pdf", "downloaded", True),
 sel_row(166, "fo", "raw-photos/", "placeholder · 48 GB", False),
 sel_row(210, "fi", "notes.md", "downloaded", True),
 P("M138 118 C 176 100, 206 92, 244 86"),
 caption("Selective sync: you see everything, download only what you open,",
         "free space again with one tap."),
]))

FILES["features/sharing"] = ("Sharing a folder with another user by its key", "".join([
 U("laptop", 110, 130), blocks(78, 108, 5, 3), T(110, 188, "You", "t"),
 U("laptop", 530, 130), blocks(498, 108, 5, 3), T(530, 188, "Another Varsto user", "t"),
 U("folder", 320, 128), '<rect x="258" y="112" width="124" height="46" rx="5" fill="url(#cb)"/>',
 T(320, 188, "project/", "t"),
 P("M164 128 L 238 128"), P("M402 128 L 476 128"),
 P("M150 86 C 220 10, 420 10, 486 86"),
 '<rect x="262" y="18" width="116" height="24" rx="12" fill="#fff" stroke="#8aa9ff" stroke-width="1.5" filter="url(#sh)"/>',
 '<use href="#key" transform="translate(286 30) scale(.75)"/>', '<text x="340" y="34.5" class="m" style="font-size:13px;font-weight:600;fill:#2b57d6">folder key</text>',
 caption("Share a folder or a file by handing over its key. The other user syncs and reads it",
         "with their own devices. Nothing else of your vault is reachable with that key."),
]))

def os_card(y, name, where):
    return card(40, y, 220, 40, 10) + U("ok", 66, y + 20) + T(86, y + 25, name, "t", "s") + T(244, y + 24.5, where, "s", "e")

menu_icons = {
 134: '<rect x="394" y="128" width="11" height="11" rx="2" fill="none" stroke="#8aa9ff" stroke-width="1.6"/>',
 158: '<path d="M395 158 a5 5 0 0 1 9 -3 M404 152 v4 h-4 M404 158 a5 5 0 0 1 -9 3 M395 164 v-4 h4" fill="none" stroke="#8aa9ff" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>',
 182: '<path d="M396 177 v10 M403 177 v10" stroke="#8aa9ff" stroke-width="2.2" stroke-linecap="round"/>',
 206: '<path d="M399.5 212 v-10 M395.5 206 l4 -4 l4 4" fill="none" stroke="#8aa9ff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
}
FILES["features/background"] = ("Background app on every desktop", "".join([
 '<rect x="16" y="20" width="608" height="30" rx="8" fill="url(#dg)" filter="url(#sh)"/>',
 '<rect x="30" y="31" width="40" height="8" rx="4" fill="#64748b"/><rect x="78" y="31" width="30" height="8" rx="4" fill="#64748b"/><rect x="116" y="31" width="36" height="8" rx="4" fill="#64748b"/>',
 '<rect x="498" y="23" width="24" height="24" rx="6" fill="#fff" fill-opacity=".16"/><rect x="502" y="27" width="16" height="16" rx="4" fill="url(#pg)"/><circle cx="510" cy="35" r="3" fill="#fff"/>',
 '<circle cx="546" cy="35" r="4.5" fill="#94a3b8"/><circle cx="566" cy="35" r="4.5" fill="#94a3b8"/><rect x="584" y="31" width="28" height="8" rx="4" fill="#94a3b8"/>',
 card(380, 56, 244, 172, 10), '<path d="M504 56 l6 -7 l6 7z" fill="#fff" stroke="#cbd5e1" stroke-width="1.5"/><path d="M505.5 56.5 h9" stroke="#fff" stroke-width="3"/>',
 '<circle cx="402" cy="76" r="5" fill="#2bb673"/>', T(414, 81, "Varsto", "t", "s"), T(396, 100, "Up to date · last sync 12 s ago", "s", "s"),
 '<path d="M392 112 H612" stroke="#e8edf7" stroke-width="1.5"/>',
 "".join(menu_icons.values()),
 T(414, 138, "Open Varsto", "n", "s"), T(414, 162, "Sync now", "n", "s"), T(414, 186, "Pause syncing", "n", "s"), T(414, 210, "Check for updates", "n", "s"),
 os_card(72, "macOS", "menu bar"), os_card(124, "Windows", "system tray"), os_card(176, "Linux", "tray or indicator"),
 caption("A menu-bar or tray app watches your folders, syncs within seconds, and updates itself",
         "with one click. macOS, Windows and Linux: the same core, the same local interface."),
]))

FILES["features/cold"] = ("Cold storage and cost-aware placement", "".join([
 U("laptop", 100, 116), blocks(68, 94, 5, 3), T(100, 174, "Laptop", "t"),
 U("cloud", 320, 100), blocks(298, 93, 3, 1, s=10, g=6), T(320, 152, "Hot storage", "t"), T(320, 170, "S3, NAS: read and write"),
 '<g transform="translate(520 104)">' + card(-40, -26, 80, 52, 7, stroke="#8aa9ff") + '<path d="M-40 -12 H40" stroke="#8aa9ff" stroke-width="2"/><use href="#snow" y="7"/></g>',
 T(520, 152, "Cold archive", "t"), T(520, 170, "Glacier: written,"), T(520, 188, "never read by surprise"),
 P("M156 100 C 200 86, 236 82, 268 92"), P("M372 90 C 410 82, 442 86, 476 98"),
 '<rect x="376" y="106" width="100" height="20" rx="10" fill="#fff" stroke="#8aa9ff" stroke-width="1.5"/><text x="426" y="120" class="m" style="font-size:11px;font-weight:600;fill:#2b57d6">ask before restore</text>',
 caption("Per-storage prices for upload, download and restore steer where data is written and read.",
         "Cold storage is never read without an explicit confirmation that shows cost and delay."),
]))

def shelf_disk(y, letter):
    return U("disk", 145, y) + f'<text x="160" y="{y + 4}" class="m" style="font-size:11px;font-weight:700;fill:#2b57d6">{letter}</text>'

FILES["features/disks"] = ("Removable disk pool", "".join([
 card(70, 56, 150, 140, 12), '<path d="M78 105 H212 M78 151 H212" stroke="#e8edf7" stroke-width="3"/>',
 shelf_disk(82, "A"), shelf_disk(128, "A"), shelf_disk(174, "B"), U("lockb", 214, 60),
 T(145, 222, "Disks on a shelf", "t"), T(145, 240, "group A at home, group B elsewhere"),
 U("laptop", 420, 116), blocks(388, 94, 5, 3),
 '<path d="M482 150 C 492 150, 492 141, 500 141" fill="none" stroke="#94a3b8" stroke-width="2"/>',
 card(500, 130, 56, 22, 5), '<rect x="508" y="137" width="9" height="8" rx="1" fill="#64748b"/><rect x="522" y="137" width="9" height="8" rx="1" fill="#64748b"/><rect x="536" y="137" width="9" height="8" rx="1" fill="#64748b"/>',
 T(440, 178, "PC with a USB dock", "t"),
 P("M228 118 C 290 98, 324 96, 362 104"),
 caption("Old hard drives become counted, verified copies: attach, fill, eject, re-check next time.",
         "A folder can live only on disks, replicated as many times as you choose."),
]))

FILES["features/mobile"] = ("Mobile apps", "".join([
 U("cloud", 320, 66), U("lockb", 354, 46),
 U("phone", 200, 152), blocks(186, 126, 3, 4, s=8, g=4), U("lockb", 226, 112),
 T(200, 220, "Phone", "t"), T(200, 238, "nothing stored in clear text"),
 U("tablet", 440, 152), '<rect x="418" y="124" width="44" height="26" rx="3" fill="#8aa9ff" fill-opacity=".4"/><path d="M418 160 h44 M418 169 h32 M418 178 h40" stroke="#94a3b8" stroke-width="2.5" stroke-linecap="round"/>',
 T(440, 220, "Tablet", "t"),
 P("M290 84 C 258 96, 236 106, 218 118", "dd"), P("M350 84 C 382 96, 404 104, 418 114", "dd"),
 caption("Android and iOS apps run the same encrypted core.",
         "Files are decrypted only when you open them."),
]))

# ========================= USE CASES ========================================
FILES["usecases/plane"] = ("Two devices on a plane sync over the phone hotspot; the cloud is crossed out until landing", "".join([
 U("plane", 46, 40), P("M72 40 H 600", "tr"), T(72, 62, "in flight, no internet", "s", "s"),
 U("phone", 200, 160), blocks(186, 134, 3, 4, s=8, g=4), T(200, 228, "Phone", "t"),
 U("laptop", 440, 158), blocks(408, 136, 5, 3), T(440, 220, "Laptop", "t"),
 P("M226 136 C 268 96, 348 96, 386 130", "l"), T(320, 96, "hotspot / LAN, direct transfer"),
 U("file", 320, 160), U("lockb", 338, 146),
 U("cloud", 320, 252, 'opacity=".75"'), U("x", 354, 236), T(320, 296, "cloud catches up when the network returns"),
]))

FILES["usecases/stolen"] = ("A stolen laptop: Strongroom stays locked, the device is revoked and wiped from another device", "".join([
 U("laptop", 150, 146), '<use href="#lock" transform="translate(150 134) scale(1.6)"/>',
 '<path d="M128 164 h44" stroke="#94a3b8" stroke-width="3" stroke-linecap="round" stroke-dasharray="4 4"/>',
 U("x", 198, 112), T(150, 210, "Stolen laptop", "t"), T(150, 228, "Strongroom stays locked"),
 U("phone", 480, 156), '<rect x="466" y="130" width="28" height="9" rx="2" fill="#8aa9ff" fill-opacity=".35"/><rect x="466" y="145" width="28" height="9" rx="2" fill="#e0535a" fill-opacity=".85"/><rect x="466" y="160" width="28" height="9" rx="2" fill="#8aa9ff" fill-opacity=".35"/><rect x="466" y="175" width="28" height="9" rx="2" fill="#8aa9ff" fill-opacity=".35"/>',
 T(480, 224, "Your phone", "t"),
 P("M456 118 C 420 68, 250 58, 208 106"), T(332, 64, "revoke + wipe", "t"),
 U("cloud", 320, 252), U("ok", 354, 236), T(320, 296, "data still restorable from your storages"),
]))

FILES["usecases/provider"] = ("One provider shuts down; copies exist elsewhere and the app repairs and drains", "".join([
 U("cloud", 130, 116, 'opacity=".55"'), U("x", 164, 96), T(130, 166, "Provider A closed", "t"),
 U("cloud", 320, 116), blocks(298, 109, 3, 1, s=10, g=6), U("ok", 354, 96), T(320, 166, "Provider B", "t"),
 U("disk", 510, 118), U("ok", 544, 96), T(510, 166, "Disk at home", "t"),
 U("laptop", 320, 232), '<rect x="282" y="212" width="76" height="14" rx="4" fill="#e0535a" fill-opacity=".14"/><circle cx="291" cy="219" r="3.5" fill="#e0535a"/><path d="M300 219 h30" stroke="#e0535a" stroke-width="2.5" stroke-linecap="round" stroke-opacity=".6"/>',
 blocks(282, 232, 5, 1, s=8, g=5),
 P("M320 190 L 320 148"), P("M374 204 C 420 182, 460 160, 488 140"),
 T(320, 296, "alert: 1 of 3 copies lost, repairing to a new storage"),
]))

FILES["usecases/fire"] = ("A house on fire; every file also has a copy in another city", "".join([
 '<use href="#flame" transform="translate(166 142)"/><use href="#flame" transform="translate(132 154) scale(.7)"/>',
 U("house", 150, 172), T(150, 236, "Home", "t"), T(150, 254, "PC, NAS and disks lost together"),
 P("M200 150 C 260 88, 400 88, 452 152"), T(330, 92, "placement rule: one copy in another place"),
 U("house", 500, 172), U("ok", 540, 140), T(500, 236, "Relatives, other city", "t"),
 U("cloud", 330, 222), U("ok", 364, 204), T(330, 270, "plus a cloud bucket"),
]))

def photo_grid(x0, y0, cols, rows, s, g):
    ops = [".55", ".85", ".4", ".7", ".5", ".9", ".35"]
    out = []
    i = 0
    for r in range(rows):
        for c in range(cols):
            out.append(f'<rect x="{x0 + c * (s + g)}" y="{y0 + r * (s + g)}" width="{s}" height="{s}" rx="1.5" fill="#8aa9ff" fill-opacity="{ops[i % len(ops)]}"/>')
            i += 1
    return "".join(out)

FILES["usecases/camera"] = ("A phone camera roll uploads encrypted and frees space once copies are verified", "".join([
 U("phone", 140, 150), photo_grid(124, 118, 3, 5, 10, 2),
 '<rect x="124" y="180" width="34" height="4" rx="2" fill="#e2e8f0"/><rect x="124" y="180" width="32" height="4" rx="2" fill="#e0535a"/>',
 U("cam", 168, 112), T(140, 216, "Camera roll full", "t"),
 P("M172 136 C 220 110, 280 104, 318 112"),
 U("cloud", 370, 120), blocks(348, 113, 3, 1, s=10, g=6), U("lockb", 404, 100), T(370, 170, "Encrypted upload", "t"),
 P("M414 134 C 460 150, 490 175, 506 204"),
 U("disk", 520, 224), U("ok", 552, 202), T(520, 258, "second copy verified"),
 caption('"Free up space" deletes originals only after the policy is met and verified.'),
]))

def tree_row(y, indent, icon, name, size, status, done, top=False):
    x = 262 + indent
    out = [U(icon, x, y), T(x + 16, y + 5 if top else y + 4.5, name, "t" if top else "n", "s"),
           T(470, y + 4.5, size, "s", "e"), T(556, y + 4.5, status, "s", "e")]
    if done:
        out.append(f'<use href="#ok" transform="translate(572 {y}) scale(.85)"/>')
    elif status:
        out.append(U("pc", 572, y + 1))
    return "".join(out)

FILES["usecases/newdevice"] = ("A new small phone shows the whole tree as placeholders and downloads only what is needed", "".join([
 U("phone", 130, 150),
 '<rect x="114" y="122" width="34" height="8" rx="2" fill="#8aa9ff" fill-opacity=".3"/><rect x="120" y="135" width="28" height="8" rx="2" fill="#8aa9ff" fill-opacity=".3"/><rect x="120" y="148" width="28" height="8" rx="2" fill="#8aa9ff" fill-opacity=".75"/><rect x="114" y="161" width="34" height="8" rx="2" fill="#8aa9ff" fill-opacity=".75"/><rect x="114" y="174" width="34" height="8" rx="2" fill="#8aa9ff" fill-opacity=".3"/>',
 U("keyb", 160, 114), T(130, 216, "New phone", "t"), T(130, 234, "joined with a key"),
 card(240, 50, 350, 200),
 '<path d="M266 88 V 148" stroke="#e2e8f0" stroke-width="2" stroke-linecap="round"/>',
 tree_row(76, 0, "fo", "Photos/", "", "", False, top=True),
 tree_row(106, 24, "fo", "2019/", "48 GB", "placeholder", False),
 tree_row(136, 24, "fo", "2024/", "31 GB", "placeholder", False),
 tree_row(166, 24, "fo", "2026/", "2.1 GB", "downloaded", True),
 tree_row(196, 0, "fo", "Documents/", "400 MB", "downloaded", True, top=True),
 tree_row(226, 0, "fo", "Video/", "1.2 TB", "placeholder", False, top=True),
 P("M160 150 C 190 140, 210 130, 234 120"),
 caption("A 128 GB phone can see a 2 TB vault. Tap a file to fetch it."),
]))

FILES["usecases/cheapest"] = ("An assistant compares storage prices from open data and proposes a move the user confirms", "".join([
 '<rect x="168" y="34" width="440" height="40" rx="14" fill="url(#pg)" filter="url(#sh)"/>',
 '<text x="388" y="59" class="m" style="font-size:13px;font-weight:600;fill:#fff">You: "What is the cheapest place to keep the 2019 videos?"</text>',
 card(32, 90, 500, 148, 14),
 '<circle cx="58" cy="114" r="10" fill="url(#pg)"/><path d="M58 108 l1.6 4.4 l4.4 1.6 l-4.4 1.6 l-1.6 4.4 l-1.6 -4.4 l-4.4 -1.6 l4.4 -1.6z" fill="#fff"/>',
 T(76, 119, "Assistant (MCP)", "t", "s"),
 T(48, 144, "310 GB, read twice a year. Cold tier at provider C would cost about a third of", "s", "s"),
 T(48, 162, "the current hot bucket; restore takes hours and costs per GB.", "s", "s"),
 T(48, 188, "Proposed: move 2019 videos to provider C cold; keep one hot copy at home.", "n", "s"),
 pill(48, 202, 92, 26, "Confirm"),
 caption("Prices come from an open, dated, sourced data set. The assistant never sees file contents.",
         "Nothing moves without your confirmation."),
]))

FILES["usecases/sensitive"] = ("A tax folder in a Strongroom: security key required, nothing in clear text on the phone, hidden from the assistant", "".join([
 U("phone", 110, 150), blocks(96, 124, 3, 4, s=8, g=4), T(110, 216, "no clear text on the phone"),
 card(212, 52, 216, 160, 14, stroke="url(#pg)", sw=3),
 '<rect x="222" y="62" width="196" height="140" rx="10" fill="none" stroke="#dbe4ff" stroke-width="1.5"/>',
 T(320, 86, "Taxes/ (Strongroom)", "t"),
 '<use href="#lock" transform="translate(320 128) scale(2.6)"/>',
 '<circle cx="311" cy="186" r="12" fill="none" stroke="#8aa9ff" stroke-width="1.5" stroke-opacity=".7"/><circle cx="311" cy="186" r="18" fill="none" stroke="#8aa9ff" stroke-width="1.5" stroke-opacity=".3"/>',
 U("key", 320, 186),
 P("M434 150 H 466", "tr"), U("x", 450, 150),
 card(470, 116, 130, 68, 12), T(535, 144, "AI assistant", "t"), T(535, 164, "cannot see it"),
 caption("opens only with a touch of your security key"),
]))

FILES["usecases/reader"] = ("A device decrypts on demand and shows thumbnails made once by another device", "".join([
 U("monitor", 150, 146), photo_grid(118, 122, 4, 2, 14, 4),
 T(150, 208, "Desktop", "t"), T(150, 226, "has the photos, makes thumbnails"),
 P("M204 126 C 238 100, 262 96, 288 102"),
 U("cloud", 340, 110), blocks(318, 103, 3, 1, s=10, g=6), U("lockb", 374, 90), T(340, 162, "thumbs/<folder>/<hash>.enc"),
 P("M386 128 C 420 148, 450 150, 482 150"),
 U("phone", 510, 160), photo_grid(497, 128, 2, 3, 12, 4),
 T(510, 228, "Phone", "t"), T(510, 246, "previews, files are placeholders"),
 caption("Thumbnails are encrypted under the folder key; the storage sees only ciphertext."),
]))

def seal(x, y, initials, name):
    return (U("seal", x, y) + f'<text x="{x}" y="{y + 3.5}" class="m" style="font-size:10px;font-weight:700;fill:#fff">{initials}</text>'
            + f'<text x="{x}" y="{y + 34}" class="m" style="font-size:12px;font-weight:600;fill:#1b3a9a">{name}</text>')

FILES["features/pq"] = ("A ledger batch with two seals, Ed25519 and ML-DSA-65, and a share token sealed with X25519 and ML-KEM-768", "".join([
 card(40, 48, 260, 176, 12), T(170, 76, "Ledger batch #42", "t"),
 '<path d="M56 88 H284" stroke="#e8edf7" stroke-width="1.5"/>',
 blocks(58, 98, 15, 3, s=11, g=4.5),
 seal(110, 176, "Ed", "Ed25519"), seal(230, 176, "ML", "ML-DSA-65"),
 T(170, 246, "both signatures must verify"),
 card(340, 48, 260, 176, 12), T(470, 76, "Share token", "t"),
 '<path d="M356 88 H584" stroke="#e8edf7" stroke-width="1.5"/>',
 '<rect x="364" y="104" width="212" height="38" rx="19" fill="#eef2ff" stroke="#8aa9ff" stroke-width="1.5"/>',
 U("lock", 388, 118), T(482, 127.5, "folder key, sealed", "n"),
 seal(410, 176, "X", "X25519"), seal(530, 176, "ML", "ML-KEM-768"),
 T(470, 246, "opens only on the requesting device"),
 caption("Classical and post-quantum together: breaking one is not enough."),
]))

# ---- write ------------------------------------------------------------------
if __name__ == "__main__":
    for name, (aria, body) in FILES.items():
        svg = build(aria, body)
        path = os.path.join(OUT, name + ".svg")
        with open(path, "w") as f:
            f.write(svg)
        print(f"{len(svg.encode()):6d} B  {path}")
