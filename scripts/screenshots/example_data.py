# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Invented example data for two screenshots that a small demo vault cannot
show well: peer-to-peer traffic between several devices, and where the data
of a few folders is kept. Names and numbers are made up; the addresses are
from the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
and private LAN ranges. Served to the page by ui-shots.py in place of the
service's answers."""
import math
import time

MB = 1_000_000
GB = 1_000_000_000

DEV = {
    "laptop": "3f1a9c2e7b4d4e0a9c1d2b3a4f5e6d70",
    "desktop": "8b2c4d6e8f0a4b1c9d2e3f4a5b6c7d81",
    "phone": "c4d5e6f7a8b94c0d8e1f2a3b4c5d6e92",
    "nas": "1e2d3c4b5a694f8e7d6c5b4a39281703",
    "office-pc": "9a8b7c6d5e4f43a2b1c0d9e8f7a6b514",
}


def wave(peak, phase, n=60, floor=0.0):
    """A minute of per-second rates that rise and fall like a real transfer."""
    out = []
    for i in range(n):
        x = (i + phase) / n
        v = peak * (0.55 + 0.45 * math.sin(6.2 * x)) * (0.85 + 0.15 * math.sin(23 * x + phase))
        out.append(int(max(floor, v)))
    return out


def traffic():
    now = int(time.time())

    def peer(name, path, addr, rx, tx, rx_total, tx_total, objs_in, objs_out, active, phase):
        return {
            "device": DEV[name], "name": name, "path": path, "addr": addr,
            "rx_bps": rx, "tx_bps": tx, "rx_total": rx_total, "tx_total": tx_total,
            "objects_in": objs_in, "objects_out": objs_out, "active": active,
            "last_seen_utc": now - (0 if active else 40),
            "rx_history": wave(rx, phase), "tx_history": wave(tx, phase + 7),
        }

    peers = [
        peer("desktop", "direct-lan", "192.168.1.20:17893", 38 * MB, int(1.2 * MB), 9_400 * MB, 610 * MB, 4120, 288, 6, 0),
        peer("phone", "direct-lan", "192.168.1.31:17893", int(0.4 * MB), int(6.5 * MB), 220 * MB, 2_850 * MB, 96, 1342, 3, 11),
        peer("nas", "direct", "203.0.113.10:17893", int(2.4 * MB), int(0.8 * MB), 1_730 * MB, 540 * MB, 811, 240, 2, 23),
        peer("office-pc", "relayed via nas", None, int(1.1 * MB), 0, 380 * MB, 12 * MB, 170, 6, 1, 37),
    ]
    rx = sum(p["rx_bps"] for p in peers)
    tx = sum(p["tx_bps"] for p in peers)
    hist_rx = [sum(p["rx_history"][i] for p in peers) for i in range(60)]
    hist_tx = [sum(p["tx_history"][i] for p in peers) for i in range(60)]
    return {
        "device": DEV["laptop"], "name": "laptop", "started_utc": now - 3 * 3600, "now_utc": now,
        "window_secs": 5, "peers": peers, "relays": [],
        "totals": {
            "rx_bps": rx, "tx_bps": tx, "relay_bps": 0,
            "rx_total": sum(p["rx_total"] for p in peers), "tx_total": sum(p["tx_total"] for p in peers),
            "relay_total": 0, "objects_in": sum(p["objects_in"] for p in peers),
            "objects_out": sum(p["objects_out"] for p in peers), "active": sum(p["active"] for p in peers),
        },
        "history": {"rx": hist_rx, "tx": hist_tx, "relay": [0] * 60},
    }


def locations():
    # Encrypted bytes per folder and where each folder is kept.
    folders = [
        ("Documents", "2b7e1516a1d24c3f9e8d7c6b5a493827", 14.2 * GB, {"cloud": 1, "nas-share": 1},
         {"laptop": 1, "desktop": 1, "nas": 1}),
        ("Photos", "6bc1bee2b3e44f2e8a7d6c5b4a392816", 186.0 * GB, {"cloud": 1, "b2-photos": 1, "shelf": 1, "deep-archive": 1},
         {"desktop": 1, "nas": 1, "phone": 0.04}),
        ("Projects", "ae2d8a57c6f14b3d9e8f7a6b5c4d3e21", 41.5 * GB, {"cloud": 1, "nas-share": 1},
         {"laptop": 1, "desktop": 1}),
    ]
    storages = {
        "cloud": dict(kind="s3", place="cloud", cold=False, monthly_cost=3.62),
        "b2-photos": dict(kind="rclone", place="cloud", cold=False, monthly_cost=1.12),
        "deep-archive": dict(kind="s3", place="cloud", cold=True, monthly_cost=0.19),
        "nas-share": dict(kind="directory", place="home", cold=False, monthly_cost=None),
        "shelf": dict(kind="pool", place="home", cold=False, monthly_cost=None),
    }
    block = 4 * MB
    total = sum(f[2] for f in folders)
    s_bytes = {k: 0 for k in storages}
    d_bytes = {k: 0 for k in DEV}
    out_folders = []
    for name, fid, size, st, dv in folders:
        sb = {k: int(size * v) for k, v in st.items()}
        db = {DEV[k]: int(size * v) for k, v in dv.items()}
        for k, v in sb.items():
            s_bytes[k] += v
        for k, v in dv.items():
            d_bytes[k] += int(size * v)
        out_folders.append({"attached": True, "name": name, "folder_id": fid, "bytes": int(size),
                            "blocks": int(size / block), "storages": sb, "devices": db, "unkept_bytes": 0})
    out_storages = []
    for k, s in storages.items():
        out_storages.append({"name": k, "bytes": s_bytes[k], "blocks": int(s_bytes[k] / block),
                             "share": s_bytes[k] / total, "kind": s["kind"], "place": s["place"],
                             "cold": s["cold"], "carrier": False, "configured": True,
                             "monthly_cost": s["monthly_cost"], "currency": "EUR" if s["monthly_cost"] is not None else "",
                             "verified_bytes": int(s_bytes[k] * 0.9)})
    out_devices = [{"name": k, "device_id": DEV[k], "bytes": v, "blocks": int(v / block), "share": v / total,
                    "this_device": k == "laptop", "revoked": False}
                   for k, v in d_bytes.items() if v > 0]
    # Kept copies on storages per byte: Documents and Projects 2, Photos 4.
    two = int(14.2 * GB + 41.5 * GB)
    three_plus = int(186.0 * GB)
    copies_avg = (2 * two + 4 * three_plus) / total
    return {
        "total_bytes": int(total), "total_blocks": int(total / block),
        "folders": out_folders, "storages": out_storages, "devices": out_devices,
        "copies": {"average": copies_avg, "bytes": [0, 0, two, three_plus],
                   "none": 0, "one": 0, "two": int(two / block), "three_plus": int(three_plus / block)},
    }
