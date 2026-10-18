#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Invented snapshot for the TV example screenshot of the full-screen visualization.

Everything in it is made up (folders, storages, devices, sizes, prices). Write it with

    python3 website/tools/screenshots/viz_tv_scene.py scene.json

and feed it to scripts/screenshots/viz-shots.py with VIZ_SCENE=scene.json
(that script comes with the visualization page, pull request 43).
"""
import json
import sys
import time

t = time.time()
GB, TB = 1e9, 1e12

scene = {
    "v": 1, "utc": t, "unlocked": True, "this_device": "d1", "key_epoch": 1, "total_bytes": 612 * GB,
    "devices": [
        {"id": "d1", "name": "Laptop", "role": "this", "platform": "linux", "online": True, "rx_bps": 0, "tx_bps": 5.6e6},
        {"id": "d2", "name": "Phone", "role": "peer", "platform": "android", "online": True, "rx_bps": 0, "tx_bps": 2.2e6},
        {"id": "d3", "name": "Tablet", "role": "peer", "platform": "ios", "online": True, "rx_bps": 0, "tx_bps": 0},
    ],
    "storages": [
        {"id": "s:Home NAS", "name": "Home NAS", "kind": "directory", "place": "home", "configured": True,
         "data_bytes": 410 * GB, "used_bytes": 410 * GB, "quota_bytes": 2 * TB, "percent": 20, "state": "ok", "verified_bytes": 360 * GB},
        {"id": "s:Disk pool", "name": "Disk pool", "kind": "pool", "place": "home", "configured": True,
         "data_bytes": 520 * GB, "used_bytes": 520 * GB, "quota_bytes": None, "state": "none", "verified_bytes": 470 * GB},
        {"id": "s:Cloud bucket", "name": "Cloud bucket", "kind": "s3", "place": "cloud", "configured": True,
         "data_bytes": 330 * GB, "used_bytes": 330 * GB, "quota_bytes": 1 * TB, "percent": 33, "state": "ok", "verified_bytes": 270 * GB,
         "price": {"currency": "EUR"}, "monthly_cost": 2.1, "read_all_cost": 25.0},
    ],
    "disks": {"count": 3, "docked": ["B"], "working_on": "B", "list": [
        {"pool": "Disk pool", "label": "A", "docked": False, "phase": "away", "capacity_bytes": 4 * TB, "used_bytes": 2.6 * TB,
         "last_verified_utc": t - 86400 * 9, "overdue_share": 0},
        {"pool": "Disk pool", "label": "B", "docked": True, "phase": "verify", "progress": 64, "eta_utc": t + 900,
         "capacity_bytes": 4 * TB, "used_bytes": 2.4 * TB, "last_verified_utc": t - 86400 * 31, "overdue_share": 0},
        {"pool": "Disk pool", "label": "C", "docked": False, "phase": "away", "capacity_bytes": 2 * TB, "used_bytes": 1.1 * TB,
         "last_verified_utc": t - 86400 * 4, "overdue_share": 0},
    ]},
    "folders": [
        {"name": "Documents", "bytes": 46 * GB, "files": 14000, "blocks": 22000, "policy": "at least 3 copies", "policy_state": "ok",
         "verified_blocks": 19500, "unverified_blocks": 2500, "local_only_blocks": 0, "missing_blocks": 0, "oldest_verification_days": 6,
         "storages": {"Home NAS": 46 * GB, "Cloud bucket": 46 * GB, "Disk pool": 46 * GB}, "targets": ["Home NAS", "Cloud bucket", "Disk pool"]},
        {"name": "Music", "bytes": 118 * GB, "files": 9800, "blocks": 47000, "policy": "at least 2 copies", "policy_state": "ok",
         "verified_blocks": 41000, "unverified_blocks": 6000, "local_only_blocks": 0, "missing_blocks": 0, "oldest_verification_days": 12,
         "storages": {"Home NAS": 118 * GB, "Disk pool": 118 * GB}, "targets": ["Home NAS", "Disk pool"]},
        {"name": "Photos", "bytes": 448 * GB, "files": 52000, "blocks": 160000, "policy": "at least 3 copies", "policy_state": "ok",
         "verified_blocks": 128000, "unverified_blocks": 31000, "local_only_blocks": 1000, "missing_blocks": 0, "oldest_verification_days": 18,
         "storages": {"Home NAS": 246 * GB, "Cloud bucket": 330 * GB, "Disk pool": 356 * GB}, "targets": ["Home NAS", "Cloud bucket", "Disk pool"]},
    ],
    "copies": {"blocks": [0, 2000, 42000, 186000], "bytes": [0, 9 * GB, 80 * GB, 523 * GB], "average": 2.7},
    "flows": [
        {"id": "a", "kind": "upload", "from": "d:d1", "to": "s:Cloud bucket", "folder": "Photos", "bps": 5.6e6, "rate": 5.6e6,
         "done": 7.4e9, "total": 21e9, "eta_utc": t + 2900, "unit": "bytes"},
        {"id": "b", "kind": "p2p", "from": "d:d2", "to": "d:d1", "folder": "", "bps": 2.2e6, "path": "direct-lan"},
    ],
    "jobs": [
        {"id": "j1", "kind": "upload", "subject": "Photos", "device_name": "Laptop", "device": "d1", "done": 7.4e9, "total": 21e9,
         "unit": "bytes", "percent": 35, "rate": 5.6e6, "eta_utc": t + 2900},
        {"id": "j2", "kind": "disk_check", "subject": "B", "device_name": "Laptop", "device": "d1", "done": 64, "total": 100,
         "unit": "items", "percent": 64, "rate": 0, "eta_utc": t + 900, "phase": "verify"},
    ],
    "moves": [], "drains": [],
    "backups": [{"name": "Laptop backup", "snapshots": 21, "latest_utc": t - 5400, "next_due_utc": t + 7200, "stopped": False}],
    "alerts": [],
    "health": {"overall": "ok", "ledger": "ok",
               "verify": {"enabled": True, "last_run_utc": t - 3600, "next_run_utc": t + 3600},
               "scrub": {"enabled": True, "last_run_utc": t - 86400, "next_run_utc": t + 86400 * 6},
               "repair": {"queued": 0, "losses": 0}},
    "traffic": {"rx_bps": 2.2e6, "tx_bps": 0},
    "cost": {"estimate": True, "month": {"EUR": 2.1}, "read_all_once": {"EUR": 25.0}, "unpriced": []},
}

json.dump(scene, open(sys.argv[1], "w"), indent=1)
