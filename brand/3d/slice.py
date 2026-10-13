#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Slice every project in this directory with the Bambu Studio command line and report the results.

    python3 slice.py <Bambu Studio root> [--work DIR] [files...]

<Bambu Studio root> holds AppRun (an extracted AppImage: --appimage-extract -> squashfs-root).
Needs xvfb-run. Sliced projects go to --work (default: a temp dir), never into the repository.
Prints print time, filament grams per AMS slot, filament changes, pause layers and warnings.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def slice_one(root: Path, src: Path, work: Path) -> dict:
    out = f"{src.stem}-sliced.3mf"
    (work / out).unlink(missing_ok=True)
    cmd = ["xvfb-run", "-a", str(root / "AppRun"), "--slice", "0", "--export-3mf", out,
           "--outputdir", str(work), str(src)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    res = {"file": src.name, "rc": r.returncode, "plates": []}
    log = r.stdout + r.stderr
    res["log_warnings"] = sorted({ln.strip() for ln in log.splitlines()
                                  if re.search(r"warn|error", ln, re.I)
                                  and not re.search(r"libEGL|MESA|Wayland|glfw|ZFiller", ln)})[:20]
    if r.returncode != 0 or not (work / out).exists():
        res["log_tail"] = log[-2000:]
        return res
    with zipfile.ZipFile(work / out) as z:
        info = ET.fromstring(z.read("Metadata/slice_info.config"))
        for plate in info.iter("plate"):
            meta = {m.get("key"): m.get("value") for m in plate.findall("metadata")}
            idx = meta.get("index")
            g = z.read(f"Metadata/plate_{idx}.gcode").decode()
            fil = [{"id": f.get("id"), "colour": f.get("color"), "g": float(f.get("used_g")), "m": float(f.get("used_m"))}
                   for f in plate.findall("filament")]
            changes = len(re.findall(r"^M620 S\d+A", g, re.M)) - 1      # the first one loads the start filament
            pauses = []
            z_now = 0.0
            for ln in g.splitlines():
                if ln.startswith("; Z_HEIGHT:"):
                    z_now = float(ln.split(":")[1])
                elif ln.startswith("M400 U1"):
                    pauses.append(z_now)
            res["plates"].append({
                "plate": idx, "time_s": float(meta.get("prediction", 0)), "weight_g": float(meta.get("weight", 0)),
                "filaments": fil, "changes": changes, "pause_after_z": pauses,
                "p1s": "machine: P1S" in g,
                "warnings": [w.attrib for w in plate.findall("warning")],
            })
    return res


def fmt_time(s: float) -> str:
    h, m = divmod(round(s / 60), 60)
    return f"{h} h {m:02d} min" if h else f"{m} min"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("bambu_root", type=Path)
    ap.add_argument("--work", type=Path)
    ap.add_argument("files", nargs="*", type=Path)
    a = ap.parse_args()
    work = a.work or Path(tempfile.mkdtemp(prefix="varsto-3d-slice-"))
    work.mkdir(parents=True, exist_ok=True)
    files = a.files or sorted(HERE.glob("*.3mf"))
    bad = False
    for f in files:
        r = slice_one(a.bambu_root.resolve(), f.resolve(), work)
        if not r["plates"]:
            bad = True
            print(f"{r['file']}: FAILED rc={r['rc']}\n{r.get('log_tail', '')}")
            continue
        for p in r["plates"]:
            grams = ", ".join(f"slot {x['id']} {x['g']:.2f} g" for x in p["filaments"])
            print(f"{r['file']} plate {p['plate']}: {fmt_time(p['time_s'])}, {p['weight_g']:.2f} g ({grams}), "
                  f"{p['changes']} filament changes, pauses after Z {p['pause_after_z']}, P1S={p['p1s']}, "
                  f"warnings={p['warnings']}")
            bad |= not p["p1s"] or bool(p["warnings"])
        for w in r["log_warnings"]:
            print("   log:", w)
    print(f"sliced projects in {work}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
