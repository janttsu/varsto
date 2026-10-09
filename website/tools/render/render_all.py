# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Render every illustration and compose the text layer in one go.

    ~/.local/opt/blender/blender -b --python website/tools/render/render_all.py -- [options]

Options (after the "--"):
    --only NAME[,NAME]   render only these scenes (e.g. features/ledger,hero)
    --samples N          Cycles samples for the 640x320 scenes (default 160; hero 192)
    --device AUTO|OPTIX|CUDA|CPU   AUTO picks the GPU when at least 2.5 GB of VRAM is free
    --work DIR           scratch directory for raw renders and layout JSON (default: $TMPDIR/varsto-render)
    --no-compose         skip compose.py (text layer)
    --layout-only        build the scenes and run the overlap check only (no render)

Outputs go next to the SVGs: website/public/assets/img/{features,usecases,encryption}/*.webp|png
and website/public/assets/img/hero.webp|png.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
OUT_DIR = os.path.join(ROOT, "website", "public", "assets", "img")

import scene_kit as K   # noqa: E402
import scenes            # noqa: E402


def parse_args(argv):
    opts = {"only": None, "samples": 160, "device": "AUTO", "work": os.path.join(tempfile.gettempdir(), "varsto-render"), "compose": True, "layout_only": False}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--only":
            opts["only"] = argv[i + 1].split(","); i += 2
        elif a == "--samples":
            opts["samples"] = int(argv[i + 1]); i += 2
        elif a == "--device":
            opts["device"] = argv[i + 1].upper(); i += 2
        elif a == "--work":
            opts["work"] = argv[i + 1]; i += 2
        elif a == "--no-compose":
            opts["compose"] = False; i += 1
        elif a == "--layout-only":
            opts["layout_only"] = True; i += 1
        else:
            raise SystemExit(f"unknown option {a}")
    return opts


def pick_device(wanted: str) -> str:
    if wanted != "AUTO":
        return wanted
    try:
        out = subprocess.run(["nvidia-smi", "--query-gpu=memory.free", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=10).stdout.strip().splitlines()
        free = int(out[0]) if out else 0
    except Exception:
        free = 0
    if free >= 2500:
        return "OPTIX"
    print(f"GPU has only {free} MiB free: rendering on the CPU")
    return "CPU"


def main():
    argv = sys.argv[sys.argv.index("--") + 1:] if "--" in sys.argv else []
    opts = parse_args(argv)
    device = "CPU" if opts["layout_only"] else pick_device(opts["device"])
    os.makedirs(opts["work"], exist_ok=True)
    names = opts["only"] or list(scenes.SCENES)
    t_all = time.time()
    report = []
    for name in names:
        w, h, fn = scenes.SCENES[name]
        t0 = time.time()
        samples = opts["samples"] if name != "hero" else max(opts["samples"], 192)
        K.new_scene(w, h, scale=2, samples=samples, gpu=device)
        fn()
        raw = os.path.join(opts["work"], name.replace("/", "_") + ".png")
        lay = os.path.join(opts["work"], name.replace("/", "_") + ".json")
        os.makedirs(os.path.dirname(raw), exist_ok=True)
        json.dump(K.layout(), open(lay, "w"), indent=1)
        if opts["layout_only"]:
            r = subprocess.run(["python3", os.path.join(HERE, "compose.py"), "--check", lay], capture_output=True, text=True)
            line = f"{name:22s} layout check: " + r.stdout.strip().replace("\n", "\n    ")
            print(line, flush=True)
            report.append(line)
            continue
        K.render(raw)
        dt = time.time() - t0
        line = f"{name:22s} {w}x{h}@2x {samples} spp {K.S.device:5s} {dt:6.1f} s"
        if opts["compose"]:
            out_base = os.path.join(OUT_DIR, name)
            r = subprocess.run([sys.executable if False else "python3", os.path.join(HERE, "compose.py"), raw, lay, out_base],
                               capture_output=True, text=True)
            if r.stderr.strip():
                line += "  compose FAILED: " + r.stderr.strip()[-400:]
            if r.stdout.strip():
                line += "\n    " + r.stdout.strip().replace("\n", "\n    ")
            for ext in ("webp", "png"):
                p = f"{out_base}.{ext}"
                if os.path.exists(p):
                    line += f"\n    {os.path.getsize(p) // 1024:4d} KB  {os.path.relpath(p, ROOT)}"
        print(line, flush=True)
        report.append(line)
    total = time.time() - t_all
    print(f"\nrendered {len(names)} scene(s) in {total:.0f} s on {device}")
    with open(os.path.join(opts["work"], "report.txt"), "w") as f:
        f.write("\n".join(report) + f"\n\ntotal {total:.0f} s on {device}\n")


if __name__ == "__main__":
    main()
