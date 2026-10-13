#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Build p1s-project-settings.json from the Bambu Studio system presets.

    python3 make_settings.py <Bambu Studio root> [--work DIR]

<Bambu Studio root> is the directory that holds resources/profiles (for the AppImage: run it
with --appimage-extract and pass squashfs-root). The script flattens the system presets
(inherits and include chains resolved, BBL vendor directory preferred)

    machine   Bambu Lab P1S 0.4 nozzle
    process   0.20mm Standard @BBL X1C
    filament  Bambu PLA Basic @BBL P1S 0.4 nozzle  (x3: AMS slots 1-3)

then lets the Bambu Studio command line combine them into a three-filament project
(--load-settings / --load-filaments on a small probe model) and keeps the project settings it
writes. This way every per-filament array has the length Bambu Studio itself expects.
generate.py only reads the resulting JSON, so Bambu Studio is not needed to regenerate models.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "p1s-project-settings.json"
MACHINE = "Bambu Lab P1S 0.4 nozzle"
PROCESS = "0.20mm Standard @BBL X1C"
FILAMENT = "Bambu PLA Basic @BBL P1S 0.4 nozzle"
SLOTS = 3
META = {"inherits", "include", "instantiation", "setting_id", "base_id", "is_custom_defined"}


def index_profiles(root: Path) -> dict[tuple[str, str], Path]:
    prof = root / "resources" / "profiles"
    bbl = str(prof / "BBL")
    paths = sorted(prof.rglob("*.json"), key=lambda q: (not str(q).startswith(bbl), str(q)))
    paths += list((root / "resources" / "profiles_template").rglob("*.json"))
    idx: dict[tuple[str, str], Path] = {}
    for p in paths:
        try:
            d = json.loads(p.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(d, dict) and "name" in d:
            idx.setdefault((d.get("type", "template"), d["name"]), p)   # include templates have no type
    return idx


def resolve(idx: dict, kind: str, name: str) -> dict:
    d = json.loads(idx[(kind, name)].read_text())
    out: dict = {}
    if d.get("inherits"):
        out.update(resolve(idx, kind, d["inherits"]))
    for inc in d.get("include", []):
        out.update(resolve(idx, kind if (kind, inc) in idx else "template", inc))
    out.update({k: v for k, v in d.items() if k not in META and k not in ("type", "name")})
    return out


def flat_preset(idx: dict, kind: str, name: str) -> dict:
    d = resolve(idx, kind, name)
    d.update({"type": kind, "name": name, "from": "system", "inherits": ""})
    return d


def probe_3mf(path: Path, settings: dict) -> None:
    """A 20 mm cube with three parts (one per AMS slot), enough for the CLI to build a project."""
    sys.path.insert(0, str(HERE))
    import generate as g

    cube = g.Manifold.cube([20, 20, 2])
    item = {"plates": [{"name": "probe", "objects": [{
        "name": "probe", "pos": (128.0, 128.0), "settings": {},
        "parts": {"blue": cube, "black": cube.translate([0, 0, 2]), "white": cube.translate([0, 0, 4])}}]}]}
    g.SETTINGS = path.with_suffix(".seed.json")
    g.SETTINGS.write_text(json.dumps(settings))
    g.write_3mf(path, item, "probe", "#0056B8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("bambu_root", type=Path)
    ap.add_argument("--work", type=Path, default=None, help="scratch directory (default: a temp dir)")
    a = ap.parse_args()
    root = a.bambu_root.resolve()
    work = a.work or Path(tempfile.mkdtemp(prefix="varsto-3d-settings-"))
    work.mkdir(parents=True, exist_ok=True)
    idx = index_profiles(root)
    files = {}
    for kind, name in (("machine", MACHINE), ("process", PROCESS), ("filament", FILAMENT)):
        d = flat_preset(idx, kind, name)
        f = work / f"{kind}.json"
        f.write_text(json.dumps(d, indent=1))
        files[kind] = f
        print(f"{kind:8s} {name}: {len(d)} keys")

    # Seed: the flattened presets merged, single-filament; the CLI expands it to three filaments.
    seed = {}
    for kind in ("machine", "process", "filament"):
        seed.update(json.loads(files[kind].read_text()))
    seed.update({"name": "project_settings", "from": "project", "printer_settings_id": MACHINE,
                 "print_settings_id": PROCESS, "filament_settings_id": [FILAMENT] * SLOTS})
    probe = work / "probe.3mf"
    if probe.exists():
        probe.unlink()
    probe_3mf(probe, seed)
    out_name = "probe-out.3mf"
    cmd = ["xvfb-run", "-a", str(root / "AppRun"),
           "--load-settings", f"{files['machine']};{files['process']}",
           "--load-filaments", ";".join([str(files["filament"])] * SLOTS),
           "--export-3mf", out_name, "--outputdir", str(work), str(probe)]
    print("+", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        print(r.stdout[-3000:], r.stderr[-3000:], sep="\n")
        sys.exit(f"Bambu Studio CLI failed ({r.returncode})")
    with zipfile.ZipFile(work / out_name) as z:
        cfg = json.loads(z.read("Metadata/project_settings.config"))
    assert len(cfg["filament_settings_id"]) == SLOTS, cfg["filament_settings_id"]
    assert cfg["printer_settings_id"] == MACHINE and cfg["print_settings_id"] == PROCESS
    OUT.write_text(json.dumps(cfg, indent=4, ensure_ascii=False) + "\n")
    print(f"-> {OUT} ({len(cfg)} keys, version {cfg.get('version')})")
    if a.work is None:
        shutil.rmtree(work)


if __name__ == "__main__":
    main()
