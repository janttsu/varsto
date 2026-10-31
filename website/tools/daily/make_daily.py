#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Prepare a Varsto daily build for publishing BY HAND (the manual/offline path).

The normal path is automatic: .github/workflows/daily.yml builds, signs and
publishes the pre-release "daily" and ops/site/daily-sync.py on the server
pulls it. Use this tool only when that path is not available (for example a
build made on your own machines). It writes the same layout the server has.

Input: a folder with the build files of one daily build (any file name prefix;
the platform is recognised by the file name ending, see PLATFORMS; the stable
varsto-daily-* names work too). The commit each file was built from is the last
dash-separated token before the platform ending when it looks like a git hash,
otherwise --commit.

What it writes under --out (not part of the generated site):
  daily/builds/<id>/<stable names>, SHA256SUMS, index.html
  daily/latest/<stable names> (relative symlinks into ../builds/<id>/),
  daily/latest/SHA256SUMS, daily/latest.json (same fields as daily-sync.py writes)
and prints the build ids that fall out of the --keep window (delete them on the
server by hand; this script never deletes anything).

SHA256SUMS is NOT signed here. Sign it before upload, with the daily key:
  VARSTO_DAILY_KEY=~/.config/varsto-release/daily-key.pem \\
      scripts/sign-daily.sh --build-id <id> <out>/daily/builds/<id>/SHA256SUMS
and copy SHA256SUMS.sig next to it and to daily/latest/. `varsto update --daily`
refuses a list without a valid signature. The page itself is static and reads
daily/latest.json, so no site deploy is needed.

Upload (never with --delete, never touching downloads/ or testbuilds/):
  ssh <host> 'mkdir -p <web root>/daily/builds/<id> <web root>/daily/latest'
  rsync -rlt --chmod=D755,F644 <out>/daily/ <host>:<web root>/daily/

Example:
  make_daily.py --src ~/builds/20261016-316c579 --build-id 20261016-316c579 \\
      --date 2026-10-16 --commit 651a3fd --out ~/daily-out
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import re
import shutil
import sys
from pathlib import Path

# (key, file name ending of the input file, stable name)
PLATFORMS = [
    ("linux-x86_64", "-linux-x86_64.tar.gz", "varsto-daily-linux-x86_64.tar.gz"),
    # Stable name still says debug: renaming it would break the signed daily list.
    # The bytes are the release APK. CI also copies that APK to this ending.
    ("android", "-android-debug.apk", "varsto-daily-android-debug.apk"),
    ("windows-setup", "-windows-setup.exe", "varsto-daily-windows-setup.exe"),
    ("macos", "-macos-apple-silicon.dmg", "varsto-daily-macos-apple-silicon.dmg"),
    ("ios", "-ios-unsigned.ipa", "varsto-daily-ios-unsigned.ipa"),
    ("screenshots", "-screenshots.tar.gz", "varsto-daily-screenshots.tar.gz"),
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def commit_of(name: str, ending: str, fallback: str) -> str:
    last = name[: -len(ending)].rsplit("-", 1)[-1]
    return last if re.fullmatch(r"[0-9a-f]{7,40}", last) else fallback


def link_or_copy(src: Path, dst: Path) -> None:
    if dst.exists() or dst.is_symlink():
        dst.unlink()
    try:
        os.link(src, dst)
    except OSError:
        shutil.copyfile(src, dst)


def build_index(meta: dict) -> str:
    e = html.escape
    rows = "".join(f'<li><a href="{e(p["file"])}">{e(p["file"])}</a> ({p["size"]} bytes)\n' for p in meta["platforms"])
    return (
        '<!doctype html><meta charset=utf-8><meta name=robots content="noindex">'
        f'<title>Varsto daily build {e(meta["id"])}</title>'
        f'<h1>Varsto daily build {e(meta["id"])}</h1>'
        '<p>Development build, not a release. See <a href="../../">the daily builds page</a>.</p>'
        f'<ul>{rows}<li><a href="SHA256SUMS">SHA256SUMS</a> (<a href="SHA256SUMS.sig">signature</a>)</ul>\n'
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", required=True, type=Path, help="folder with the build files")
    ap.add_argument("--build-id", required=True, help="e.g. 20261016-316c579")
    ap.add_argument("--date", required=True, help="YYYY-MM-DD")
    ap.add_argument("--version", default="", help="version string inside the builds (default: version in the workspace Cargo.toml)")
    ap.add_argument("--commit", required=True, help="commit the build is based on")
    ap.add_argument("--ci-run", default="", help="URL of the CI run")
    ap.add_argument("--out", required=True, type=Path, help="directory to write the server layout into")
    ap.add_argument("--keep", type=int, default=7, help="dated builds kept on the server")
    a = ap.parse_args()
    if not re.fullmatch(r"[0-9]{8}-[0-9a-f]{7,40}", a.build_id):
        sys.exit("--build-id must look like 20261016-316c579")
    version = a.version
    if not version:
        cargo = Path(__file__).resolve().parents[3] / "Cargo.toml"
        m = re.search(r'^version\s*=\s*"([^"]+)"', cargo.read_text(), re.M)
        version = m.group(1) if m else ""

    platforms = []
    for key, ending, stable in PLATFORMS:
        hits = sorted(p for p in a.src.iterdir() if p.is_file() and (p.name.endswith(ending) or p.name == stable))
        if not hits:
            print(f"warning: no file for {key} ({ending})", file=sys.stderr)
            continue
        if len(hits) > 1:
            sys.exit(f"several files for {key}: {[h.name for h in hits]}")
        f = hits[0]
        platforms.append({
            "key": key, "file": stable, "src": f, "size": f.stat().st_size, "sha256": sha256(f),
            "commit": commit_of(f.name, ending, a.commit),
        })
    if not platforms:
        sys.exit("no build files found")
    for p in platforms:
        p["build"] = a.build_id

    if a.add_platforms:
        oldcur = old.get("current")
        if not oldcur:
            sys.exit("--add-platforms needs an existing current build in daily.json")
        keys = {p["key"] for p in platforms}
        carried = [{**q, "build": q.get("build", oldcur["id"])} for q in oldcur["platforms"] if q["key"] not in keys]
        order = [k for k, *_ in PLATFORMS]
        new_platforms = platforms
        platforms = sorted(carried + platforms, key=lambda p: order.index(p["key"]))
    else:
        new_platforms = platforms

    root = a.out / "daily"
    builds = root / "builds"
    bdir, ldir = builds / a.build_id, root / "latest"
    bdir.mkdir(parents=True, exist_ok=True)
    ldir.mkdir(parents=True, exist_ok=True)
    for p in platforms:
        link_or_copy(p["src"], bdir / p["file"])
    meta = {
        "schema": 1, "channel": "daily", "id": a.build_id, "date": a.date, "version": version, "commit": a.commit,
        "ci_run": a.ci_run,
        "platforms": [{k: v for k, v in p.items() if k != "src"} for p in platforms],
    }
    (bdir / "SHA256SUMS").write_text("".join(f'{p["sha256"]}  {p["file"]}\n' for p in platforms))
    (bdir / "latest.json").write_text(json.dumps(meta, indent=2) + "\n")
    (bdir / "index.html").write_text(build_index(meta))
    for stale in ldir.iterdir():
        stale.unlink()
    for p in platforms:
        (ldir / p["file"]).symlink_to(f'../builds/{a.build_id}/{p["file"]}')
    shutil.copyfile(bdir / "SHA256SUMS", ldir / "SHA256SUMS")
    ids = sorted((d.name for d in builds.iterdir() if re.fullmatch(r"[0-9]{8}-[0-9a-f]{7,40}", d.name)), reverse=True)
    history = []
    for i in ids[: a.keep]:
        try:
            date = json.loads((builds / i / "latest.json").read_text()).get("date", "")
        except (OSError, ValueError):
            date = ""
        history.append({"id": i, "date": date})
    (root / "latest.json").write_text(json.dumps({**meta, "history": history}, indent=2) + "\n")

    print(f"build {a.build_id}: {len(platforms)} files; {root} written (SHA256SUMS is not signed yet)")
    for i in ids[a.keep:]:
        print(f"prune on server: daily/builds/{i}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
