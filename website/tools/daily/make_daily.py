#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Prepare a Varsto daily build for publishing.

Input: a folder with the build files of one daily build (any file name prefix;
the platform is recognised by the file name ending, see PLATFORMS). The commit
each file was built from is the last dash-separated token before the platform
ending when it looks like a git hash (e.g. varsto-testbuild-20261016-316c579-
linux-x86_64.tar.gz), otherwise the build's --main-commit.

What it does:
  1. updates website/src/data/daily.json (the page is generated from it): the
     new build becomes "current", the previous current one moves to "history"
     (at most --keep builds in all, the current one included);
  2. writes the server layout under --out (not part of the generated site):
       daily/builds/<id>/<files>, SHA256SUMS, index.html
       daily/latest/<stable names> (relative symlinks into ../builds/<id>/),
       daily/latest/SHA256SUMS, daily/latest.json
  3. prints the build ids that fall out of the window; delete them on the
     server by hand or in the workflow (this script never deletes anything
     outside --out).

Upload (never with --delete, never touching downloads/ or testbuilds/):
  ssh <host> 'mkdir -p <web root>/daily/builds/<id> <web root>/daily/latest'
  rsync -rlt --chmod=D755,F644 <out>/daily/ <host>:<web root>/daily/

Then regenerate and deploy the site page (python3 website/build.py) so that
/daily/ shows the new build.

Incremental mode (--add-platforms): the folder holds the files of only some
platforms of the build (say, the macOS dmg that finished first). Those
platforms are added to (or replaced in) daily.json under the new build id; the
other platforms keep the files and the build they already had (each platform
entry names its own "build"), and the previous current build is not moved to
the history unless the build id is new. --out then holds only the new files and
their symlinks, but SHA256SUMS (daily/latest and the dated one) and
latest.json always cover every platform, so an upload without --delete never
loses another platform's link. Run it once per platform as each one is ready.

Example:
  make_daily.py --src ~/builds/20261016-316c579 --build-id 20261016-316c579 \\
      --date 2026-10-16 --main-commit 651a3fd --prs 39,41,44 --out /tmp/daily-out
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

SITE_URL = "https://varsto.net"
HERE = Path(__file__).resolve().parent
DAILY_JSON = HERE.parent.parent / "src" / "data" / "daily.json"

# (key, label, file name ending of the dated file, stable "latest" name)
PLATFORMS = [
    ("linux-x86_64", "Linux x86_64 (static, musl)", "-linux-x86_64.tar.gz", "varsto-daily-linux-x86_64.tar.gz"),
    ("android", "Android (debug APK)", "-android-debug.apk", "varsto-daily-android-debug.apk"),
    ("windows-setup", "Windows installer", "-windows-setup.exe", "varsto-daily-windows-setup.exe"),
    ("windows-zip", "Windows portable zip", "-windows-x86_64.zip", "varsto-daily-windows-x86_64.zip"),
    ("macos", "macOS Apple Silicon (dmg)", "-macos-apple-silicon.dmg", "varsto-daily-macos-apple-silicon.dmg"),
    ("ios", "iOS (unsigned ipa)", "-ios-unsigned.ipa", "varsto-daily-ios-unsigned.ipa"),
]

# Known gaps used when daily.json has none yet. The ids key the page translations in build.py.
DEFAULT_GAPS = [
    ("unsigned", "Nothing is signed: no release signature, no Apple or Microsoft code signing. The checksums only catch a corrupted download."),
    ("not-format-2", "Format 2 (the records work) is not included; when it lands, vaults created with these builds must be recreated."),
    ("os-warnings", "macOS, Windows and iOS warn about unsigned software; expect right-click and Open on macOS, and SmartScreen on Windows."),
    ("windows-ci-only", "The Windows installer has been smoke-tested on CI only (install, upgrade, repair, downgrade refusal, uninstall), not on a real machine."),
    ("ios-untested", "The iOS ipa has not been run on a real device. Sideload it with AltStore, SideStore or Sideloadly."),
    ("ui-strings", "Some strings in the app interface are not translated yet; they are logged."),
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def commit_of(name: str, ending: str, fallback: str) -> str:
    stem = name[: -len(ending)]
    last = stem.rsplit("-", 1)[-1]
    return last if re.fullmatch(r"[0-9a-f]{7,40}", last) else fallback


def link_or_copy(src: Path, dst: Path) -> None:
    if dst.exists() or dst.is_symlink():
        dst.unlink()
    try:
        os.link(src, dst)
    except OSError:
        shutil.copyfile(src, dst)


def build_index(entry: dict) -> str:
    rows = "".join(
        f'<li><a href="{html.escape(p["file"])}">{html.escape(p["file"])}</a> ({p["size"]} bytes, built from {html.escape(p["commit"])})\n'
        for p in entry["platforms"]
    )
    return (
        '<!doctype html><meta charset=utf-8><meta name=robots content="noindex">'
        f'<title>Varsto daily build {html.escape(entry["id"])}</title>'
        f'<h1>Varsto daily build {html.escape(entry["id"])}</h1>'
        '<p>Unsigned development build, not a release. See <a href="../../">the daily builds page</a>.</p>'
        f'<ul>{rows}<li><a href="SHA256SUMS">SHA256SUMS</a></ul>\n'
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", required=True, type=Path, help="folder with the build files")
    ap.add_argument("--build-id", required=True, help="e.g. 20261016-316c579")
    ap.add_argument("--date", required=True, help="YYYY-MM-DD")
    ap.add_argument("--version", default="0.0.1-alpha.14", help="version string inside the builds")
    ap.add_argument("--main-commit", required=True, help="main commit the build is based on")
    ap.add_argument("--prs", default="", help="comma-separated PR numbers merged on top of main")
    ap.add_argument("--note", default="", help="one-line note about the build (e.g. extra CI fixes)")
    ap.add_argument("--ci-run", default="", help="URL of the CI run")
    ap.add_argument("--out", required=True, type=Path, help="directory to write the server layout into")
    ap.add_argument("--daily-json", type=Path, default=DAILY_JSON)
    ap.add_argument("--add-platforms", action="store_true",
                    help="incremental: add the platforms found in --src, keep the others as they are")
    ap.add_argument("--keep", type=int, default=7, help="dated builds kept on the server")
    a = ap.parse_args()

    old = json.loads(a.daily_json.read_text()) if a.daily_json.exists() else {}
    platforms = []
    for key, label, ending, stable in PLATFORMS:
        hits = sorted(p for p in a.src.iterdir() if p.is_file() and p.name.endswith(ending))
        if not hits:
            print(f"warning: no file for {key} ({ending})", file=sys.stderr)
            continue
        if len(hits) > 1:
            sys.exit(f"several files for {key}: {[h.name for h in hits]}")
        f = hits[0]
        platforms.append({
            "key": key, "label": label, "file": f.name, "latest": stable, "size": f.stat().st_size,
            "sha256": sha256(f), "commit": commit_of(f.name, ending, a.main_commit), "signed": False,
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

    current = {
        "id": a.build_id, "date": a.date, "version": a.version,
        "main_commit": a.main_commit, "prs": [int(x) for x in a.prs.split(",") if x.strip()],
        "note": a.note, "ci_run": a.ci_run, "platforms": platforms,
    }
    history = [h for h in old.get("history", []) if h["id"] != a.build_id]
    prev = old.get("current")
    if prev and prev["id"] != a.build_id:
        history.insert(0, {"id": prev["id"], "date": prev["date"]})
    history = history[: max(a.keep - 1, 0)]
    kept = {a.build_id} | {h["id"] for h in history}
    before = [old.get("current", {}).get("id")] + [h["id"] for h in old.get("history", [])]
    pruned = [x for x in before if x and x not in kept]

    data = {
        "channel": {"name": "daily", "url": f"{SITE_URL}/daily/", "updater": False, "keep": a.keep},
        "current": current,
        "history": history,
        "known_gaps": old.get("known_gaps") or [{"id": i, "text": t} for i, t in DEFAULT_GAPS],
    }
    a.daily_json.parent.mkdir(parents=True, exist_ok=True)
    a.daily_json.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")

    # Server layout.
    root = a.out / "daily"
    bdir = root / "builds" / a.build_id
    ldir = root / "latest"
    bdir.mkdir(parents=True, exist_ok=True)
    ldir.mkdir(parents=True, exist_ok=True)
    for p in new_platforms:
        link_or_copy(a.src / p["file"], bdir / p["file"])
    own = [p for p in platforms if p["build"] == a.build_id]
    (bdir / "SHA256SUMS").write_text("".join(f'{p["sha256"]}  {p["file"]}\n' for p in own))
    (bdir / "index.html").write_text(build_index({**current, "platforms": own}))
    for stale in ldir.iterdir():
        stale.unlink()
    for p in new_platforms:
        (ldir / p["latest"]).symlink_to(f'../builds/{a.build_id}/{p["file"]}')
    (ldir / "SHA256SUMS").write_text("".join(f'{p["sha256"]}  {p["latest"]}\n' for p in platforms))
    latest = dict(data["channel"])
    latest["build"] = {
        **{k: v for k, v in current.items() if k != "platforms"},
        "sha256sums_url": f"{SITE_URL}/daily/latest/SHA256SUMS",
        "platforms": [
            {**p, "url": f'{SITE_URL}/daily/latest/{p["latest"]}',
             "dated_url": f'{SITE_URL}/daily/builds/{p["build"]}/{p["file"]}'}
            for p in platforms
        ],
    }
    (root / "latest.json").write_text(json.dumps(latest, indent=2, ensure_ascii=False) + "\n")

    print(f"build {a.build_id}: {len(platforms)} platforms; daily.json and {root} written")
    for x in pruned:
        print(f"prune on server: daily/builds/{x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
