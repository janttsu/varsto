#!/usr/bin/env python3
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
"""Put the CI outputs of one daily build together under the stable daily names.

    daily-assemble.py --art DIR --out DIR --build-id ID --date YYYY-MM-DD \\
        --version V --commit SHA [--ci-run URL]

DIR for --art is what actions/download-artifact leaves (one sub-directory per
artifact; the files are found by pattern, anywhere below). Writes into --out
(which must be empty or missing):

  varsto-daily-linux-x86_64.tar.gz       varsto-daily-android-debug.apk
  varsto-daily-windows-setup.exe         varsto-daily-macos-apple-silicon.dmg
  varsto-daily-ios-unsigned.ipa          varsto-daily-screenshots.tar.gz
  SHA256SUMS                             (unsigned; scripts/sign-daily.sh signs it)
  latest.json                            (what the daily page and daily-sync.py read)

Every file must be found exactly once; anything else stops the script, so a
build with a missing platform is never published half.
"""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import sys
import tarfile

# (key, glob below --art, stable name)
PLATFORMS = [
    ("linux-x86_64", "varsto-*-x86_64-unknown-linux-musl.tar.gz", "varsto-daily-linux-x86_64.tar.gz"),
    ("android", "varsto-*-android-debug.apk", "varsto-daily-android-debug.apk"),
    ("windows-setup", "Varsto-*-setup.exe", "varsto-daily-windows-setup.exe"),
    ("macos", "Varsto-*-macos.dmg", "varsto-daily-macos-apple-silicon.dmg"),
    ("ios", "Varsto-*-ios-unsigned.ipa", "varsto-daily-ios-unsigned.ipa"),
]
SCREENSHOTS = "varsto-daily-screenshots.tar.gz"


def sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def one(art: pathlib.Path, pattern: str) -> pathlib.Path:
    hits = sorted(p for p in art.rglob(pattern) if p.is_file())
    if len(hits) > 1:
        # The same package is uploaded by its build job and again inside the
        # assembled download set; take the download set when it has one, and
        # otherwise accept copies whose bytes are identical.
        assembled = [h for h in hits if "downloads" in h.relative_to(art).parts]
        if assembled:
            hits = assembled[:1]
        elif len({sha256_of(h) for h in hits}) == 1:
            hits = hits[:1]
    if len(hits) != 1:
        sys.exit(f"expected exactly one {pattern} below {art}, found {[str(h) for h in hits]}")
    return hits[0]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--art", required=True, type=pathlib.Path)
    ap.add_argument("--out", required=True, type=pathlib.Path)
    ap.add_argument("--build-id", required=True)
    ap.add_argument("--date", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--commit", required=True)
    ap.add_argument("--ci-run", default="")
    a = ap.parse_args()
    if not re.fullmatch(r"[0-9]{8}-[0-9a-f]{7,40}", a.build_id):
        sys.exit("--build-id must look like 20261016-316c579")
    if not re.fullmatch(r"[0-9a-f]{40}", a.commit):
        sys.exit("--commit must be the full 40-digit hash")
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", a.date):
        sys.exit("--date must be YYYY-MM-DD")
    if a.out.exists() and any(a.out.iterdir()):
        sys.exit(f"{a.out} is not empty")
    a.out.mkdir(parents=True, exist_ok=True)

    entries = []
    for key, pattern, stable in PLATFORMS:
        shutil.copyfile(one(a.art, pattern), a.out / stable)
        entries.append((key, stable))
    shots = a.art / "screenshots"
    if not (shots.is_dir() and any(shots.glob("*.png"))):
        sys.exit(f"no screenshots below {shots}")
    with tarfile.open(a.out / SCREENSHOTS, "w:gz") as t:
        for p in sorted(shots.iterdir()):
            if p.is_file():
                t.add(p, arcname=p.name)
    entries.append(("screenshots", SCREENSHOTS))

    platforms = []
    for key, name in entries:
        f = a.out / name
        platforms.append({"key": key, "file": name, "size": f.stat().st_size, "sha256": sha256(f), "commit": a.commit})
    (a.out / "SHA256SUMS").write_text("".join(f'{p["sha256"]}  {p["file"]}\n' for p in platforms))
    latest = {
        "schema": 1, "channel": "daily", "id": a.build_id, "date": a.date, "version": a.version,
        "commit": a.commit, "ci_run": a.ci_run, "platforms": platforms,
    }
    (a.out / "latest.json").write_text(json.dumps(latest, indent=2) + "\n")
    print(f"daily build {a.build_id}: {len(platforms)} files in {a.out}")


if __name__ == "__main__":
    main()
