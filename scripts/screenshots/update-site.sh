#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Put the screenshots of a CI run (or a local test run) on the website:
#   scripts/screenshots/update-site.sh                 # newest successful CI run on main
#   scripts/screenshots/update-site.sh <run id>        # that run (e.g. a release tag's run)
#   scripts/screenshots/update-site.sh --dir <dir>     # finalize.py output from elsewhere
# Copies the pictures into website/public/assets/img/screenshots, sets their
# width and height on the Screenshots pages of every language, states the
# version, commit and date they were captured from, and rebuilds the site
# (deploy separately with website/deploy.sh). The CI package has the
# subdirectories en/ (-> assets/img/screenshots), fi/ and sv/ (-> screenshots-fi,
# screenshots-sv) and viz/viz-tv.png (-> assets/img/viz-tv.png) and sizes per
# set in shots.json; a flat directory (finalize.py without --pack) is the en set.
# The web server does the same from the published package
# (ops/site/screenshots-sync.py); this script is for the repository's copy.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
repo="${GITHUB_REPO:-janttsu/varsto}"
dest="$root/website/public/assets/img/screenshots"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
if [ "${1:-}" = "--dir" ]; then
  src="${2:?--dir needs a directory}"
else
  run="${1:-}"
  if [ -z "$run" ]; then
    run="$(gh run list -R "$repo" --workflow CI --branch main --status success --limit 1 --json databaseId -q '.[0].databaseId')"
  fi
  [ -n "$run" ] || { echo "no successful CI run found" >&2; exit 1; }
  echo "== screenshots of CI run $run"
  gh run download "$run" -R "$repo" -n screenshots -D "$tmp/shots"
  src="$tmp/shots"
fi
[ -f "$src/shots.json" ] || { echo "$src has no shots.json (run finalize.py first)" >&2; exit 1; }
mkdir -p "$dest"
python3 - "$src" "$dest" "$root/website/src" <<'PY'
import json, pathlib, re, shutil, sys
src, dest, pages = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
meta = json.loads((src / "shots.json").read_text())
# The caption per language; the English page and its Finnish, Swedish and French copies.
CAPTION = {
    "en": ("Captured automatically from version {v}{c} on {d}{s}.", "GitHub Actions run"),
    "fi": ("Kuvattu automaattisesti versiosta {v}{c} {d}{s}.", "GitHub Actions -ajo"),
    "sv": ("Tagna automatiskt från version {v}{c} den {d}{s}.", "GitHub Actions-körning"),
    "fr": ("Capturées automatiquement depuis la version {v}{c} le {d}{s}.", "exécution GitHub Actions"),
}
def stamp(lang, version, commit, date, source, esc=lambda s: s):
    text, run = CAPTION[lang]
    source = re.sub(r"^GitHub Actions run", run, source or "")
    return '<span class="shots-meta">' + text.format(
        v=esc(version), c=f" (commit {esc(commit[:7])})" if commit else "", d=esc(date),
        s=f", {esc(source)}" if source else "") + "</span>"
sizes = meta["sizes"]
if sizes and not all(isinstance(v, dict) for v in sizes.values()):
    sizes = {"en": sizes}  # flat package
DIRS = {"en": "screenshots", "fi": "screenshots-fi", "sv": "screenshots-sv", "viz": ""}
img = dest.parent
for group, table in sizes.items():
    sub = src / group if (src / group).is_dir() else src
    out = img / DIRS[group] if DIRS[group] else img
    out.mkdir(parents=True, exist_ok=True)
    for name in table:
        shutil.copyfile(sub / f"{name}.png", out / f"{name}.png")
for lang, page in [("en", pages / "pages/screenshots.html"),
                   ("fi", pages / "i18n/fi/pages/screenshots.html"),
                   ("sv", pages / "i18n/sv/pages/screenshots.html"),
                   ("fr", pages / "i18n/fr/pages/screenshots.html")]:
    if not page.exists():
        continue
    html = page.read_text()
    for group, table in sorted(sizes.items()):
        for name, (w, h) in sorted(table.items()):
            rel = f"{DIRS[group]}/{name}" if DIRS[group] else name
            pat = re.compile(r'(src="(?:\.\./|\{\{P\}\})*assets/img/' + re.escape(rel) + r'\.png"[^>]*?) width="\d+" height="\d+"')
            html, n = pat.subn(rf'\1 width="{w}" height="{h}"', html)
            if lang == "en":
                print(f"{rel}.png {w}x{h}" + ("" if n else "  (not on the page)"))
    s = stamp(lang, meta["version"], meta.get("commit", ""), meta["date"], meta.get("source", ""))
    html, n = re.subn(r'<span class="shots-meta">.*?</span>', lambda _: s, html, flags=re.S)
    if not n:
        print(f"!! {page} has no shots-meta span", file=sys.stderr)
    page.write_text(html)
    print(s)
PY
python3 "$root/website/build.py" >/dev/null
echo "site rebuilt; deploy with website/deploy.sh"
