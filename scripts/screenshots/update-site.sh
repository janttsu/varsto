#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Put the screenshots of a CI run (or a local test run) on the website:
#   scripts/screenshots/update-site.sh                 # newest successful CI run on main
#   scripts/screenshots/update-site.sh <run id>        # that run (e.g. a release tag's run)
#   scripts/screenshots/update-site.sh --dir <dir>     # finalize.py output from elsewhere
# Copies the pictures into website/public/assets/img/screenshots, sets their
# width and height on the Screenshots page, states the version, commit and
# date they were captured from, and rebuilds the site (deploy separately with
# website/deploy.sh).
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
python3 - "$src" "$dest" "$root/website/src/pages/screenshots.html" <<'PY'
import json, pathlib, re, shutil, sys
src, dest, page = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
meta = json.loads((src / "shots.json").read_text())
html = page.read_text()
for name, (w, h) in sorted(meta["sizes"].items()):
    shutil.copyfile(src / f"{name}.png", dest / f"{name}.png")
    pat = re.compile(r'(src="\.\./assets/img/screenshots/' + re.escape(name) + r'\.png"[^>]*?) width="\d+" height="\d+"')
    html, n = pat.subn(rf'\1 width="{w}" height="{h}"', html)
    print(f"{name}.png {w}x{h}" + ("" if n else "  (not on the page)"))
commit = meta.get("commit", "")[:7]
stamp = f'<span class="shots-meta">Captured automatically from version {meta["version"]}' + \
        (f' (commit {commit})' if commit else '') + f' on {meta["date"]}' + \
        (f', {meta["source"]}' if meta.get("source") else '') + '.</span>'
html, n = re.subn(r'<span class="shots-meta">.*?</span>', stamp, html, flags=re.S)
if not n:
    print("!! the page has no shots-meta span", file=sys.stderr)
page.write_text(html)
print(stamp)
PY
python3 "$root/website/build.py" >/dev/null
echo "site rebuilt; deploy with website/deploy.sh"
