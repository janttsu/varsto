#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Publish a Mac-built Varsto.app zip to the download page from a Mac:
# fetches the live checksum list and manifest, adds (or replaces) the macOS
# entry, rebuilds the site and deploys it with rsync.
#   website/publish-macos.sh apps/macos/dist/Varsto-<version>-macos.zip
# Needs: pandoc (brew install pandoc), python3, rsync, SSH access to the
# site host (DEPLOY_HOST, default "dedibox"; DEPLOY_PATH, default
# sites/varsto/public, relative to the home directory on that host).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
zip="${1:?usage: publish-macos.sh <Varsto-<version>-macos.zip>}"
site="${SITE_URL:-https://varsto.soderlund.in}"
out="$root/website/public/downloads"
mkdir -p "$out"
name="$(basename "$zip")"
version="$(grep -m1 '^version' "$root/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
case "$name" in Varsto-"$version"-macos.zip) ;; *) echo "$name does not match version $version in Cargo.toml" >&2; exit 2 ;; esac
cp "$zip" "$out/$name"
curl -fsS "$site/downloads/SHA256SUMS" -o "$out/SHA256SUMS"
curl -fsS "$site/downloads/manifest.json" -o "$out/manifest.json"
# The site build reads file sizes from disk: fetch the other artifacts' sizes
# by downloading them once (they are a few megabytes each).
grep -o '[A-Za-z0-9._-]*$' "$out/SHA256SUMS" | while read -r f; do
  [ -f "$out/$f" ] || curl -fsS "$site/downloads/$f" -o "$out/$f"
done
python3 - "$out" "$name" <<'PY'
import hashlib, json, sys, pathlib
out, name = pathlib.Path(sys.argv[1]), sys.argv[2]
digest = hashlib.sha256((out / name).read_bytes()).hexdigest()
lines = [l for l in (out / "SHA256SUMS").read_text().splitlines() if l.strip() and not l.endswith(name) and "-macos-" not in l.split()[-1] and not l.split()[-1].endswith("-apple-darwin.tar.gz")]
lines.append(f"{digest}  {name}")
(out / "SHA256SUMS").write_text("\n".join(lines) + "\n")
m = json.loads((out / "manifest.json").read_text())
for k in [k for k in m if "-macos-" in k or k.endswith("-apple-darwin.tar.gz")]:
    del m[k]
m[name] = {"platform": "macOS app (Apple Silicon)", "note": "native app: own window, menu-bar item, background service and the varsto command line inside the bundle; built and ad-hoc signed on a Mac, not notarised"}
(out / "manifest.json").write_text(json.dumps(m, indent=2) + "\n")
print("download table entry added for", name)
PY
python3 "$root/website/build.py"
DEPLOY_HOST="${DEPLOY_HOST:-dedibox}" DEPLOY_PATH="${DEPLOY_PATH:-sites/varsto/public}" "$root/website/deploy.sh"
echo "published: $site/downloads/$name"
