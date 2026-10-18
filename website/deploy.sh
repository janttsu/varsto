#!/usr/bin/env bash
# Deploys website/public to a web server over SSH with rsync.
# Configuration comes from the environment so no host names or addresses are committed:
#   DEPLOY_HOST   ssh destination, e.g. user@host; the word "local" copies to the
#                 directory DEPLOY_PATH on this machine instead (dry runs and tests)
#   DEPLOY_PATH   target directory on the server (the web root)
set -euo pipefail
: "${DEPLOY_HOST:?set DEPLOY_HOST (user@host)}"
: "${DEPLOY_PATH:?set DEPLOY_PATH (web root on the server)}"
here="$(cd "$(dirname "$0")" && pwd)"
# Never publish a checksum list the updater would refuse.
if [ -f "$here/public/downloads/SHA256SUMS" ]; then
  "$here/../scripts/sign-release.sh" --verify "$here/public/downloads/SHA256SUMS" \
    || { echo "SHA256SUMS or manifest.json is not signed with the release key; run scripts/sign-release.sh first" >&2; exit 1; }
fi
# A page that says "No binaries are published yet" was rendered without a
# download set (and without the live list build.py reads as a fallback); it
# would replace the live downloads page with an empty one. Refuse, whatever
# the language or path (2026-10-16: the fi/sv/fr pages went live that way).
stubs="$(grep -rlF --include=index.html "No binaries are published yet" "$here/public" 2>/dev/null || true)"
if [ -n "$stubs" ] && [ "${ALLOW_DOWNLOAD_STUB:-}" != 1 ]; then
  echo "refusing to deploy: these pages were built without a download set (run website/build.py with network access, or with a download set in website/public/downloads):" >&2
  echo "$stubs" | sed "s|^$here/public/|  |" >&2
  exit 1
fi
# Without a local download set (a fresh checkout deploying a page or a
# screenshot), leave the server's downloads alone instead of deleting them.
# The server's screenshots (English, Finnish and Swedish sets and the
# visualization picture) come from CI (ops/site/screenshots-sync.py).
# /testbuilds/ and /daily/ hold large files that are uploaded by hand or by the
# daily build workflow, outside this repository: never delete them. Only the
# generated daily page (/daily/index.html) is part of the site.
keep=(--exclude /assets/img/screenshots/ --exclude /assets/img/screenshots-fi/ --exclude /assets/img/screenshots-sv/ --exclude /assets/img/viz-tv.png
      --exclude /testbuilds/ --include /daily/ --include /daily/index.html --exclude '/daily/*')
[ -f "$here/public/downloads/manifest.json" ] || { keep+=(--exclude /downloads/); echo "no local download set: the server's downloads stay as they are"; }
dest="${DEPLOY_HOST}:${DEPLOY_PATH}/"
[ "$DEPLOY_HOST" = local ] && dest="${DEPLOY_PATH}/"
rsync -rltv --delete "${keep[@]}" --chmod=D755,F644 "$here/public/" "$dest"
