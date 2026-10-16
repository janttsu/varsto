#!/usr/bin/env bash
# Deploys website/public to a web server over SSH with rsync.
# Configuration comes from the environment so no host names or addresses are committed:
#   DEPLOY_HOST   ssh destination, e.g. user@host
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
# Without a local download set (a fresh checkout deploying a page or a
# screenshot), leave the server's downloads alone instead of deleting them.
# The server's screenshots come from CI (ops/site/screenshots-sync.py).
# /testbuilds/ and /daily/ hold large files that are uploaded by hand or by the
# daily build workflow, outside this repository: never delete them. Only the
# generated daily page (/daily/index.html) is part of the site.
keep=(--exclude /assets/img/screenshots/ --exclude /testbuilds/ --include /daily/ --include /daily/index.html --exclude '/daily/*')
[ -f "$here/public/downloads/manifest.json" ] || { keep+=(--exclude /downloads/); echo "no local download set: the server's downloads stay as they are"; }
rsync -rltv --delete "${keep[@]}" --chmod=D755,F644 "$here/public/" "${DEPLOY_HOST}:${DEPLOY_PATH}/"
