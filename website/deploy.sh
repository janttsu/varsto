#!/usr/bin/env bash
# Deploys website/public to a web server over SSH with rsync.
# Configuration comes from the environment so no host names or addresses are committed:
#   DEPLOY_HOST   ssh destination, e.g. user@host
#   DEPLOY_PATH   target directory on the server (the web root)
set -euo pipefail
: "${DEPLOY_HOST:?set DEPLOY_HOST (user@host)}"
: "${DEPLOY_PATH:?set DEPLOY_PATH (web root on the server)}"
here="$(cd "$(dirname "$0")" && pwd)"
rsync -rltv --delete --chmod=D755,F644 "$here/public/" "${DEPLOY_HOST}:${DEPLOY_PATH}/"
