#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Runs on a fresh Ubuntu build instance: installs the toolchain, runs the
# whole test suite on a real Linux, builds the release archives.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential musl-tools pkg-config curl git zip unzip ffmpeg libdbus-1-dev >/dev/null
# A current rclone (the distribution package is too old for `rclone serve s3`).
curl -fsS https://rclone.org/install.sh | bash >/dev/null 2>&1 || true
rclone version | head -1
if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
rustup target add x86_64-unknown-linux-musl >/dev/null
cd /build/varsto
echo "== tests on $(lsb_release -ds) $(uname -m)"
cargo test --workspace --release 2>&1 | grep -E "test result|FAILED|panicked" 
echo "== release archives"
website/build-release.sh x86_64-unknown-linux-musl 2>&1 | tail -60
ls -la website/public/downloads/
