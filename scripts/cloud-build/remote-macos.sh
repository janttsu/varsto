#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Runs on a Scaleway Mac mini (Apple Silicon): installs the toolchain,
# builds the native Varsto.app, runs the tests, and captures a screenshot of
# the app window from the logged-in session.
set -euo pipefail
if ! xcode-select -p >/dev/null 2>&1; then
  echo "== installing Command Line Tools"
  touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
  label="$(softwareupdate -l 2>&1 | grep -o 'Label: Command Line Tools for Xcode-[0-9.]*' | sed 's/Label: //' | tail -1)"
  [ -n "$label" ] || { echo "no Command Line Tools label found" >&2; exit 1; }
  sudo -S softwareupdate -i "$label" --verbose < /tmp/sudo-pass
  rm -f /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
fi
if ! command -v cargo >/dev/null; then
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal >/dev/null
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
cd "$HOME/build/varsto"
echo "== $(sw_vers -productName) $(sw_vers -productVersion) $(uname -m), $(swiftc --version 2>&1 | head -1)"
echo "== tests on macOS"
cargo test --workspace --release 2>&1 | grep -E "test result|FAILED|panicked"
echo "== native app"
apps/macos/build.sh --out "$HOME/build/dist"
zip="$(ls "$HOME/build/dist"/Varsto-*-macos.zip)"
rm -rf "$HOME/build/app" && mkdir -p "$HOME/build/app" && ditto -x -k "$zip" "$HOME/build/app"
echo "== smoke test of the bundled command line"
export VARSTO_PASSPHRASE=cloud-test-passphrase-123
bin="$HOME/build/app/Varsto.app/Contents/MacOS/varsto"
"$bin" --version
"$bin" --home "$HOME/build/home" init --name mac-a >/dev/null
mkdir -p "$HOME/build/storage" "$HOME/build/files"
"$bin" --home "$HOME/build/home" storage add-local box "$HOME/build/storage" >/dev/null
"$bin" --home "$HOME/build/home" folder add docs "$HOME/build/files" >/dev/null
echo "hello from macos" > "$HOME/build/files/note.txt"
"$bin" --home "$HOME/build/home" sync
echo "== launching the app in the desktop session (screenshot after 8 s)"
VARSTO_NO_OPEN= open "$HOME/build/app/Varsto.app" || true
for i in $(seq 1 8); do sleep 1; done
pgrep -x Varsto >/dev/null && echo "app process running" || echo "app process NOT running"
screencapture -x "$HOME/build/dist/macos-app.png" 2>/dev/null && echo "screenshot taken" || echo "screenshot not possible (no GUI session)"
osascript -e 'tell application "Varsto" to quit' 2>/dev/null || pkill -x Varsto || true
echo "== done"
