#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Build Varsto.app for macOS on a Mac: native Rust binary for this machine's
# architecture (or --arch arm64|x86_64), the Swift menu-bar app, an ad-hoc
# code signature, and a zip. Requires: Xcode command line tools, rustup.
#   apps/macos/build.sh [--arch arm64|x86_64] [--out DIR]
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
version="$(grep -m1 '^version' "$root/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
arch="$(uname -m)"; out="$root/website/public/downloads"
while [ $# -gt 0 ]; do
  case "$1" in
    --arch) arch="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
case "$arch" in
  arm64|aarch64) target=aarch64-apple-darwin; label=apple-silicon ;;
  x86_64) target=x86_64-apple-darwin; label=intel ;;
  *) echo "unsupported arch $arch" >&2; exit 2 ;;
esac
command -v swiftc >/dev/null || { echo "swiftc missing: run xcode-select --install" >&2; exit 1; }
command -v cargo >/dev/null || { echo "cargo missing: install rustup from https://rustup.rs" >&2; exit 1; }
rustup target add "$target" >/dev/null
echo "== Rust binary ($target)"
cargo build --release --target "$target" -p varsto-cli --features fsevents
stage="$(mktemp -d)"
app="$stage/Varsto.app/Contents"
mkdir -p "$app/MacOS" "$app/Resources"
echo "== Swift menu-bar app"
swiftc -O -target "${arch/aarch64/arm64}-apple-macos11.0" -framework AppKit -framework ServiceManagement \
  -o "$app/MacOS/Varsto" "$root/apps/macos/VarstoMenuBar/main.swift"
cp "$root/target/$target/release/varsto" "$app/MacOS/varsto"
cat > "$app/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Varsto</string>
  <key>CFBundleDisplayName</key><string>Varsto</string>
  <key>CFBundleIdentifier</key><string>in.soderlund.varsto</string>
  <key>CFBundleVersion</key><string>$version</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleExecutable</key><string>Varsto</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
</dict>
</plist>
PLIST
cp "$root/README.md" "$root/LICENSE" "$root/NOTICE" "$root/TRADEMARK.md" "$app/Resources/"
echo "== ad-hoc signature"
codesign --force --deep --sign - "$stage/Varsto.app"
mkdir -p "$out"
name="Varsto-$version-macos-$label.zip"
rm -f "$out/$name"
(cd "$stage" && ditto -c -k --keepParent Varsto.app "$out/$name")
echo "built $out/$name"
echo "Quick test: open \"$stage/Varsto.app\""
