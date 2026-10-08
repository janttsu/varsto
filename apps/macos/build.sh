#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Build Varsto.app for Apple Silicon on a Mac: the native Rust binary (service
# and command line, placed inside the bundle), the Swift app (own window with
# the interface, menu-bar item), an ad-hoc code signature, and a zip.
# Requires: Xcode command line tools (xcode-select --install) and rustup.
#   apps/macos/build.sh [--out DIR]      default DIR: apps/macos/dist
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
version="$(grep -m1 '^version' "$root/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
out="$root/apps/macos/dist"
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
[ "$(uname -s)" = Darwin ] || { echo "run this on a Mac" >&2; exit 1; }
command -v swiftc >/dev/null || { echo "swiftc missing: run xcode-select --install" >&2; exit 1; }
command -v cargo >/dev/null || { echo "cargo missing: install rustup from https://rustup.rs" >&2; exit 1; }
target=aarch64-apple-darwin
# With rustup, make sure the target is installed; a Homebrew toolchain on an
# Apple Silicon Mac already has it as its host target.
if command -v rustup >/dev/null; then rustup target add "$target" >/dev/null; fi
echo "== Rust binary ($target)"
cargo build --release --target "$target" -p varsto-cli --features fsevents
stage="$(mktemp -d)"
app="$stage/Varsto.app/Contents"
mkdir -p "$app/MacOS" "$app/Helpers" "$app/Resources"
echo "== Swift app"
swiftc -O -target arm64-apple-macos12.0 -framework AppKit -framework WebKit -framework ServiceManagement \
  -o "$app/MacOS/Varsto" "$root/apps/macos/VarstoMenuBar/main.swift"
# The command line goes to Contents/Helpers: the Mac file system is case-
# insensitive, so "varsto" next to the app executable "Varsto" would replace it.
cp "$root/target/$target/release/varsto" "$app/Helpers/varsto"
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
  <key>CFBundleIconFile</key><string>Varsto</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSAppTransportSecurity</key><dict><key>NSAllowsLocalNetworking</key><true/></dict>
</dict>
</plist>
PLIST
echo "== app icon"
if [ -f "$root/brand/Varsto.icns" ]; then
  cp "$root/brand/Varsto.icns" "$app/Resources/Varsto.icns"
else
  # Build the .icns from the brand PNGs (iconutil ships with macOS).
  iconset="$stage/Varsto.iconset"
  mkdir -p "$iconset"
  for size in 16 32 128 256 512; do
    cp "$root/brand/png/logo-$size.png" "$iconset/icon_${size}x${size}.png"
    double=$((size * 2))
    cp "$root/brand/png/logo-$double.png" "$iconset/icon_${size}x${size}@2x.png"
  done
  iconutil -c icns "$iconset" -o "$app/Resources/Varsto.icns"
fi
cp "$root/README.md" "$root/LICENSE" "$root/NOTICE" "$root/TRADEMARK.md" "$app/Resources/"
echo "== ad-hoc signature"
codesign --force --sign - "$app/Helpers/varsto"
codesign --force --deep --sign - "$stage/Varsto.app"
mkdir -p "${out:?}"
name="Varsto-$version-macos.zip"
rm -f "${out:?}/${name:?}"
(cd "$stage" && ditto -c -k --keepParent Varsto.app "$out/$name")
shasum -a 256 "$out/$name"
echo
echo "built $out/$name"
echo "Test now:   open \"$stage/Varsto.app\""
echo "Publish:    website/publish-macos.sh \"$out/$name\"   (uploads it and updates the download page)"
