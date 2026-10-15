#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Build an UNSIGNED iOS/iPadOS .ipa on a Mac (Xcode, xcodegen, rustup needed).
# AltStore, SideStore, Sideloadly and similar tools re-sign it with your own
# Apple ID when they install it; nothing here needs an Apple account.
#
#   apps/ios/make-ipa.sh [--out DIR] [--version V] [--build-number N]
#
# Result: DIR/Varsto-<version>-ios-unsigned.ipa (default DIR: dist/ios-ipa).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="$root/dist/ios-ipa"
version="$(grep -m1 '^version' "$root/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
build="1"
while [ $# -gt 0 ]; do
  case "$1" in
    --out) out="$(mkdir -p "$2" && cd "$2" && pwd)"; shift 2 ;;
    --version) version="$2"; shift 2 ;;
    --build-number) build="$2"; shift 2 ;;
    *) echo "usage: $0 [--out DIR] [--version V] [--build-number N]" >&2; exit 2 ;;
  esac
done
for tool in xcodegen xcodebuild plutil zip unzip cargo rustup; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool (brew install xcodegen; Xcode; rustup)" >&2; exit 1; }
done
mkdir -p "$out"

echo "== Rust static library for devices (aarch64-apple-ios)"
rustup target add aarch64-apple-ios >/dev/null
# One deployment target for the C dependencies (zstd, blake3, mimalloc) and the
# Rust link, matching project.yml; a mismatch leaves ___chkstk_darwin undefined.
export IPHONEOS_DEPLOYMENT_TARGET=16.0
cargo build --release --locked --target aarch64-apple-ios -p varsto-ffi --manifest-path "$root/Cargo.toml"

echo "== Xcode project and unsigned archive"
cd "$root/apps/ios"
xcodegen generate
rm -rf build/ipa && mkdir -p build/ipa
xcodebuild archive -project Varsto.xcodeproj -scheme Varsto -configuration Release \
  -destination 'generic/platform=iOS' -archivePath build/ipa/Varsto.xcarchive \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
  MARKETING_VERSION="$version" CURRENT_PROJECT_VERSION="$build" \
  -quiet 2>&1 | tee build/ipa/xcodebuild.log

echo "== Payload/Varsto.app"
app="build/ipa/Varsto.xcarchive/Products/Applications/Varsto.app"
[ -d "$app" ] || { echo "archive has no $app" >&2; exit 1; }
rm -rf build/ipa/stage && mkdir -p build/ipa/stage/Payload
ditto "$app" build/ipa/stage/Payload/Varsto.app
# Nothing is signed (the sideloader signs it); drop any leftover signature folder.
rm -rf build/ipa/stage/Payload/Varsto.app/_CodeSignature
ipa="$out/Varsto-$version-ios-unsigned.ipa"
rm -f "$ipa"
(cd build/ipa/stage && zip -qry "$ipa" Payload)

echo "== Checks"
listing="$(unzip -l "$ipa")"
echo "$listing"
echo "$listing" | grep -q ' Payload/Varsto.app/Info.plist$' || { echo "Info.plist is not at Payload/Varsto.app/" >&2; exit 1; }
echo "$listing" | grep -q ' Payload/Varsto.app/Varsto$' || { echo "executable missing" >&2; exit 1; }
chk="$(mktemp -d)"; trap 'rm -rf "$chk"' EXIT
unzip -q "$ipa" -d "$chk"
plist="$chk/Payload/Varsto.app/Info.plist"
plutil -lint "$plist"
want() { # key expected
  got="$(plutil -extract "$1" raw -o - "$plist")"
  [ "$got" = "$2" ] || { echo "Info.plist $1 is '$got', expected '$2'" >&2; exit 1; }
}
want CFBundleIdentifier in.soderlund.varsto.ios
want MinimumOSVersion 16.0
want CFBundleShortVersionString "$version"
plutil -extract NSLocalNetworkUsageDescription raw -o - "$plist" >/dev/null
plutil -extract UIDeviceFamily json -o - "$plist"; echo
[ -f "$chk/Payload/Varsto.app/Assets.car" ] || { echo "no Assets.car: app icon missing" >&2; exit 1; }
lipo -archs "$chk/Payload/Varsto.app/Varsto" | grep -qx arm64 || { echo "executable is not arm64" >&2; exit 1; }
echo "ipa: $ipa ($(du -h "$ipa" | cut -f1))"
