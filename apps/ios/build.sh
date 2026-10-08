#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Build the iOS app on a Mac: Rust static library, then the Xcode project.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
command -v xcodegen >/dev/null || { echo "install xcodegen (brew install xcodegen)" >&2; exit 1; }
rustup target add aarch64-apple-ios aarch64-apple-ios-sim >/dev/null
# One deployment target for the C dependencies (zstd, blake3) and the Rust link,
# matching project.yml; a mismatch leaves ___chkstk_darwin undefined.
export IPHONEOS_DEPLOYMENT_TARGET=16.0
cargo build --release --target aarch64-apple-ios -p varsto-ffi
cargo build --release --target aarch64-apple-ios-sim -p varsto-ffi
cd "$root/apps/ios" && xcodegen generate
# -quiet prints only warnings, errors and the result; the full log goes to build/xcodebuild.log.
mkdir -p build
xcodebuild -project Varsto.xcodeproj -scheme Varsto -sdk iphonesimulator -configuration Release \
  -derivedDataPath build CODE_SIGNING_ALLOWED=NO -quiet build 2>&1 | tee build/xcodebuild.log
echo "app: apps/ios/build/Build/Products/Release-iphonesimulator/Varsto.app"
echo "Open apps/ios/Varsto.xcodeproj in Xcode to run on a device (signing needed)."
