#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Build release archives for the website downloads directory.
#
# Usage: website/build-release.sh [target ...]
# Default targets: x86_64-unknown-linux-musl, x86_64-pc-windows-gnu and, when
# cargo-zigbuild is available, aarch64-apple-darwin + x86_64-apple-darwin
# (combined into one universal binary with llvm-lipo and packaged as Varsto.app).
# Output: website/public/downloads/<name>, SHA256SUMS, manifest.json, source archive.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
version="$(grep -m1 '^version' "$root/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
out="$root/website/public/downloads"
mkdir -p "$out"
rm -f "$out"/varsto-"$version"-* "$out/Varsto-$version-macos.zip" "$out/SHA256SUMS" "$out/manifest.json"
targets=("$@")
have_zig=0
command -v cargo-zigbuild >/dev/null 2>&1 && have_zig=1
if [ ${#targets[@]} -eq 0 ]; then
  targets=(x86_64-unknown-linux-musl x86_64-pc-windows-gnu)
  [ "$have_zig" = 1 ] && targets+=(aarch64-apple-darwin x86_64-apple-darwin)
fi
manifest="{\"_version\": \"$version\""
mac_bins=()

build_target() {
  local t="$1"
  case "$t" in
    *apple-darwin*)
      if [ "$have_zig" != 1 ]; then echo "!! cargo-zigbuild missing, cannot build $t" >&2; return 1; fi
      cargo zigbuild --release --target "$t" -p varsto-cli 2>&1 | grep -vE "^\s+(Compiling|Downloaded)" | tail -2 ;;
    *musl*)
      export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-gcc}"
      cargo build --release --target "$t" -p varsto-cli 2>&1 | tail -1 ;;
    *windows-gnu*)
      export CC_x86_64_pc_windows_gnu="${CC_x86_64_pc_windows_gnu:-x86_64-w64-mingw32-gcc}" AR_x86_64_pc_windows_gnu="${AR_x86_64_pc_windows_gnu:-x86_64-w64-mingw32-ar}"
      cargo build --release --target "$t" -p varsto-cli 2>&1 | tail -1 ;;
    *)
      cargo build --release --target "$t" -p varsto-cli 2>&1 | tail -1 ;;
  esac
}

for t in "${targets[@]}"; do
  echo "== building $t"
  if ! build_target "$t"; then echo "!! build failed for $t, skipping" >&2; continue; fi
  stage="$(mktemp -d)"
  name="varsto-$version-$t"
  mkdir -p "$stage/$name"
  cp "$root/README.md" "$root/LICENSE" "$root/NOTICE" "$root/TRADEMARK.md" "$stage/$name/"
  case "$t" in
    *windows*)
      cp "$root/target/$t/release/varsto.exe" "$stage/$name/"
      printf '@echo off\r\n"%%~dp0varsto.exe" desktop\r\n' > "$stage/$name/Varsto Desktop.cmd"
      (cd "$stage" && zip -qr "$out/$name.zip" "$name")
      manifest+=", \"$name.zip\": {\"platform\": \"Windows x86_64\", \"note\": \"command line + desktop UI; cross-compiled, not tested on Windows\"}"
      ;;
    *apple-darwin*)
      mac_bins+=("$root/target/$t/release/varsto")
      cp "$root/target/$t/release/varsto" "$stage/$name/"
      tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
      arch="Apple Silicon"; [[ "$t" == x86_64* ]] && arch="Intel"
      manifest+=", \"$name.tar.gz\": {\"platform\": \"macOS ($arch)\", \"note\": \"command line + desktop UI; cross-compiled, unsigned\"}"
      ;;
    *)
      cp "$root/target/$t/release/varsto" "$stage/$name/"
      strip "$stage/$name/varsto" 2>/dev/null || true
      tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
      manifest+=", \"$name.tar.gz\": {\"platform\": \"Linux x86_64\", \"note\": \"command line + desktop UI; static binary (musl)\"}"
      ;;
  esac
  rm -rf "$stage"
done

# macOS app bundle with a universal binary (Apple Silicon + Intel).
if [ ${#mac_bins[@]} -gt 0 ]; then
  echo "== Varsto.app"
  stage="$(mktemp -d)"
  app="$stage/Varsto.app/Contents"
  mkdir -p "$app/MacOS" "$app/Resources"
  if [ ${#mac_bins[@]} -ge 2 ] && command -v llvm-lipo >/dev/null 2>&1; then
    llvm-lipo -create "${mac_bins[@]}" -output "$app/MacOS/varsto"
    kind="universal (Apple Silicon + Intel)"
  else
    cp "${mac_bins[0]}" "$app/MacOS/varsto"; kind="single architecture"
  fi
  chmod 755 "$app/MacOS/varsto"
  cat > "$app/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Varsto</string>
  <key>CFBundleDisplayName</key><string>Varsto</string>
  <key>CFBundleIdentifier</key><string>in.soderlund.varsto.alpha</string>
  <key>CFBundleVersion</key><string>$version</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleExecutable</key><string>varsto</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
</dict>
</plist>
PLIST
  cp "$root/README.md" "$root/LICENSE" "$root/NOTICE" "$root/TRADEMARK.md" "$app/Resources/"
  cat > "$stage/README-macOS.txt" <<TXT
Varsto $version for macOS (alpha, $kind, unsigned).

The app is not signed or notarised. The first time, right-click Varsto.app and
choose Open, or run:  xattr -dr com.apple.quarantine Varsto.app
Double-clicking opens the local desktop interface in your browser. For the
command line, use Varsto.app/Contents/MacOS/varsto (for example: varsto --help).
Cross-compiled on Linux; not yet tested on a Mac. Use test data only.
TXT
  (cd "$stage" && zip -qr "$out/Varsto-$version-macos.zip" Varsto.app README-macOS.txt)
  manifest+=", \"Varsto-$version-macos.zip\": {\"platform\": \"macOS app\", \"note\": \"double-click to open the desktop UI; $kind; unsigned, not yet tested on a Mac\"}"
  rm -rf "$stage"
fi

echo "== source archive"
if git -C "$root" rev-parse --verify -q "v$version" >/dev/null; then ref="v$version"; else ref="HEAD"; fi
git -C "$root" archive --format=tar.gz --prefix="varsto-$version/" -o "$out/varsto-$version-source.tar.gz" "$ref"
manifest+=", \"varsto-$version-source.tar.gz\": {\"platform\": \"Source\", \"note\": \"git archive of $ref\"}}"
echo "$manifest" | python3 -c "import json,sys; json.dump(json.load(sys.stdin), sys.stdout, indent=2)" > "$out/manifest.json"
(cd "$out" && sha256sum varsto-"$version"-* Varsto-"$version"-macos.zip 2>/dev/null > SHA256SUMS)
cat "$out/SHA256SUMS"
