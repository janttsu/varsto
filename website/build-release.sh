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
# Keep a Mac-built native app (Varsto-<version>-macos.zip) if one is already here.
for f in "$out"/varsto-"$version"-* "$out"/Varsto-"$version"-*; do
  [ -e "$f" ] || continue
  case "$f" in *"/Varsto-$version-macos.zip") ;; *) rm -f "$f" ;; esac
done
rm -f "$out/SHA256SUMS" "$out/manifest.json"
targets=("$@")
have_zig=0
command -v cargo-zigbuild >/dev/null 2>&1 && have_zig=1
if [ ${#targets[@]} -eq 0 ]; then
  targets=(x86_64-unknown-linux-musl x86_64-pc-windows-gnu)
  [ "$have_zig" = 1 ] && targets+=(aarch64-apple-darwin)
fi
manifest="{\"_version\": \"$version\""
mac_bins=()

build_target() {
  local t="$1"
  case "$t" in
    *apple-darwin*)
      if [ "$have_zig" != 1 ]; then echo "!! cargo-zigbuild missing, cannot build $t" >&2; return 1; fi
      cargo zigbuild --release --target "$t" -p varsto-cli 2>&1 | grep -vE "^\s+(Compiling|Downloaded|Downloading)" | tail -40 ;;
    *musl*)
      export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-gcc}"
      cargo build --release --target "$t" -p varsto-cli 2>&1 | grep -vE "^\s+(Compiling|Downloaded|Downloading)" | tail -40 ;;
    *windows-gnu*)
      export CC_x86_64_pc_windows_gnu="${CC_x86_64_pc_windows_gnu:-x86_64-w64-mingw32-gcc}" AR_x86_64_pc_windows_gnu="${AR_x86_64_pc_windows_gnu:-x86_64-w64-mingw32-ar}"
      cargo build --release --target "$t" -p varsto-cli 2>&1 | grep -vE "^\s+(Compiling|Downloaded|Downloading)" | tail -40 ;;
    *)
      cargo build --release --target "$t" -p varsto-cli 2>&1 | grep -vE "^\s+(Compiling|Downloaded|Downloading)" | tail -40 ;;
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
      printf '@echo off\r\nstart "" /B "%%~dp0varsto.exe" tray --open\r\n' > "$stage/$name/Varsto.cmd"
      printf 'Varsto for Windows (alpha, cross-compiled, not yet tested on Windows).\r\n\r\nDouble-click Varsto.cmd: a tray icon appears, the background service starts and the\r\nlocal interface opens in your browser. Start at login: varsto.exe service install\r\nCommand line: varsto.exe --help. Updates: tray menu or varsto.exe update.\r\n' > "$stage/$name/README-Windows.txt"
      (cd "$stage" && zip -qr "$out/$name.zip" "$name")
      manifest+=", \"$name.zip\": {\"platform\": \"Windows x86_64\", \"note\": \"tray app + background service + command line; cross-compiled, not tested on Windows\"}"
      ;;
    *apple-darwin*)
      mac_bins+=("$root/target/$t/release/varsto")
      cp "$root/target/$t/release/varsto" "$stage/$name/"
      tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
      arch="Apple Silicon"; [[ "$t" == x86_64* ]] && arch="Intel"
      manifest+=", \"$name.tar.gz\": {\"platform\": \"macOS ($arch) command line\", \"note\": \"service + browser interface; cross-compiled, unsigned\"}"
      ;;
    *)
      cp "$root/target/$t/release/varsto" "$stage/$name/"
      strip "$stage/$name/varsto" 2>/dev/null || true
      cp "$root/brand/logo.svg" "$stage/$name/varsto.svg"
      printf '[Desktop Entry]\nType=Application\nName=Varsto\nComment=Encrypted sync with your own storage\nExec=varsto tray --open\nIcon=varsto\nTerminal=false\nCategories=Network;Utility;\n' > "$stage/$name/varsto.desktop"
      printf 'Varsto for Linux (alpha; static binary).\n\n./varsto            tray icon + background service (default)\n./varsto desktop    service + browser interface, no tray\n./varsto service install   start the tray app at login (autostart entry)\n./varsto update     self-update from the download page\nInstall: copy varsto to ~/.local/bin, varsto.desktop to ~/.local/share/applications and varsto.svg to ~/.local/share/icons/hicolor/scalable/apps/.\n' > "$stage/$name/README-Linux.txt"
      tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
      manifest+=", \"$name.tar.gz\": {\"platform\": \"Linux x86_64\", \"note\": \"tray app + background service + command line; static binary (musl)\"}"
      ;;
  esac
  rm -rf "$stage"
done

# macOS app bundles, one per architecture (cross-compiled: Rust binary only, no
# menu bar; the native menu-bar app is built on a Mac with apps/macos/build.sh).
if [ -f "$out/Varsto-$version-macos.zip" ]; then
  echo "== Varsto.app (built on a Mac, kept)"
  manifest+=", \"Varsto-$version-macos.zip\": {\"platform\": \"macOS app (Apple Silicon)\", \"note\": \"native app: own window, menu-bar item, background service and the varsto command line inside the bundle; built and ad-hoc signed on a Mac, not notarised\"}"
  mac_bins=()
fi
for bin in "${mac_bins[@]}"; do
  case "$bin" in *aarch64*) label=apple-silicon; arch_text="Apple Silicon" ;; *) label=intel; arch_text="Intel" ;; esac
  echo "== Varsto.app ($label, cross-compiled)"
  stage="$(mktemp -d)"
  app="$stage/Varsto.app/Contents"
  mkdir -p "$app/MacOS" "$app/Resources"
  cp "$bin" "$app/MacOS/varsto"; chmod 755 "$app/MacOS/varsto"
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
  <key>CFBundleIconFile</key><string>Varsto</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
</dict>
</plist>
PLIST
  cp "$root/README.md" "$root/LICENSE" "$root/NOTICE" "$root/TRADEMARK.md" "$app/Resources/"
  [ -f "$root/brand/Varsto.icns" ] && cp "$root/brand/Varsto.icns" "$app/Resources/Varsto.icns"
  cat > "$stage/README-macOS.txt" <<TXT
Varsto $version for macOS ($arch_text; alpha; unsigned; cross-compiled, no menu-bar icon).

The app is not signed or notarised. The first time, right-click Varsto.app and
choose Open, or run:  xattr -dr com.apple.quarantine Varsto.app
Double-clicking starts the background service and opens the local interface in
your browser. Command line: Varsto.app/Contents/MacOS/varsto --help
To start at login: Varsto.app/Contents/MacOS/varsto service install
TXT
  (cd "$stage" && zip -qr "$out/Varsto-$version-macos-$label-lite.zip" Varsto.app README-macOS.txt)
  manifest+=", \"Varsto-$version-macos-$label-lite.zip\": {\"platform\": \"macOS app ($arch_text), lite\", \"note\": \"background service + browser interface, no menu-bar icon; unsigned, cross-compiled, not yet tested on a Mac\"}"
  rm -rf "$stage"
done

# Android APK, if the app has been built (apps/android/build.sh).
apk="$root/apps/android/app/build/outputs/apk/debug/app-debug.apk"
if [ -f "$apk" ]; then
  echo "== Android APK"
  cp "$apk" "$out/varsto-$version-android-debug.apk"
  manifest+=", \"varsto-$version-android-debug.apk\": {\"platform\": \"Android (arm64, x86_64)\", \"note\": \"debug-signed APK for sideloading; foreground service + in-app interface; tested in the emulator only\"}"
fi

echo "== source archive"
if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if git -C "$root" rev-parse --verify -q "v$version" >/dev/null; then ref="v$version"; else ref="HEAD"; fi
  git -C "$root" archive --format=tar.gz --prefix="varsto-$version/" -o "$out/varsto-$version-source.tar.gz" "$ref"
  manifest+=", \"varsto-$version-source.tar.gz\": {\"platform\": \"Source\", \"note\": \"git archive of $ref\"}}"
else
  echo "== source archive skipped (not a git checkout)"
  manifest+="}"
fi
echo "$manifest" | python3 -c "import json,sys; json.dump(json.load(sys.stdin), sys.stdout, indent=2)" > "$out/manifest.json"
(cd "$out" && sha256sum varsto-"$version"-* Varsto-"$version"-* 2>/dev/null > SHA256SUMS)
cat "$out/SHA256SUMS"
