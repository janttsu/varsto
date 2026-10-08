#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Build release archives for the website downloads directory.
# Usage: website/build-release.sh [target ...]
# Default targets: x86_64-unknown-linux-musl x86_64-pc-windows-gnu (whatever is installed).
# Output: website/public/downloads/<name>, SHA256SUMS, manifest.json, source archive.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
version="$(grep -m1 '^version' "$root/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
out="$root/website/public/downloads"
mkdir -p "$out"
rm -f "$out"/varsto-"$version"-* "$out/SHA256SUMS" "$out/manifest.json"
targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=(x86_64-unknown-linux-musl x86_64-pc-windows-gnu)
fi
manifest="{\"_version\": \"$version\""
for t in "${targets[@]}"; do
  echo "== building $t"
  case "$t" in
    *musl*) export CC_x86_64_unknown_linux_musl="${CC_x86_64_unknown_linux_musl:-gcc}" ;;
    *windows-gnu*) export CC_x86_64_pc_windows_gnu="${CC_x86_64_pc_windows_gnu:-x86_64-w64-mingw32-gcc}" AR_x86_64_pc_windows_gnu="${AR_x86_64_pc_windows_gnu:-x86_64-w64-mingw32-ar}" ;;
  esac
  if ! cargo build --release --target "$t" -p varsto-cli; then
    echo "!! build failed for $t, skipping" >&2
    continue
  fi
  stage="$(mktemp -d)"
  name="varsto-$version-$t"
  mkdir -p "$stage/$name"
  cp "$root/README.md" "$root/LICENSE" "$root/NOTICE" "$root/TRADEMARK.md" "$stage/$name/"
  case "$t" in
    *windows*)
      cp "$root/target/$t/release/varsto.exe" "$stage/$name/"
      (cd "$stage" && zip -qr "$out/$name.zip" "$name")
      manifest+=", \"$name.zip\": {\"platform\": \"Windows x86_64\", \"note\": \"cross-compiled, not tested on Windows\"}"
      ;;
    *)
      cp "$root/target/$t/release/varsto" "$stage/$name/"
      strip "$stage/$name/varsto" 2>/dev/null || true
      tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
      manifest+=", \"$name.tar.gz\": {\"platform\": \"Linux x86_64\", \"note\": \"static binary (musl)\"}"
      ;;
  esac
  rm -rf "$stage"
done
echo "== source archive"
if git -C "$root" rev-parse --verify -q "v$version" >/dev/null; then ref="v$version"; else ref="HEAD"; fi
git -C "$root" archive --format=tar.gz --prefix="varsto-$version/" -o "$out/varsto-$version-source.tar.gz" "$ref"
manifest+=", \"varsto-$version-source.tar.gz\": {\"platform\": \"Source\", \"note\": \"git archive of $ref\"}}"
echo "$manifest" | python3 -c "import json,sys; json.dump(json.load(sys.stdin), sys.stdout, indent=2)" > "$out/manifest.json"
(cd "$out" && sha256sum varsto-"$version"-* > SHA256SUMS)
cat "$out/SHA256SUMS"
