#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Turn a directory of release packages into a download set: adds the source
# archive (from a git checkout), writes manifest.json (version and one entry
# per package for the download table) and SHA256SUMS, and signs it when the
# release key is available (scripts/sign-release.sh).
#   website/assemble-release.sh [dir]     (default website/public/downloads)
# Used at the end of website/build-release.sh and by CI, which builds the
# packages on several runners; CI never has the key, so its list is unsigned.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$(realpath "${1:-$root/website/public/downloads}")"
version="$(grep -m1 '^version' "$root/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
rm -f "$out/SHA256SUMS" "$out/SHA256SUMS.sig" "$out/manifest.json"
if [ ! -f "$out/varsto-$version-source.tar.gz" ]; then
  if git -C "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if git -C "$root" rev-parse --verify -q "v$version" >/dev/null; then ref="v$version"; else ref="HEAD"; fi
    echo "== source archive ($ref)"
    git -C "$root" archive --format=tar.gz --prefix="varsto-$version/" -o "$out/varsto-$version-source.tar.gz" "$ref"
  else
    echo "== source archive skipped (not a git checkout)"
  fi
fi
python3 - "$out" "$version" <<'PY'
import json, pathlib, sys
out, v = pathlib.Path(sys.argv[1]), sys.argv[2]
NOTES = [
    (f"varsto-{v}-x86_64-unknown-linux-musl.tar.gz", "Linux x86_64", "tray app + background service + command line; static binary (musl)"),
    (f"varsto-{v}-aarch64-unknown-linux-musl.tar.gz", "Linux arm64", "tray app + background service + command line; static binary (musl)"),
    (f"varsto-{v}-x86_64-pc-windows-gnu.zip", "Windows x86_64", "tray app + background service + command line; cross-compiled, tested on Windows Server 2025 by the build pipeline"),
    (f"Varsto-{v}-macos.dmg", "macOS app (Apple Silicon)", "disk image: drag Varsto to Applications. Native app with its own window, menu-bar item, Finder actions, background service and the varsto command line inside the bundle; built and ad-hoc signed on a Mac, not notarised"),
    (f"varsto-{v}-aarch64-apple-darwin.tar.gz", "macOS (Apple Silicon) command line", "service + browser interface; cross-compiled, unsigned"),
    (f"varsto-{v}-x86_64-apple-darwin.tar.gz", "macOS (Intel) command line", "service + browser interface; cross-compiled, unsigned"),
    (f"Varsto-{v}-macos-apple-silicon-lite.zip", "macOS app (Apple Silicon), lite", "background service + browser interface, no menu-bar icon; unsigned, cross-compiled, not yet tested on a Mac"),
    (f"Varsto-{v}-macos-intel-lite.zip", "macOS app (Intel), lite", "background service + browser interface, no menu-bar icon; unsigned, cross-compiled, not yet tested on a Mac"),
    (f"varsto-{v}-android-debug.apk", "Android (arm64, x86_64)", "debug-signed APK for sideloading; foreground service + in-app interface; tested in the emulator by the build pipeline"),
    (f"varsto-{v}-source.tar.gz", "Source", "git archive of the release"),
]
m = {"_version": v}
names = []
for name, platform, note in NOTES:
    if (out / name).is_file():
        m[name] = {"platform": platform, "note": note}
        names.append(name)
# The native disk image replaces the cross-compiled lite apps.
if f"Varsto-{v}-macos.dmg" in m:
    for k in [k for k in m if k.endswith("-lite.zip")]:
        del m[k]; names.remove(k)
other = sorted(p.name for p in out.iterdir() if p.is_file() and (p.name.startswith(f"varsto-{v}-") or p.name.startswith(f"Varsto-{v}-")) and p.name not in names)
if other:
    print("not in the manifest (unknown kind):", ", ".join(other))
(out / "manifest.json").write_text(json.dumps(m, indent=2) + "\n")
(out / ".release-files").write_text("\n".join(names) + "\n")
PY
(cd "$out" && xargs -a .release-files sha256sum > SHA256SUMS && rm -f .release-files)
cat "$out/SHA256SUMS"
echo "== signing SHA256SUMS"
if ! "$root/scripts/sign-release.sh" "$out/SHA256SUMS"; then
  echo "!! SHA256SUMS is NOT signed: run scripts/sign-release.sh before deploying (updates refuse unsigned releases)" >&2
fi
