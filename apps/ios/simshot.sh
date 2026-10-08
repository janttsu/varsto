#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Boot an iPhone Simulator, install the app built by build.sh, launch it and
# save a screenshot plus the app bundle:  apps/ios/simshot.sh [OUT_DIR]
set -euxo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
out="${1:-$root/dist/ios}"
mkdir -p "$out"
app="$root/apps/ios/build/Build/Products/Release-iphonesimulator/Varsto.app"
[ -d "$app" ] || { echo "build first: apps/ios/build.sh" >&2; exit 1; }
udid="$(xcrun simctl list devices available -j | python3 -c '
import json, re, sys
devs = [d for v in json.load(sys.stdin)["devices"].values() for d in v if d["name"].startswith("iPhone")]
# Newest numbered iPhone, Pro over Plus over base; the SE models last.
def rank(d):
    m = re.match(r"iPhone (\d+)( Pro Max| Pro| Plus|e)?$", d["name"])
    return (int(m.group(1)), {" Pro": 3, " Pro Max": 2, " Plus": 1, None: 1, "e": 0}[m.group(2)]) if m else (0, 0)
print(sorted(devs, key=rank)[-1]["udid"])')"
xcrun simctl boot "$udid" 2>/dev/null || true
xcrun simctl bootstatus "$udid" -b
xcrun simctl install "$udid" "$app"
xcrun simctl launch "$udid" in.soderlund.varsto.ios
sleep 20
xcrun simctl io "$udid" screenshot "$out/ios-simulator.png"
xcrun simctl spawn "$udid" log show --last 2m --predicate 'process == "Varsto"' > "$out/ios-simulator.log" 2>/dev/null || true
xcrun simctl shutdown "$udid"
# Crash reports of the app, if it died after launch.
for f in $(ls -t ~/Library/Logs/DiagnosticReports/Varsto* 2>/dev/null | head -3 || true); do cp "$f" "$out/"; done
ditto -c -k --keepParent "$app" "$out/Varsto-ios-simulator.zip"
ls -l "$out"
