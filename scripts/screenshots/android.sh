#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# Install the APK in a running emulator (or a test phone), check that the app
# and its service start, set up an invented vault through the service API and
# capture the first-run screen, the overview and the files view, light and
# dark.  scripts/screenshots/android.sh <apk> <out dir>
# Needs adb on PATH and exactly one device. Writes android-{light,dark}.png,
# android-overview-{light,dark}.png and android-files-{light,dark}.png
# (screen size; finalize.py scales them for the website).
set -euo pipefail
apk="$1"; out="$(mkdir -p "$2" && realpath "$2")"
pkg=in.soderlund.varsto
for i in $(seq 1 100); do [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ] && break; sleep 3; done
echo "== device: $(adb shell getprop ro.product.model | tr -d '\r'), Android $(adb shell getprop ro.build.version.release | tr -d '\r'), $(adb shell wm size | tr -d '\r')"
shot() { adb exec-out screencap -p > "$out/$1.png"; echo "   $1.png"; }
night() { adb shell cmd uimode night "$1" >/dev/null; sleep "${2:-6}"; }
adb shell settings put global window_animation_scale 0 || true
adb shell settings put global transition_animation_scale 0 || true
night no 1
adb uninstall "$pkg" >/dev/null 2>&1 || true
adb install -r "$apk" | tail -1
adb shell pm grant "$pkg" android.permission.POST_NOTIFICATIONS 2>/dev/null || true
adb shell am start -n "$pkg/.MainActivity" >/dev/null
sj=""
for i in $(seq 1 60); do
  sj="$(adb shell run-as "$pkg" cat files/vault/service.json 2>/dev/null || true)"
  case "$sj" in *token*) break ;; esac
  sleep 2
done
case "$sj" in *token*) echo "== service started" ;; *) echo "!! no service.json after 120 s" >&2; adb logcat -d -t 200 | grep -i varsto | tail -40 >&2; exit 1 ;; esac
sleep 10
shot android-light
night yes; shot android-dark; night no 3
port="$(echo "$sj" | python3 -c 'import json,sys; print(json.load(sys.stdin)["port"])')"
token="$(echo "$sj" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
adb forward tcp:18790 "tcp:$port" >/dev/null
api() {
  local r code
  # The body is printed on failure (the service answers {"error": ...}).
  r="$(curl -sS -w '\n%{http_code}' -X POST "http://127.0.0.1:18790$1" -H "Host: 127.0.0.1:$port" -H "X-Varsto-Token: $token" -H "Content-Type: application/json" -d "$2")" || { echo "!! $1: no answer" >&2; return 1; }
  code="${r##*$'\n'}"; r="${r%$'\n'*}"
  [ "$code" = 200 ] || { echo "!! $1: HTTP $code: $r" >&2; return 1; }
  LAST="$r"
  echo "   $1: $(echo "$r" | cut -c1-100)"
}
# Storage format 3 keeps a folder's records on the vault's storages, so the
# folder needs one. A phone refuses local-directory storages (only S3 and
# rclone are allowed, see storage_kind_allowed): `rclone serve s3` on the host
# is the bucket, reached from the emulator through `adb reverse`.
command -v rclone >/dev/null || { echo "!! rclone is needed on the host (curl https://rclone.org/install.sh | sudo bash)" >&2; exit 1; }
s3dir="$(mktemp -d)"; mkdir -p "$s3dir/phone"
rclone serve s3 --auth-key ci-access,ci-secret-key --addr 127.0.0.1:9000 "$s3dir" > "$s3dir/rclone.log" 2>&1 &
s3pid=$!
trap 'kill "$s3pid" 2>/dev/null || true' EXIT
for i in $(seq 1 50); do curl -s -o /dev/null http://127.0.0.1:9000/ && break; sleep 0.2; done
adb reverse tcp:9000 tcp:9000 >/dev/null
echo "== vault through the service API"
api /api/init '{"name":"phone","passphrase":"correct horse battery staple"}'
# The recovery words are in the kit /api/init returns; the folder's recovery
# copy is made from them, so the vault has no "no recovery copy" warning.
recovery="$(echo "$LAST" | python3 -c 'import json,re,sys; k=json.load(sys.stdin)["kit"].split("RECOVERY WORDS")[1]; print(" ".join(re.findall(r"\d+\.\s+([a-z]+)", k)))')"
api /api/storage '{"kind":"s3","name":"cloud","endpoint":"http://127.0.0.1:9000","bucket":"phone","access_key_id":"ci-access","secret_access_key":"ci-secret-key","insecure_http":true}'
api /api/folder "{\"name\":\"Notes\",\"recovery_words\":\"$recovery\"}"
api /api/write '{"folder":"Notes","path":"shopping.md","text":"- oat milk\n- rye bread\n- coffee\n"}'
api /api/write '{"folder":"Notes","path":"ideas.md","text":"# Ideas\n\nA walk along the river on Saturday.\n"}'
api /api/write '{"folder":"Notes","path":"travel/lyon.md","text":"Train 08:12, hotel near Bellecour.\n"}'
sleep 8
state="$(curl -fsS "http://127.0.0.1:18790/api/state" -H "Host: 127.0.0.1:$port" -H "X-Varsto-Token: $token")"
echo "$state" | python3 -c 'import json,sys; s=json.load(sys.stdin); assert s.get("has_vault"), "no vault"; print("== state: vault", s.get("device_name") or "", "unlocked" if s.get("unlocked") else "locked")'
# The first-run page does not poll for a vault created behind its back: a
# theme change recreates the activity, which reloads the interface.
night yes 4; night no 8
shot android-overview-light
read -r w h < <(adb shell wm size | tr -d '\r' | awk '{print $3}' | tr x ' ')
# Files is the second of four tabs in the bottom bar.
adb shell input tap $((w * 3 / 8)) $((h - 180)); sleep 4
shot android-files-light
night yes 8
adb shell input tap $((w * 3 / 8)) $((h - 180)); sleep 4
shot android-files-dark
adb shell input tap $((w * 1 / 8)) $((h - 180)); sleep 4
shot android-overview-dark
night no 1
adb shell run-as "$pkg" tail -5 files/vault/service.log 2>/dev/null || true
ls -la "$out"
