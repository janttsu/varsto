#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# The Linux tray icon and its menu on a virtual Xfce panel, and the interface
# in its own window (Chromium app mode), on an Ubuntu machine (CI runner or a
# throw-away VM; uses sudo for packages).
#   scripts/screenshots/linux-desktop.sh <varsto binary> <demo work dir> <out dir>
# The app window shows the demo laptop of demo-vault.sh; the tray runs on a
# small vault of its own. Writes linux-tray.png and the app window both
# light and dark (linux-app-light.png, linux-app-dark.png). linux-app.png
# stays a copy of the light window so a page that still names that file
# keeps showing a picture.
set -euo pipefail
bin="$(realpath "$1")"; work="$(realpath "$2")"; out="$(mkdir -p "$3" && realpath "$3")"
raw="$out/raw"; mkdir -p "$raw"
SUDO=""; [ "$(id -u)" = 0 ] || SUDO=sudo
export DEBIAN_FRONTEND=noninteractive
$SUDO apt-get update -qq
$SUDO apt-get install -y -qq xvfb xfce4-panel xfce4-session xfconf dbus-x11 imagemagick xdotool openbox fonts-noto-core libdbusmenu-gtk3-4 python3-pil >/dev/null
export DISPLAY=:99
Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 &
sleep 2
eval "$(dbus-launch --sh-syntax)"
# The distribution's default panel (with the status tray), so the panel does
# not stop at its first-run question.
mkdir -p ~/.config/xfce4/panel ~/.config/xfce4/xfconf/xfce-perchannel-xml
[ -f /etc/xdg/xfce4/panel/default.xml ] && cp /etc/xdg/xfce4/panel/default.xml ~/.config/xfce4/xfconf/xfce-perchannel-xml/xfce4-panel.xml
xfce4-panel --disable-wm-check >/dev/null 2>&1 &
sleep 4
t="$work/tray"; mkdir -p "$t/files" "$t/storage"
export VARSTO_PASSPHRASE=shots-passphrase-123
init="$("$bin" --home "$t/home" init --name laptop --json)"
rw="$(echo "$init" | python3 -c 'import json,re,sys; k=json.load(sys.stdin)["kit"].split("RECOVERY WORDS")[1]; print(" ".join(re.findall(r"\d+\.\s+([a-z]+)", k)))')"
"$bin" --home "$t/home" storage add-local box "$t/storage" >/dev/null
VARSTO_RECOVERY_WORDS="$rw" "$bin" --home "$t/home" folder add Documents "$t/files" >/dev/null
printf 'notes\n' > "$t/files/notes.md"
"$bin" --home "$t/home" sync >/dev/null
nohup "$bin" --home "$t/home" tray > "$work/tray.log" 2>&1 &
echo $! >> "$work/pids"
sleep 8
import -window root "$raw/linux-desktop.png"
# The Varsto icon is the right-most blue cluster in the top panel.
pos="$(python3 - "$raw/linux-desktop.png" <<'PY'
import sys
from PIL import Image
im = Image.open(sys.argv[1]).convert('RGB')
xs = []
for x in range(im.width // 2, im.width):
    for y in range(2, 26):
        r, g, b = im.getpixel((x, y))
        if b > 150 and r < 110 and g < 130 and b - r > 60:
            xs.append(x); break
if xs:
    xs.sort(); cluster = [xs[-1]]
    for x in reversed(xs[:-1]):
        if cluster[-1] - x <= 3: cluster.append(x)
        else: break
    print((max(cluster) + min(cluster)) // 2, 13)
PY
)"
if [ -n "$pos" ]; then
  set -- $pos
  xdotool mousemove "$1" "$2" click 3
  sleep 2
  import -window root "$raw/linux-tray-menu.png"
  left=$(( $1 - 260 > 0 ? $1 - 260 : 0 ))
  convert "$raw/linux-tray-menu.png" -crop 520x300+${left}+0 +repage "$out/linux-tray.png"
  xdotool key Escape; sleep 1
  # Off the icon, or its tooltip covers the app window's top bar later.
  xdotool mousemove 120 620; sleep 1
  echo "tray icon at $1 $2"
else
  echo "tray icon not found on the panel" >&2
  tail -20 "$work/tray.log" >&2
fi
# The interface in its own window, on the demo laptop, once per theme.
# ?theme= is read by the page (app.js) before it follows the browser.
openbox >/dev/null 2>&1 &
sleep 1
chrome="${CHROMIUM:-$(python3 -c 'from playwright.sync_api import sync_playwright as s
with s() as p: print(p.chromium.executable_path)' 2>/dev/null || true)}"
[ -x "$chrome" ] || chrome="$(command -v chromium || command -v google-chrome || true)"
[ -n "$chrome" ] || { echo "no chromium for the app window" >&2; exit 1; }
port="$(python3 -c "import json;print(json.load(open('$work/laptop.json'))['port'])")"
token="$(python3 -c "import json;print(json.load(open('$work/laptop.json'))['token'])")"
# A flat crop is the empty desktop, not the interface. The loop waits until
# the window has real content (text, sidebar) or gives up.
window_ready() {
  python3 - "$1" <<'PY'
import sys
from PIL import Image, ImageStat
im = Image.open(sys.argv[1]).convert("L")
st = ImageStat.Stat(im)
sys.exit(0 if st.stddev[0] >= 8 else 1)
PY
}
# A failed second theme must not leave the light window behind: the pack
# step treats one side of a pair as an error and would then hold back every
# other picture from this build.
cleanup_app() {
  status=$?
  if [ "$status" -ne 0 ]; then
    rm -f "$out/linux-app-light.png" "$out/linux-app-dark.png" "$out/linux-app.png"
  fi
  trap - EXIT
  exit "$status"
}
trap cleanup_app EXIT
for scheme in light dark; do
  # The window opens with a one-time start code, not the session token.
  boot="$(curl -fsS -X POST "http://127.0.0.1:$port/api/session/boot" -H "X-Varsto-Token: $token" -d '{}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["boot"])')"
  profile="$work/chrome-$scheme"
  rm -rf "$profile"
  setsid "$chrome" --no-sandbox --disable-gpu --no-first-run --password-store=basic --disable-infobars \
    --test-type --user-data-dir="$profile" "--app=http://127.0.0.1:$port/?boot=${boot}&theme=${scheme}" \
    --window-size=1280,772 --window-position=0,28 > "$work/app-$scheme.log" 2>&1 &
  echo $! >> "$work/pids"
  dest="$out/linux-app-$scheme.png"
  rm -f "$dest"
  for _ in $(seq 1 12); do
    sleep 3
    import -window root "$raw/linux-app-$scheme-full.png" || true
    convert "$raw/linux-app-$scheme-full.png" -crop 1280x772+0+28 +repage "$dest" 2>/dev/null || true
    [ -s "$dest" ] && window_ready "$dest" && break
  done
  # The bracket keeps pkill from matching its own command line.
  pkill -f "[c]hrome-$scheme" || true
  sleep 1
  if [ ! -s "$dest" ] || ! window_ready "$dest"; then
    echo "linux-app-$scheme.png is not a window of the interface" >&2
    exit 1
  fi
done
cp "$out/linux-app-light.png" "$out/linux-app.png"
python3 - "$out/linux-app-light.png" "$out/linux-app-dark.png" <<'PY'
import sys
from PIL import Image, ImageStat
def mean(p):
    return ImageStat.Stat(Image.open(p).convert("L")).mean[0]
light, dark = mean(sys.argv[1]), mean(sys.argv[2])
if abs(light - dark) < 12:
    sys.exit(f"linux window themes look the same (light {light:.0f}, dark {dark:.0f})")
print(f"linux window themes: light {light:.0f}, dark {dark:.0f}")
PY
trap - EXIT
ls -la "$out"
