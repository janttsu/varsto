#!/usr/bin/env bash
# SPDX-License-Identifier: PolyForm-Shield-1.0.0
# On an Ubuntu machine: run the Linux tray app on a virtual desktop with a
# panel that hosts StatusNotifier icons, and capture screenshots of the panel
# icon and its menu. Expects the release tarball at /it/varsto.tar.gz.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq xvfb xfce4-panel xfce4-session dbus-x11 imagemagick xdotool fonts-noto-core libdbusmenu-gtk3-4 python3-pil >/dev/null
cd /it && tar xzf varsto.tar.gz && bin="$(ls -d /it/varsto-*/ | head -1)varsto"
export VARSTO_PASSPHRASE=shots-passphrase-123 DISPLAY=:99
Xvfb :99 -screen 0 1280x800x24 >/dev/null 2>&1 &
sleep 2
eval "$(dbus-launch --sh-syntax)"
# A panel with the status-notifier plugin, no other session parts.
mkdir -p ~/.config/xfce4/panel
xfce4-panel --disable-wm-check >/dev/null 2>&1 &
sleep 4
# Demo vault with invented files so the tray has something to show.
mkdir -p /it/files /it/storage
"$bin" --home /it/home init --name laptop >/dev/null
"$bin" --home /it/home storage add-local box /it/storage >/dev/null
"$bin" --home /it/home folder add Documents /it/files >/dev/null
printf 'notes\n' > /it/files/notes.md
"$bin" --home /it/home sync >/dev/null
nohup "$bin" --home /it/home tray > /it/tray.log 2>&1 &
sleep 6
mkdir -p /it/shots
import -window root /it/shots/linux-desktop.png
# Find the Varsto icon in the top panel by its blue, click it, capture the menu.
pos="$(python3 - <<'PY'
from PIL import Image
im = Image.open('/it/shots/linux-desktop.png').convert('RGB')
w = im.width
xs = []
for x in range(w // 2, w):
    for y in range(2, 26):
        r, g, b = im.getpixel((x, y))
        if b > 150 and r < 110 and g < 130 and b - r > 60:
            xs.append(x); break
if xs:
    # the right-most cluster of blue pixels is the newest status icon
    xs.sort(); cluster = [xs[-1]]
    for x in reversed(xs[:-1]):
        if cluster[-1] - x <= 3: cluster.append(x)
        else: break
    print((max(cluster) + min(cluster)) // 2, 13)
PY
)"
if [ -n "$pos" ]; then
  set -- $pos
  xdotool mousemove "$1" "$2" click 1
  sleep 2
  import -window root /it/shots/linux-tray-menu-left.png
  xdotool key Escape; sleep 1
  xdotool mousemove "$1" "$2" click 3
  sleep 2
  import -window root /it/shots/linux-tray-menu.png
  # Zoomed crop of the panel corner around the icon for the website.
  convert /it/shots/linux-tray-menu.png -crop 520x300+$(( $1 - 260 > 0 ? $1 - 260 : 0 ))+0 +repage /it/shots/linux-tray-menu-crop.png
  convert /it/shots/linux-desktop.png -crop 240x28+$(( $1 - 200 ))+0 +repage -filter point -resize 300% /it/shots/linux-tray-icon-zoom.png
  echo "clicked tray icon at $1 $2"
fi
convert /it/shots/linux-desktop.png -crop 1280x40+0+0 /it/shots/linux-panel.png || true
ls -la /it/shots; tail -3 /it/tray.log

# ---- The interface in its own window: a real Chromium (Playwright build) in
# app mode under a window manager, captured from the virtual desktop.
apt-get install -y -qq openbox python3-venv >/dev/null
openbox >/dev/null 2>&1 &
sleep 1
{ python3 -m venv /it/venv && /it/venv/bin/pip -q install playwright && /it/venv/bin/playwright install --with-deps chromium; } > /it/playwright-install.log 2>&1 || { echo "playwright install failed:"; tail -5 /it/playwright-install.log; }
port="$(python3 -c "import json;print(json.load(open('/it/home/service.json'))['port'])")"
token="$(python3 -c "import json;print(json.load(open('/it/home/service.json'))['token'])")"
# Launch the Playwright Chromium binary directly: errors land in the log, and
# root needs --no-sandbox. App mode shows the page without tabs or address bar.
chrome="$(ls -d /root/.cache/ms-playwright/chromium-*/chrome-linux*/chrome 2>/dev/null | head -1)"
echo "chromium: ${chrome:-not found}"
nohup "$chrome" --no-sandbox --disable-gpu --no-first-run --password-store=basic --disable-infobars \
  --user-data-dir=/it/chrome-profile "--app=http://127.0.0.1:$port/?token=$token" \
  --window-size=1280,770 --window-position=0,30 > /it/app-window.log 2>&1 &
sleep 15
xdotool key Escape 2>/dev/null || true   # close the tray menu left open by the capture above
# The test build of Chromium shows a 'Download Chrome' bar; its close button sits at the right end.
xdotool mousemove 1262 76 click 1 2>/dev/null || true
sleep 2
import -window root /it/shots/linux-app.png
echo "app window captured; browser log:"; cat /it/app-window.log 2>/dev/null | tail -5
ls -la /it/shots
